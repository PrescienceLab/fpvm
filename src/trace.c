#define _GNU_SOURCE
#include <signal.h>
#include <ucontext.h>

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include <fpvm/trace.h>
#include <fpvm/decoder.h>
#include <fpvm/fpvm_common.h>

#include <capstone/capstone.h>

static csh handle;

fpvm_instr_trace_context_t *fpvm_instr_tracer_create(void)
{
  uint64_t size = sizeof(fpvm_instr_trace_context_t)+DEFAULT_TRACE_STORE_SIZE*sizeof(fpvm_instr_trace_t);
  fpvm_instr_trace_context_t *c = malloc(size);
  if (!c) {
    ERROR("cannot allocate trace context\n");
    return 0;
  }
  memset(c,0,size);
  c->size = DEFAULT_TRACE_STORE_SIZE;
  return c;
}

static int cmp_count(const void *_l, const void *_r)
{
  fpvm_instr_trace_t *l = (fpvm_instr_trace_t*)_l;
  fpvm_instr_trace_t *r = (fpvm_instr_trace_t*)_r;

  return l->trace_count > r->trace_count ? -1 : l->trace_count < r->trace_count ? +1 : 0;
}

static int cmp_len(const void *_l, const void *_r)
{
  fpvm_instr_trace_t *l = (fpvm_instr_trace_t*)_l;
  fpvm_instr_trace_t *r = (fpvm_instr_trace_t*)_r;

  return l->instr_count < r->instr_count ? -1 : l->instr_count > r->instr_count ? +1 : 0;
}

static int cmp_lendist(const void *_l, const void *_r)
{
  const uint64_t *l = (const uint64_t *)_l;
  const uint64_t *r = (const uint64_t *)_r;

  return r[1] - l[1];
}


static int cmp_lenpop(const void *_l, const void *_r)
{
  int rc = cmp_len(_l,_r);
  if (rc) {
    return rc;
  } else {
    return cmp_count(_l,_r);
  }
}


static void dump_trace(FILE *out, char *prefix, fpvm_instr_trace_t *r, uint64_t extra)
{
  fprintf(out,"%sTRACE BEGIN (start_cond 0x%lx (%s) end_cond 0x%lx (%s), start_addr 0x%016lx instr_count %lu trace_count %lu)\n",
	  prefix,
	  r->start_cond,
	  r->start_cond==TRACE_START_UNUSED ? "**UNUSED!**" :
	  r->start_cond==TRACE_START_NORMAL ? "normal" : "**UNKNOWN!**",
	  r->end_cond,
	  r->end_cond==TRACE_END_INSTR_UNDECODABLE ? "undecodable" :
	  r->end_cond==TRACE_END_INSTR_UNBINDABLE ? "unbindable" :
	  r->end_cond==TRACE_END_INSTR_UNEMULATABLE ? "unemulatable" :
	  r->end_cond==TRACE_END_INSTR_SHOULDNOT ? "shouldnot" :
	  r->end_cond==TRACE_END_INSTR_SEQUENCE_MAX ? "max" : "**UNKNOWN!**",
	  r->start_addr,r->instr_count,r->trace_count);
  uint64_t currip;
  uint64_t i;
  char pre1[strlen(prefix)+1+2];
  strcpy(pre1,prefix);
  strcat(pre1,"  ");
  char pre2[strlen(prefix)+1+2];
  strcpy(pre2,prefix);
  strcat(pre2," *");

  for (i=0, currip=r->start_addr;i<r->instr_count+extra;i++) {
    int rc=fpvm_decoder_decode_and_print_any_inst((void*)currip,stderr,i<r->instr_count ? pre1 : pre2);
    if (rc<0) {
      ERROR("failed to decode and print...\n");
      return;
    } else {
      currip+=rc;
    }
  }
  fprintf(out,"%sTRACE END\n",prefix);
}  

int fpvm_instr_tracer_print(FILE *out, char *prefix, fpvm_instr_trace_context_t *c, uint64_t extra)
{
  fpvm_instr_trace_context_t *t = fpvm_instr_tracer_create();
  if (!t) {
    ERROR("cannot consolidate data for print\n");
    return -1;
  }

  // collect and pack traces
  uint64_t i,j;
  for (i=0,j=0;i<c->size;i++) {
    if (c->entries[i].start_cond) {
      t->entries[j] = c->entries[i];
      j++;
    }
  }

  if (j!=c->unique_trace_count) {
    ERROR("unique trace mismatch (%lu vs %lu (counted))\n",c->unique_trace_count,j);
  }
  t->trace_count=c->trace_count;
  t->unique_trace_count = c->unique_trace_count;


  fprintf(out, "%sTRACE STATS BEGIN\n", prefix);
  fprintf(out, "%s%lu traces recorded of which %lu are unique\n", prefix, t->trace_count, t->unique_trace_count);

  /*
  fprintf(out, "%sunique traces in packed order:\n",prefix);
  for (i=0;i<t->unique_trace_count;i++) {
    dump_trace(out,prefix,&t->entries[i],extra);
  }
  */

  
  // now sort by hotness of trace
  qsort(t->entries,t->unique_trace_count,sizeof(fpvm_instr_trace_t), cmp_count);
  fprintf(out, "%strace rank popularity:\n",prefix);
  double prob, cumprob=0;
  for (i=0;i<t->unique_trace_count;i++) {
    prob = 100.0*t->entries[i].trace_count/((double)t->trace_count);
    cumprob+=prob;
    fprintf(out,"%srank %lu -> %lu (%lf%% %lf%%) [length %lu]\n",prefix,i,t->entries[i].trace_count,prob, cumprob, t->entries[i].instr_count);
  }
  fprintf(out, "%sunique traces in order of hotness:\n",prefix);
  for (i=0;i<t->unique_trace_count;i++) {
    dump_trace(out,prefix,&t->entries[i],extra);
  }

  uint64_t maxlen=0;
  for (i=0;i<t->unique_trace_count;i++) {
    if (t->entries[i].instr_count>maxlen) { maxlen=t->entries[i].instr_count; }
  }

  uint64_t lendist[maxlen+1][2];
  for (i=0;i<maxlen+1;i++) {
    lendist[i][0]=i;
    lendist[i][1]=0;
  }

  uint64_t total=0;
  for (i=0;i<t->unique_trace_count;i++) {
    lendist[t->entries[i].instr_count][1]+=t->entries[i].trace_count;
    total+=t->entries[i].trace_count;
  }
  
  qsort(lendist,maxlen+1,2*sizeof(uint64_t),cmp_lendist);

  cumprob=0;
  fprintf(out, "%strace length popularity:\n",prefix);
  for (i=0;i<maxlen;i++) {
    if (lendist[i][1]) {
      prob=100.0*lendist[i][1]/((double)total);
      cumprob+=prob;
      fprintf(out,"%slength %lu -> %lu (%lf%% %lf%%)\n",prefix,lendist[i][0],lendist[i][1], prob,cumprob);
    }
  }

  qsort(t->entries,t->unique_trace_count,sizeof(fpvm_instr_trace_t), cmp_lenpop);
  //

  fprintf(out, "%sunique traces in order of trace length and rev order of popularity:\n",prefix);
  for (i=0;i<t->unique_trace_count;i++) {
    dump_trace(out,prefix,&t->entries[i],extra);
  }
  fprintf(out, "%sTRACE STATS END\n",prefix);
  
  fpvm_instr_tracer_destroy(t);
  
  return 0;
}

int fpvm_instr_tracer_destroy(fpvm_instr_trace_context_t *c)
{
  free(c);
  return 0;
}
