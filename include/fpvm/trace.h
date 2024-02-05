#ifndef _TRACE
#define _TRACE

#include <string.h>
#include <stdio.h>
#include <stdint.h>



typedef struct fpvm_instr_trace {
#define TRACE_START_UNUSED 0
#define TRACE_START_NORMAL 1
  uint64_t start_cond;
  uint64_t start_addr;
#define TRACE_END_INSTR_UNDECODABLE  1
#define TRACE_END_INSTR_UNBINDABLE   2
#define TRACE_END_INSTR_UNEMULATABLE 4
#define TRACE_END_INSTR_SHOULDNOT    8
#define TRACE_END_INSTR_SEQUENCE_MAX 512
  uint64_t end_cond;
  uint64_t instr_count;     // number of instructions that were handled (not including terminating instruction)
  uint64_t trace_count;     // number of times the instruction was encoutered;
} fpvm_instr_trace_t;

// stored per execution context
typedef struct fpvm_instr_trace_context {
  uint64_t       size;
  uint64_t       trace_count;
  uint64_t       unique_trace_count;
  fpvm_instr_trace_t  entries[0];
} fpvm_instr_trace_context_t;

fpvm_instr_trace_context_t *fpvm_instr_tracer_create(void);
int fpvm_instr_tracer_print(FILE *out, char *prefix, fpvm_instr_trace_context_t *c, uint64_t extra);
int fpvm_instr_tracer_destroy(fpvm_instr_trace_context_t *c);

static inline int fpvm_instr_tracer_record(fpvm_instr_trace_context_t *c,
					   uint64_t start_cond,
					   uint64_t start_addr,
					   uint64_t end_cond,
					   uint64_t instr_count)
{
  // chaining search
  uint64_t start = start_addr % c->size;
  uint64_t searched=0;
  uint64_t i;
  for (i=start;i<c->size && searched<c->trace_count;i++,searched++) {
    if (c->entries[i].start_cond==start_cond &&
	c->entries[i].start_addr==start_addr &&
	c->entries[i].end_cond==end_cond &&
	c->entries[i].instr_count==instr_count) {
      // match, simply update entry
      c->entries[i].trace_count++;
      c->trace_count++;
      //DEBUG("trace: saw %016lx again\n", start_addr);
      return 0;
    }
  }
  // wrap search
  for (i=0;i<start && searched<c->trace_count;i++,searched++) {
    if (c->entries[i].start_cond==start_cond &&
	c->entries[i].start_addr==start_addr &&
	c->entries[i].end_cond==end_cond &&
	c->entries[i].instr_count==instr_count) {
      // match, simply update entry
      c->entries[i].trace_count++;
      c->trace_count++;
      //DEBUG("trace: saw %016lx again\n", start_addr);
      return 0;
    }
  }

  // if we got here, we have a unique trace, so search for an entry
  uint64_t new_ent = -1;
  for (i=start;i<c->size && new_ent==-1;i++) {
    if (!c->entries[i].start_cond) {
      new_ent = i;
    }
  }
  // wrap search if needed
  for (i=0;i<start && new_ent==-1;i++) {
    if (!c->entries[i].start_cond) {
      new_ent = i;
    }
  }

  if (new_ent==-1) {
    fprintf(stderr,"unable to allocate a new trace entry....\n");
    return -1;
  }

  fpvm_instr_trace_t *r = &c->entries[new_ent];

  r->start_cond = start_cond;
  r->start_addr = start_addr;
  r->end_cond = end_cond;
  r->instr_count = instr_count;
  r->trace_count = 1;

  c->trace_count++;
  c->unique_trace_count++;

  //DEBUG("unique trace recorded (%lu total)\n",c->unique_trace_count);
  
  return 0;
  
}

#endif
