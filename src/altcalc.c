#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>

#include <fpvm/altcalc.h>
#include <fpvm/number_system.h>


#define STACK_DEPTH 1024

static uint64_t stack[STACK_DEPTH];
static int      tos=-1;

#define CLEAR() memset(stack,0,STACK_DEPTH*sizeof(uint64_t)); tos=-1; 
#define EMPTY() (tos<0)
#define FULL()  (tos>=(STACK_DEPTH-1))
#define PUSH(X) ( !FULL() ?  stack[++tos] = (X), 0 : -1UL )
#define POP(X)  ( !EMPTY() ? stack[tos--] : -1UL)
#define DUP()   ( !FULL() && !EMPTY()  ? stack[tos+1] = stack[tos], tos++, 0 : -1UL )

#define UNIMPL() printf("unimplemented - go yell at Peter\n");

void print_details(uint64_t x)
{
  char buf[256];
  altmath_print_double((double*)&x,buf,256);
  printf("%s",buf);
}

void print_stack()
{
  int i;
  for (i=0;i<=tos;i++) {
    printf("%d\t%016llx\t",i,stack[i]);
    print_details(stack[i]);
    printf("\n");
  }
}

uint64_t box(uint64_t x)
{
  uint64_t y=x;
  altmath_promote_double_in_place((double*)&y);
  return y;
}

uint64_t unbox(uint64_t x)
{
  uint64_t y=x;
  altmath_demote_double_in_place((double*)&y);
  return y;
}

static void help()
{
  printf("0x<num>              = push a specific bitpattern onto the stack\n");
  printf("d 0x<num> | <double> = push a double onto the stack\n");
  printf("c                    = clone top of stack\n");
  printf("p                    = pop stack\n");
  printf("s                    = print stack\n");
  printf("b                    = box double at top of stack (convert to altmath and box)\n");
  printf("u                    = unbox altmath at top of stack (unbox and convert to double)\n");
  printf("neg|sqrt             = basic unary ops\n");
  printf("+|-|*|/|min|max|     = basic binary ops\n");
  printf("madd|nmadd|msub|\n");
  printf("  nmsub              = basic trinary ops\n");
  printf("  cmp|ucmp           = binary compares\n");
  printf("cmpxx                = unimplmented\n");
  printf("<conversions>        = unimplemented\n");
  printf("q                    = quit gracefully and continue FPVM\n");
  printf("Q                    = quit and abort FPVM run\n");
  printf("?                    = help\n");
  printf("#                    = comment rest of line\n");
}

static char* first_ptr(char *s)
{
  while (*s && isspace(*s)) { s++; }
  return s;
}

static char first(char *s)
{
  return *first_ptr(s);
}

int fpvm_number_alt_calc(void)
{
  char buf[80];
  char buf2[80];
  uint64_t u;
  uint64_t di, ti, bi;
  double d,t,b;
  uint64_t s,e,m;
  uint64_t src1, src2, src3, dst;

  CLEAR();
  
  while (1) {
    print_stack();
    printf("altcalc> ");
    if (!fgets(buf,80,stdin) || buf[0]=='q') {
      // graceful exit
      return 0; 
    }
    if (strlen(buf)>0 && buf[strlen(buf)-1]=='\n') {
      // strip \ns from tail
      buf[strlen(buf)-1]=0;
    }
    if (strlen(buf)==0) {
      continue;
    }
    if (first(buf)=='Q') {
      // abort fpvm
      return -1;
    }
    if (first(buf)=='?') {
      help();
      continue;
    }
    if (first(buf)=='#') {
      continue; // comment char
    }
    if (first(buf)=='c') {
      DUP();
      continue;
    }
    if (first(buf)=='s') {
      print_stack();
      continue;
    }
    if (first(buf)=='p') {
      u=POP();
      printf("popped value %016llx\n",u);
      continue;
    }
    if (first(buf)=='b') {
      src1 = POP();
      dst = box(src1);
      PUSH(dst);
      continue;
    }
    if (first(buf)=='u') {
      src1 = POP();
      dst = unbox(src1);
      PUSH(dst);
      continue;
    }
      
    if (sscanf(buf,"0x%lx",&src1)==1) {
      PUSH(src1);
      continue;
    }
    if (sscanf(buf,"d %s",buf2)==1) {
      // from double
      if (sscanf(buf2,"0x%lx",&di)==1) {
	d = *(double*)&di;
      } else if (sscanf(buf2,"%lf",&d)==1) {
	di = *(uint64_t*)&d;
      } else {
	printf("d 0x<num> or d <double>\n");
	continue;
      }
      src1=di;
      PUSH(src1);
      continue;
    }

    if (!strcmp(first_ptr(buf),"neg")) {
      src1 = POP();
      dst = src1 ^ 0x8000000000000000UL;
      PUSH(dst);
      continue;
    }
    if (!strcmp(first_ptr(buf),"sqrt")) {
      src1 = POP();
      sqrt_double(0,&dst,&src1,0,0,0);
      PUSH(dst);
      continue;
    }
    if (!strcmp(first_ptr(buf),"+")) {
      src1 = POP();
      src2 = POP();
      add_double(0,&dst,&src1,&src2,0,0);
      PUSH(dst);
      continue;
    }
    if (!strcmp(first_ptr(buf),"-")) {
      src1 = POP();
      src2 = POP();
      sub_double(0,&dst,&src1,&src2,0,0);
      PUSH(dst);
      continue;
    }
    if (!strcmp(first_ptr(buf),"*")) {
      src1 = POP();
      src2 = POP();
      mul_double(0,&dst,&src1,&src2,0,0);
      PUSH(dst);
      continue;
    }
    if (!strcmp(first_ptr(buf),"/")) {
      src1 = POP();
      src2 = POP();
      div_double(0,&dst,&src1,&src2,0,0);
      PUSH(dst);
      continue;
    }
    if (!strcmp(first_ptr(buf),"min")) {
      src1 = POP();
      src2 = POP();
      min_double(0,&dst,&src1,&src2,0,0);
      PUSH(dst);
      continue;
    }
    if (!strcmp(first_ptr(buf),"max")) {
      src1 = POP();
      src2 = POP();
      max_double(0,&dst,&src1,&src2,0,0);
      PUSH(dst);
      continue;
    }
    if (!strcmp(first_ptr(buf),"madd")) {
      src1 = POP();
      src2 = POP();
      src3 = POP();
      madd_double(0,&dst,&src1,&src2,&src3,0);
      PUSH(dst);
      continue;
    }
    if (!strcmp(first_ptr(buf),"nmadd")) {
      src1 = POP();
      src2 = POP();
      src3 = POP();
      nmadd_double(0,&dst,&src1,&src2,&src3,0);
      PUSH(dst);
      continue;
    }
    if (!strcmp(first_ptr(buf),"msub")) {
      src1 = POP();
      src2 = POP();
      src3 = POP();
      msub_double(0,&dst,&src1,&src2,&src3,0);
      PUSH(dst);
      continue;
    }
    if (!strcmp(first_ptr(buf),"nmsub")) {
      src1 = POP();
      src2 = POP();
      src3 = POP();
      nmsub_double(0,&dst,&src1,&src2,&src3,0);
      PUSH(dst);
      continue;
    }
    if (!strcmp(first_ptr(buf),"cmp")) {
      UNIMPL();
      continue;
    }
    if (!strcmp(first_ptr(buf),"ucmp")) {
      UNIMPL();
      continue;
    }
    if (!strcmp(first_ptr(buf),"cmpxx")) {
      UNIMPL();
      continue;
    }
    UNIMPL();

  }
}
  
  
  

