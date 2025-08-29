/*

  Part of FPVM

  Preload that traps and emulates floating point instructions
  that round or consume/produce a NAN

  Copyright (c) 2018 Peter A. Dinda - see LICENSE


  This code does the following:

  - installs itself at load time of the target program
  - adds hooks for fpe* functions - if any of these are used, the library
    deactivates itself
  - adds hook for signal installation (individual mode only)
    so that it can get out of the way if the target program
    establishes its own floating point exception handler
  - removes itself at unload time of the target program

    A core set of FP exeptions are used to drive the FPVM state machine.
    When an exception occurs, control is handed to an emulator.   When
    the emulator returns, the instruction is skipped.

  Concurrency:
      - fork() - both parent and child are tracked.  Child's FPE state is
  cleared any previous abort in parent is inherited
      - exec() - Tracking restarts (assuming the environment variables are
  inherited) any previous abort is discarded
      - pthread_create() - both parent and child are tracked.  Child's FPE state
  is cleared both have a log file.  May not work on a pthread_cancel An abort in
  any thread is shared by all the threads


*/


#define _GNU_SOURCE
#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <fenv.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
//#include <sys/reg.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <time.h>
#include <ucontext.h>
#include <unistd.h>

#include <math.h>

#include <sys/time.h>

#include <fpvm/decoder.h>
#include <fpvm/emulator.h>
#include <fpvm/fpvm_common.h>
#include <fpvm/gc.h>
#include <fpvm/vm.h>
#include <fpvm/util.h>

#include <fpvm/perf.h>
#include <fpvm/trace.h>

#include <fpvm/fpvm_fenv.h>
#include <fpvm/fpvm_math.h>
#include <fpvm/number_system.h>
#include <fpvm/fpvm_magic.h>
#include <fpvm/config.h>
#include <fpvm/pulse.h>

// support for kernel module
#if CONFIG_TRAP_SHORT_CIRCUITING
#include <sys/ioctl.h>
#include "fpvm/fpvm_ioctl.h"
#endif


volatile static int inited = 0;
volatile static int aborted = 0;  // set if the target is doing its own FPE processing

volatile static int exceptmask = FE_ALL_EXCEPT;  // which C99 exceptions to handle, default all
volatile static int mxcsrmask_base =
    0x3f;  // which sse exceptions to handle, default all (using base zero)

#define MXCSR_FLAG_MASK (mxcsrmask_base << 0)
#define MXCSR_MASK_MASK (mxcsrmask_base << 7)

// MXCSR used when *we* are executing floating point code
// All masked, flags zeroed, round nearest, special features off
#define MXCSR_OURS 0x1f80

static int control_mxcsr_round_daz_ftz = 0;     // control the rounding bits
static uint32_t orig_mxcsr_round_daz_ftz_mask;  // captured at start
static uint32_t our_mxcsr_round_daz_ftz_mask =
    0;  // as we want to run 0 = round to nearest, no FAZ, no DAZ (IEEE default)

volatile static int kernel = 0;
volatile static int aggressive = 0;
volatile static int disable_pthreads = 0;

static int (*orig_fork)() = 0;
static int (*orig_pthread_create)(
    pthread_t *tid, const pthread_attr_t *attr, void *(*start)(void *), void *arg) = 0;
static int (*orig_pthread_exit)(void *ret) __attribute__((noreturn)) = 0;
static sighandler_t (*orig_signal)(int sig, sighandler_t func) = 0;
static int (*orig_sigaction)(int sig, const struct sigaction *act, struct sigaction *oldact) = 0;
// static int (*orig_feenableexcept)(int) = 0 ;
// static int (*orig_fedisableexcept)(int) = 0 ;
// static int (*orig_fegetexcept)() = 0 ;
// static int (*orig_feclearexcept)(int) = 0 ;
// static int (*orig_fegetexceptflag)(fexcept_t *flagp, int excepts) = 0 ;
// static int (*orig_feraiseexcept)(int excepts) = 0;
// static int (*orig_fesetexceptflag)(const fexcept_t *flagp, int excepts) = 0;
// static int (*orig_fetestexcept)(int excepts) = 0;
// static int (*orig_fegetround)(void) = 0;
// static int (*orig_fesetround)(int rounding_mode) = 0;
// static int (*orig_fegetenv)(fenv_t *envp) = 0;
// static int (*orig_feholdexcept)(fenv_t *envp) = 0;
// static int (*orig_fesetenv)(const fenv_t *envp) = 0;
// static int (*orig_feupdateenv)(const fenv_t *envp) = 0;

int (*orig_feenableexcept)(int) = 0;
int (*orig_fedisableexcept)(int) = 0;
int (*orig_fegetexcept)() = 0;
int (*orig_feclearexcept)(int) = 0;
int (*orig_fegetexceptflag)(fexcept_t *flagp, int excepts) = 0;
int (*orig_feraiseexcept)(int excepts) = 0;
int (*orig_fesetexceptflag)(const fexcept_t *flagp, int excepts) = 0;
int (*orig_fetestexcept)(int excepts) = 0;
int (*orig_fegetround)(void) = 0;
int (*orig_fesetround)(int rounding_mode) = 0;
int (*orig_fegetenv)(fenv_t *envp) = 0;
int (*orig_feholdexcept)(fenv_t *envp) = 0;
int (*orig_fesetenv)(const fenv_t *envp) = 0;
int (*orig_feupdateenv)(const fenv_t *envp) = 0;

double (*orig_pow)(double a, double b) = 0;
double (*orig_exp)(double a) = 0;
double (*orig_log)(double a) = 0;
double (*orig_sin)(double a) = 0;
double (*orig_sincos)(double a, double *sin, double *cos) = 0;
double (*orig_cos)(double a) = 0;
double (*orig_tan)(double a) = 0;
double (*orig_log10)(double a) = 0;
double (*orig_ceil)(double a) = 0;
double (*orig_floor)(double a) = 0;
int (*orig_round)(double a) = 0;
long int (*orig_lround)(double a) = 0;
double (*orig_ldexp)(double a, int b) = 0;
double (*orig_sinh)(double a) = 0;
double (*orig_cosh)(double a) = 0;
double (*orig_tanh)(double a) = 0;
double (*orig_asin)(double a) = 0;
double (*orig_acos)(double a) = 0;
double (*orig_atan)(double a) = 0;
double (*orig_asinh)(double a) = 0;
double (*orig_acosh)(double a) = 0;
double (*orig_atanh)(double a) = 0;
double (*orig_atan2)(double a, double b) = 0;
double (*orig___powidf2)(double a, int b) = 0;

static struct sigaction oldsa_fpe, oldsa_trap, oldsa_int, oldsa_segv;

#define ORIG_RETURN(func, ...)                            \
  if (orig_##func) {                                      \
    return orig_##func(__VA_ARGS__);                      \
  } else {                                                \
    ERROR("cannot call orig_" #func " returning zero\n"); \
    return 0;                                             \
  }
#define ORIG_IF_CAN(func, ...)                                          \
  if (orig_##func) {                                                    \
    if (!DEBUG_OUTPUT) {                                                \
      orig_##func(__VA_ARGS__);                                         \
    } else {                                                            \
      DEBUG("orig_" #func " returns 0x%x\n", orig_##func(__VA_ARGS__)); \
    }                                                                   \
  } else {                                                              \
    DEBUG("cannot call orig_" #func " - skipping\n");                   \
  }

#define SHOW_CALL_STACK()

#define MAX_CONTEXTS 1024

// make this run-time configurable later
static uint64_t decode_cache_size = DEFAULT_DECODE_CACHE_SIZE;

#ifdef CONFIG_FPTRAPALL

#define FPTRAPALL_REGISTER_PATH "/sys/kernel/fptrapall/register"
#define FPTRAPALL_TS_PATH "/sys/kernel/fptrapall/ts"
#define FPTRAPALL_IN_SIGNAL_PATH "/sys/kernel/fptrapall/in_signal"

static void
fptrapall_register(void)
{
	int fd = syscall(SYS_open, FPTRAPALL_REGISTER_PATH, O_WRONLY);
	if(fd < 0) {
		perror("open");
		syscall(SYS_exit, fd);
	}

	syscall(SYS_lseek, fd, 0, SEEK_SET);

	uint8_t val = '1';
	long written = syscall(SYS_write, fd, &val, sizeof(val));

        if (written < 0) {
            perror("write");
	    syscall(SYS_exit, (int)written);
        }

	syscall(SYS_close, fd);
}

static void
fptrapall_mark_in_signal(void) {
	int fd = syscall(SYS_open, FPTRAPALL_IN_SIGNAL_PATH, O_WRONLY);
	if(fd < 0) {
		perror("open");
		syscall(SYS_exit, fd);
	}

	syscall(SYS_lseek, fd, 0, SEEK_SET);

	uint8_t val = '1';
	long written = syscall(SYS_write, fd, &val, sizeof(val));

        if (written < 0) {
            perror("write");
	    syscall(SYS_exit, (int)written);
        }

	syscall(SYS_close, fd);
}

void
fptrapall_set_ts(void)
{
	int fd = syscall(SYS_open, FPTRAPALL_TS_PATH, O_WRONLY);
	if(fd < 0) {
		perror("open");
		syscall(SYS_exit, fd);
	}

	syscall(SYS_lseek, fd, 0, SEEK_SET);

	uint8_t val = '1';
	long written = syscall(SYS_write, fd, &val, sizeof(val));

        if (written < 0) {
            perror("write");
	    syscall(SYS_exit, (int)written);
        }

	syscall(SYS_close, fd);
}

void
fptrapall_clear_ts(void)
{
	int fd = syscall(SYS_open, FPTRAPALL_TS_PATH, O_WRONLY);
	if(fd < 0) {
		perror("open");
		syscall(SYS_exit, fd);
	}

	syscall(SYS_lseek, fd, 0, SEEK_SET);

	uint8_t val = '0';
	long written = syscall(SYS_write, fd, &val, sizeof(val));

        if (written < 0) {
            perror("write");
	    syscall(SYS_exit, (int)written);
        }

	syscall(SYS_close, fd);
}

#endif

static FILE *fpvm_log_file = NULL;
#define FPVM_LOG_FILE (fpvm_log_file ? fpvm_log_file : stderr)

// This is to allow us to handle multiple threads
// and to follow forks later
typedef struct execution_context {
  enum { INIT, AWAIT_FPE, AWAIT_TRAP, ABORT } state;
  int aborting_in_trap;
  int tid;

  uint32_t foreign_return_mxcsr;
  void    *foreign_return_addr;
  
  uint64_t fp_traps;
  uint64_t promotions;
  uint64_t demotions;
  uint64_t clobbers;           // overwriting one of our nans
  uint64_t correctness_traps;  
  uint64_t correctness_foreign_calls; 
  uint64_t correctness_demotions;
  uint64_t emulated_inst;

  fpvm_inst_t **decode_cache;  // chaining hash - array of pointers to instructions
  uint64_t decode_cache_size;
  uint64_t decode_cache_hits;
  uint64_t decode_cache_unique;

  fpvm_vm_t *vm;     // vm associated with this execution context, if any

  
#if CONFIG_INSTR_TRACES
  fpvm_instr_trace_context_t *trace_context;
#define INIT_TRACER(c) (c)->trace_context = fpvm_instr_tracer_create()
#define DEINIT_TRACER(c) fpvm_instr_tracer_destroy((c)->trace_context)
#define RECORD_TRACE(c,ec,sa,ic) fpvm_instr_tracer_record((c)->trace_context,TRACE_START_NORMAL,sa,ec,ic)
#define PRINT_TRACES(c) { char _buf[256]; sprintf(_buf,"fpvm info(%8d): trace: ",(c)->tid); fpvm_instr_tracer_print(FPVM_LOG_FILE,_buf,(c)->trace_context,4); }
#else
#define INIT_TRACER(c)
#define DEINIT_TRACER(c)
#define RECORD_TRACE(c,ec,sa,ic)
#define PRINT_TRACES(c)
#endif
  
#if CONFIG_PERF_STATS
  perf_stat_t gc_stat;
  perf_stat_t decode_cache_stat;
  perf_stat_t decode_stat;
  perf_stat_t bind_stat;
  perf_stat_t emulate_stat;
  perf_stat_t correctness_stat;
  perf_stat_t foreign_call_stat;
  perf_stat_t altmath_stat;

#define START_PERF(c, x) perf_stat_start(&c->x##_stat)
#define END_PERF(c, x) perf_stat_end(&c->x##_stat)
#define PRINT_PERF(c, x) { char _buf[256]; sprintf(_buf,"fpvm info(%8d): perf: ",(c)->tid); perf_stat_print(&(c)->x##_stat, FPVM_LOG_FILE, _buf); }
#define PRINT_PERFS(c)         \
  PRINT_PERF(c, gc);           \
  PRINT_PERF(c, decode_cache); \
  PRINT_PERF(c, decode);       \
  PRINT_PERF(c, bind);         \
  PRINT_PERF(c, emulate);      \
  PRINT_PERF(c, correctness);  \
  PRINT_PERF(c, foreign_call); \
  PRINT_PERF(c, altmath); 
#else
#define START_PERF(c, x)
#define END_PERF(c, x)
#define PRINT_PERF(c, x)
#define PRINT_PERFS(c)
#endif

  
#if CONFIG_TELEMETRY_PROMOTIONS
#define PRINT_TELEMETRY(c) fprintf(FPVM_LOG_FILE, "fpvm info(%8d): telemetry: %lu fp traps, %lu promotions, %lu demotions, %lu clobbers, %lu correctness traps, %lu correctness foreign calls, %lu correctness demotions, %lu instructions emulated (~%lu per trap), %lu decode cache hits, %lu unique instructions\n",(c)->tid, (c)->fp_traps, (c)->promotions, (c)->demotions, (c)->clobbers, (c)->correctness_traps, (c)->correctness_foreign_calls, (c)->correctness_demotions, (c)->emulated_inst, DIVU((c)->emulated_inst,(c)->fp_traps), (c)->decode_cache_hits, (c)->decode_cache_unique)
#else
#define PRINT_TELEMETRY(c) fprintf(FPVM_LOG_FILE, "fpvm info(%8d): telemetry: %lu fp traps, -1 promotions, -1 demotions, -1 clobbers, %lu correctness traps, %lu correctness foreign calls -1 correctness demotions, %lu instructions emulated (~%lu per trap), %lu decode cache hits, %lu unique instructions\n",(c)->tid, (c)->fp_traps, (c)->correctness_traps, (c)->correctness_foreign_calls, (c)->emulated_inst, DIVU((c)->emulated_inst,(c)->fp_traps), (c)->decode_cache_hits, (c)->decode_cache_unique)
#endif
  
} execution_context_t;

typedef union {
  uint32_t val;
  struct {
    uint8_t ie : 1;        // detected nan
    uint8_t de : 1;        // detected denormal
    uint8_t ze : 1;        // detected divide by zero
    uint8_t oe : 1;        // detected overflow (infinity)
    uint8_t ue : 1;        // detected underflow (zero)
    uint8_t pe : 1;        // detected precision (rounding)
    uint8_t daz : 1;       // denormals become zeros
    uint8_t im : 1;        // mask nan exceptions
    uint8_t dm : 1;        // mask denorm exceptions
    uint8_t zm : 1;        // mask zero exceptions
    uint8_t om : 1;        // mask overflow exceptions
    uint8_t um : 1;        // mask underflow exceptions
    uint8_t pm : 1;        // mask precision exceptions
    uint8_t rounding : 2;  // rounding (toward
                           // 00=>nearest,01=>negative,10=>positive,11=>zero)
    uint8_t fz : 1;        // flush to zero (denormals are zeros)
    uint16_t rest;
  } __attribute__((packed));
} __attribute__((packed)) mxcsr_t;

typedef union {
  uint64_t val;
  struct {
    // note that not all of these are visible in user mode
    uint8_t cf : 1;      // detected carry
    uint8_t res1 : 1;    // reserved MB1
    uint8_t pf : 1;      // detected parity
    uint8_t res2 : 1;    // reserved
    uint8_t af : 1;      // detected adjust (BCD math)
    uint8_t res3 : 1;    // resered
    uint8_t zf : 1;      // detected zero
    uint8_t sf : 1;      // detected negative
    uint8_t tf : 1;      // trap enable flag (single stepping)
    uint8_t intf : 1;    // interrupt enable flag
    uint8_t df : 1;      // direction flag (1=down);
    uint8_t of : 1;      // detected overflow
    uint8_t iopl : 2;    // I/O privilege level (ring)
    uint8_t nt : 1;      // nested task
    uint8_t res4 : 1;    // reserved
    uint8_t rf : 1;      // resume flag;
    uint8_t vm : 1;      // virtual 8086 mode
    uint8_t ac : 1;      // alignment check enable
    uint8_t vif : 1;     // virtual interrupt flag
    uint8_t vip : 1;     // virtual interrupt pending;
    uint8_t id : 1;      // have cpuid instruction
    uint16_t res5 : 10;  // reserved
    uint32_t res6;       // nothing in top half of rflags yet
  } __attribute__((packed));
} __attribute__((packed)) rflags_t;

static int context_lock;
static execution_context_t context[MAX_CONTEXTS];

// faster lookup of execution context
__thread execution_context_t *__fpvm_current_execution_context=0;


static uint64_t NO_TOUCH_FLOAT get_xmm0() {
  uint64_t val = 0;
  #ifdef __x86_64__
  // TODO: move to a central "machine state save/restore" function
  __asm__ __volatile__("movq %%xmm0, %0" : "=r"(val) : : "memory");
  #endif
  return val;
}

static uint32_t NO_TOUCH_FLOAT get_mxcsr() {
  uint32_t val = 0;
  #ifdef __x86_64__
  // TODO: move to a central "machine state save/restore" function
  __asm__ __volatile__("stmxcsr %0" : "=m"(val) : : "memory");
  #endif
  return val;
}

static void NO_TOUCH_FLOAT set_mxcsr(uint32_t val) {
  #ifdef __x86_64__
  // TODO: move to a central "machine state save/restore" function
  __asm__ __volatile__("ldmxcsr %0" : : "m"(val) : "memory");
  #endif
}


static void mxcsr_disable_save(uint32_t* old) {
  uint32_t tmp = get_mxcsr();
  *old = tmp;
  tmp |= MXCSR_MASK_MASK;
  set_mxcsr(tmp);
}

static void mxcsr_restore(uint32_t old) {
  set_mxcsr(old);
}


static inline void NO_TOUCH_FLOAT fxsave(fpvm_fpstate_t *fpvm_fpregs)
{
  #ifdef __x86_64__
  __asm__ __volatile__("fxsave64 (%0)" :: "r"(fpvm_fpregs));
  #endif
}

static inline void NO_TOUCH_FLOAT fxrstor(const fpvm_fpstate_t *fpvm_fpregs)
{
  #ifdef __x86_64__
  __asm__ __volatile__("fxrstor64 (%0)" :: "r"(fpvm_fpregs));
  #endif
}

static void init_execution_contexts() {
  memset(context, 0, sizeof(context));
  context_lock = 0;
}

static void lock_contexts() {
  while (!__sync_bool_compare_and_swap(&context_lock, 0, 1)) {
  }
}

static void unlock_contexts() {
  __sync_and_and_fetch(&context_lock, 0);
}

static execution_context_t * find_execution_context(int tid) {
  int i;
  lock_contexts();
  for (i = 0; i < MAX_CONTEXTS; i++) {
    if (context[i].tid == tid) {
      unlock_contexts();
      return &context[i];
    }
  }
  unlock_contexts();
  return 0;
}

static inline execution_context_t *find_my_execution_context(void)
{
  return __fpvm_current_execution_context;
}


static void dump_execution_contexts_info(void)
{
  int i;
  uint32_t m;
  lock_contexts();
  // we will internally be using floating point
  // and need to guarantee that we don't trap to ourselves
  mxcsr_disable_save(&m);

  for (i = 0; i < MAX_CONTEXTS; i++) {
    if (context[i].tid) {
#if CONFIG_INSTR_TRACES
      PRINT_TRACES(&context[i]);
#endif
#if CONFIG_TELEMETRY
      PRINT_TELEMETRY(&context[i]);
#endif
#if CONFIG_PERF_STATS
      PRINT_PERFS(&context[i]);
#endif
    }
  }
  mxcsr_restore(m);
  unlock_contexts();
}


static execution_context_t *alloc_execution_context(int tid) {
  int i;
  lock_contexts();
  for (i = 0; i < MAX_CONTEXTS; i++) {
    if (!context[i].tid) {
      context[i].tid = tid;
      unlock_contexts();
      INIT_TRACER(&context[i]);
#if CONFIG_PERF_STATS
      perf_stat_init(&context[i].gc_stat, "garbage collector");
      perf_stat_init(&context[i].decode_cache_stat, "decode cache");
      perf_stat_init(&context[i].decode_stat, "decoder");
      perf_stat_init(&context[i].bind_stat, "bind");
      perf_stat_init(&context[i].emulate_stat, "emulate");
      perf_stat_init(&context[i].correctness_stat, "correctness");
      perf_stat_init(&context[i].foreign_call_stat, "foreign call");
      perf_stat_init(&context[i].altmath_stat, "altmath");
#endif
      return &context[i];
    }
  }
  unlock_contexts();
  return 0;
}

static void free_execution_context(int tid) {
  int i;
  lock_contexts();
  for (i = 0; i < MAX_CONTEXTS; i++) {
    if (context[i].tid == tid) {
      DEINIT_TRACER(&context[i]);
      context[i].tid = 0;
      unlock_contexts();
    }
  }
  unlock_contexts();
}

static void stringify_current_fe_exceptions(char *buf) {
  int have = 0;
  uint32_t mxcsr = get_mxcsr();
  buf[0] = 0;

#define FE_HANDLE(x)          \
  if (orig_fetestexcept(x)) { \
    if (!have) {              \
      strcat(buf, #x);        \
      have = 1;               \
    } else {                  \
      strcat(buf, " " #x);    \
    }                         \
  }
  FE_HANDLE(FE_DIVBYZERO);
  FE_HANDLE(FE_INEXACT);
  FE_HANDLE(FE_INVALID);
  FE_HANDLE(FE_OVERFLOW);
  FE_HANDLE(FE_UNDERFLOW);
  if (mxcsr & 0x2) {  // denorm
    if (have) {
      strcat(buf, " ");
    }
    strcat(buf, "FE_DENORM");
    have = 1;
  }

  if (!have) {
    strcpy(buf, "NO_EXCEPTIONS_RECORDED");
  }
}

/*
static void show_current_fe_exceptions()
{
  char buf[80];
  stringify_current_fe_exceptions(buf);
  INFO("%s\n", buf);
}
*/

#if CONFIG_HAVE_MAIN
static void fpvm_init(void);
#else
static __attribute__((constructor )) void fpvm_init(void);
#endif

#if DEBUG_OUTPUT

static void dump_rflags(char *pre, ucontext_t *uc) {
  #ifdef __x86_64__
  char buf[256];
  rflags_t *r = (rflags_t *)&(uc->uc_mcontext.gregs[REG_EFL]);

  sprintf(buf, "rflags = %016lx", r->val);

#define EF(x, y)         \
  if (r->x) {            \
    strcat(buf, " " #y); \
  }

  EF(zf, zero);
  EF(sf, neg);
  EF(cf, carry);
  EF(of, over);
  EF(pf, parity);
  EF(af, adjust);
  EF(tf, TRAP);
  EF(intf, interrupt);
  EF(ac, alignment)
  EF(df, down);

  DEBUG("%s: %s\n", pre, buf);
  #endif
}

static void dump_mxcsr(char *pre, ucontext_t *uc) {
  char buf[256];
  #ifdef __x86_64__

  mxcsr_t *m = (mxcsr_t *)&uc->uc_mcontext.fpregs->mxcsr;

  sprintf(buf, "mxcsr = %08x flags:", m->val);

#define MF(x, y)         \
  if (m->x) {            \
    strcat(buf, " " #y); \
  }

  MF(ie, NAN);
  MF(de, DENORM);
  MF(ze, ZERO);
  MF(oe, OVER);
  MF(ue, UNDER);
  MF(pe, PRECISION);

  strcat(buf, " masking:");

  MF(im, nan);
  MF(dm, denorm);
  MF(zm, zero);
  MF(om, over);
  MF(um, under);
  MF(pm, precision);

  DEBUG("%s: %s rounding: %s %s %s\n", pre, buf,
      m->rounding == 0   ? "nearest"
      : m->rounding == 1 ? "negative"
      : m->rounding == 2 ? "positive"
                         : "zero",
      m->daz ? "DAZ" : "", m->fz ? "FTZ" : "");
  #endif
}

#endif

// trap should never be enabled...   this can probably go
static inline void set_trap_flag_context(ucontext_t *uc, int val) {
  #ifdef __x86_64__
  if (val) {
    uc->uc_mcontext.gregs[REG_EFL] |= 0x100UL;
  } else {
    uc->uc_mcontext.gregs[REG_EFL] &= ~0x100UL;
  }
  #else
  // TODO: arm64 & riscv
  #endif
}

static inline void clear_fp_exceptions_context(ucontext_t *uc) {
  #ifdef __x86_64__
  uc->uc_mcontext.fpregs->mxcsr &= ~MXCSR_FLAG_MASK;
  #else
  // TODO: arm64 & riscv
  #endif
}

static inline void set_mask_fp_exceptions_context(ucontext_t *uc, int mask)
{
  #ifdef __x86_64__
  if (mask) {
    uc->uc_mcontext.fpregs->mxcsr |= MXCSR_MASK_MASK;
#ifdef CONFIG_FPTRAPALL
    fptrapall_clear_ts();
#endif
  } else {
    uc->uc_mcontext.fpregs->mxcsr &= ~MXCSR_MASK_MASK;
#ifdef CONFIG_FPTRAPALL
    fptrapall_set_ts();
#endif
  }
  #else
  // TODO: arm64 & riscv
  #endif
}

static inline void zero_fp_xmm_context(ucontext_t *uc)
{
  #ifdef __x86_64__
  memset(uc->uc_mcontext.fpregs->_xmm,0,16*16);
  #else
  // TODO: arm64 & riscv
  #endif
}


static void abort_operation(char *reason) {
  DEBUG("aborting due to %s inited=%d\n",reason,inited);
  if (!inited) {
    DEBUG("Initializing before aborting\n");
    fpvm_init();
    DEBUG("Done with fpvm_preload_init()\n");
  }

  if (!aborted) {
    ORIG_IF_CAN(fedisableexcept, FE_ALL_EXCEPT);
    ORIG_IF_CAN(feclearexcept, FE_ALL_EXCEPT);
    ORIG_IF_CAN(sigaction, SIGFPE, &oldsa_fpe, 0);
    ORIG_IF_CAN(sigaction, SIGINT, &oldsa_int, 0);
    // ORIG_IF_CAN(sigaction, SIGSEGV, &oldsa_segv, 0);

    execution_context_t *mc = find_my_execution_context();

    if (!mc) {
      ERROR("Cannot find execution context\n");
    } else {
      mc->state = ABORT;
    }

    // even if we have no execution context we need to restore
    // the mcontext.  If we do have a execution context,
    // and we are a trap, the mcontext has already been restored
    if (!mc || !mc->aborting_in_trap) {
      // signal ourselves to restore the FP and TRAP state in the context
      kill(gettid(), SIGTRAP);
    }
  }

  // finally remove our trap handler
  ORIG_IF_CAN(sigaction, SIGTRAP, &oldsa_trap, 0);

  aborted = 1;
  DEBUG("Aborted operation because %s\n", reason);
}

static void fpvm_panic(void)
{
  abort_operation("panicing!");
  abort();
}


static int bringup_execution_context(int tid);

int fork() {
  int rc;

  DEBUG("fork\n");

  rc = orig_fork();

  if (aborted) {
    return rc;
  }

  if (rc < 0) {
    DEBUG("fork failed\n");
    return rc;
  }

  if (rc == 0) {
    // child

    // clear exceptions - we will not inherit the current ones from the parent
    ORIG_IF_CAN(feclearexcept, exceptmask);

    if (bringup_execution_context(gettid())) {
      ERROR("Failed to start up execution context at fork\n");
      // we won't break, however..
    } else {
      // we should have inherited all the sighandlers, etc, from our parent
      // now kick ourselves to set the sse bits; we are currently in state INIT
      kill(gettid(), SIGTRAP);
      // we should now be in the right state
    }

    DEBUG("Done with setup on fork\n");
    return rc;

  } else {
    // parent - nothing to do
    return rc;
  }
}

struct tramp_context {
  void *(*start)(void *);
  void *arg;
  int done;
};

static void *trampoline(void *p) {
  struct tramp_context *c = (struct tramp_context *)p;
  void *(*start)(void *) = c->start;
  void *arg = c->arg;
  void *ret;

  // let our wrapper go - this must also be a software barrier
  __sync_fetch_and_or(&c->done, 1);

  DEBUG("Setting up thread %ld\n", gettid());

  // clear exceptions just in case
  ORIG_IF_CAN(feclearexcept, exceptmask);

  // make new context for individual mode
  if (bringup_execution_context(gettid())) {
    ERROR("Failed to start up execution context on thread creation\n");
    // we won't break, however..
  } else {
    // we should have inherited all the sighandlers, etc, from the spawning
    // thread

    // now kick ourselves to set the sse bits; we are currently in state INIT
    kill(gettid(), SIGTRAP);
    // we should now be in the right state
  }
  DEBUG("Done with setup on thread creation\n");

  DEBUG("leaving trampoline\n");

  ret = start(arg);

  // if it's returning normally instead of via pthread_exit(), we'll do the
  // cleanup here

#if CONFIG_INSTR_TRACES
  PRINT_TRACES(find_my_execution_context());
#endif
#if CONFIG_TELEMETRY
  PRINT_TELEMETRY(find_my_execution_context());
#endif
#if CONFIG_PERF_STATS
  PRINT_PERFS(find_my_execution_context());
#endif

  pthread_exit(ret);
}

int pthread_create(pthread_t *tid, const pthread_attr_t *attr, void *(*start)(void *), void *arg) {
  struct tramp_context c;

  DEBUG("pthread_create\n");

  if (aborted) {
    return orig_pthread_create(tid, attr, start, arg);
  }

  c.start = start;
  c.arg = arg;
  c.done = 0;

  int rc = orig_pthread_create(tid, attr, trampoline, &c);

  if (!rc) {
    // don't race on the tramp context - wait for thread to copy out
    while (!__sync_fetch_and_and(&c.done, 1)) {
    }
  }

  DEBUG("pthread_create done\n");

  return rc;
}

static int teardown_execution_context(int tid);

__attribute__((noreturn)) void pthread_exit(void *ret) {
  DEBUG("pthread_exit(%p)\n", ret);

  // we will process this even if we have aborted, since
  teardown_execution_context(gettid());

  orig_pthread_exit(ret);
}

sighandler_t signal(int sig, sighandler_t func) {
  DEBUG("signal(%d,%p)\n", sig, func);
  SHOW_CALL_STACK();
  if ((sig == SIGFPE || sig == SIGTRAP) && !aborted) {
    if (!aggressive) {
      abort_operation("target is using sigaction with SIGFPE or SIGTRAP (nonaggressive)");
    } else {
      // do not override our signal handlers - we are not aborting
      DEBUG(
          "not overriding SIGFPE or SIGTRAP because we are in aggressive "
          "mode\n");
      return 0;
    }
  }
  ORIG_RETURN(signal, sig, func);
}

int sigaction(int sig, const struct sigaction *act, struct sigaction *oldact) {
  DEBUG("sigaction(%d,%p,%p)\n", sig, act, oldact);
  SHOW_CALL_STACK();
  if ((sig == SIGFPE || sig == SIGTRAP) && !aborted) {
    if (!aggressive) {
      abort_operation("target is using sigaction with SIGFPE or SIGTRAP");
      // return 0;
    } else {
      // do not override our signal handlers - we are not aborting
      DEBUG(
          "not overriding SIGFPE or SIGTRAP because we are in aggressive "
          "mode\n");
      return 0;
    }
  }
  ORIG_RETURN(sigaction, sig, act, oldact);
}

int feclearexcept(int excepts) {
  DEBUG("feclearexcept(0x%x)\n", excepts);
  SHOW_CALL_STACK();
  abort_operation("target is using feclearexcept");
  ORIG_RETURN(feclearexcept, excepts);
}

int feenableexcept(int excepts) {
  DEBUG("feenableexcept(0x%x)\n", excepts);
  SHOW_CALL_STACK();
  abort_operation("target is using feenableexcept");
  ORIG_RETURN(feenableexcept, excepts);
}

int fedisableexcept(int excepts) {
  DEBUG("fedisableexcept(0x%x)\n", excepts);
  SHOW_CALL_STACK();
  abort_operation("target is using fedisableexcept");
  ORIG_RETURN(fedisableexcept, excepts);
}

int fegetexcept(void) {
  DEBUG("fegetexcept()\n");
  SHOW_CALL_STACK();
  abort_operation("target is using fegetexcept");
  ORIG_RETURN(fegetexcept);
}

int fegetexceptflag(fexcept_t *flagp, int excepts) {
  DEBUG("fegetexceptflag(%p,0x%x)\n", flagp, excepts);
  SHOW_CALL_STACK();
  abort_operation("target is using fegetexceptflag");
  ORIG_RETURN(fegetexceptflag, flagp, excepts);
}

int feraiseexcept(int excepts) {
  DEBUG("feraiseexcept(0x%x)\n", excepts);
  SHOW_CALL_STACK();
  abort_operation("target is using feraiseexcept");
  ORIG_RETURN(feraiseexcept, excepts);
}

int fesetexceptflag(const fexcept_t *flagp, int excepts) {
  DEBUG("fesetexceptflag(%p,0x%x\n", flagp, excepts);
  SHOW_CALL_STACK();
  abort_operation("target is using fesetexceptflag");
  ORIG_RETURN(fesetexceptflag, flagp, excepts);
}

int fetestexcept(int excepts) {
  DEBUG("fesetexcept(0x%x)\n", excepts);
  SHOW_CALL_STACK();
  abort_operation("target is using fetestexcept");
  ORIG_RETURN(fetestexcept, excepts);
}

int fegetround(void) {
  DEBUG("fegetround()\n");
  SHOW_CALL_STACK();
  abort_operation("target is using fegetround");
  ORIG_RETURN(fegetround);
}

int fesetround(int rounding_mode) {
  DEBUG("fesetround(0x%x)\n", rounding_mode);
  SHOW_CALL_STACK();
  abort_operation("target is using fesetround");
  ORIG_RETURN(fesetround, rounding_mode);
}

int fegetenv(fenv_t *envp) {
  DEBUG("fegetenv(%p)\n", envp);
  SHOW_CALL_STACK();
  abort_operation("target is using fegetenv");
  ORIG_RETURN(fegetenv, envp);
}

int feholdexcept(fenv_t *envp) {
  DEBUG("feholdexcept(%p)\n", envp);
  SHOW_CALL_STACK();
  abort_operation("target is using feholdexcept");
  ORIG_RETURN(feholdexcept, envp);
}

int fesetenv(const fenv_t *envp) {
  DEBUG("fesetenv(%p)\n", envp);
  SHOW_CALL_STACK();
  abort_operation("target is using fesetenv");
  ORIG_RETURN(fesetenv, envp);
}

int feupdateenv(const fenv_t *envp) {
  DEBUG("feupdateenv(%p)\n", envp);
  SHOW_CALL_STACK();
  abort_operation("target is using feupdateenv");
  ORIG_RETURN(feupdateenv, envp);
}

static int setup_shims() {
#define SHIMIFY(x)                              \
  if (!(orig_##x = dlsym(RTLD_NEXT, #x))) {     \
    ERROR("Failed to setup SHIM for " #x "\n"); \
    return -1; \
  }

  if (disable_pthreads == 0) {
    SHIMIFY(pthread_create);
    SHIMIFY(pthread_exit);
  }
  SHIMIFY(fork);
  SHIMIFY(signal);
  SHIMIFY(sigaction);
  if (!getenv("FPVM_NO_LIBM")) {
    SHIMIFY(feclearexcept);
    SHIMIFY(feenableexcept);
    SHIMIFY(fedisableexcept);
    SHIMIFY(fegetexcept);
    SHIMIFY(fegetexceptflag);
    SHIMIFY(feraiseexcept);
    SHIMIFY(fesetexceptflag);
    SHIMIFY(fetestexcept);
    SHIMIFY(fegetround);
    SHIMIFY(fesetround);
    SHIMIFY(fegetenv);
    SHIMIFY(feholdexcept);
    SHIMIFY(fesetenv);
    SHIMIFY(feupdateenv);

    SHIMIFY(pow);
    SHIMIFY(exp);
    SHIMIFY(log);
    SHIMIFY(sin);
    SHIMIFY(sincos);
    SHIMIFY(cos);
    SHIMIFY(tan);

    SHIMIFY(log10);
    SHIMIFY(ceil);
    SHIMIFY(floor);
    SHIMIFY(round);
    SHIMIFY(lround);
    SHIMIFY(ldexp);
    SHIMIFY(__powidf2);

    SHIMIFY(sinh);
    SHIMIFY(cosh);
    SHIMIFY(tanh);

    SHIMIFY(asin);
    SHIMIFY(acos);
    SHIMIFY(atan);
    SHIMIFY(atan2);
    SHIMIFY(asinh);
    SHIMIFY(acosh);
    SHIMIFY(atanh);
  }

  return 0;
}

#define MXCSR_ROUND_DAZ_FTZ_MASK (~(0xe040UL))

static uint32_t get_mxcsr_round_daz_ftz(ucontext_t *uc) {
  #ifdef __x86_64__
  uint32_t mxcsr = uc->uc_mcontext.fpregs->mxcsr;
  uint32_t mxcsr_round = mxcsr & MXCSR_ROUND_DAZ_FTZ_MASK;
  DEBUG("mxcsr (0x%08x) round faz dtz at 0x%08x\n", mxcsr, mxcsr_round);
  // dump_mxcsr("get_mxcsr_round_daz_ftz: ", uc);
  return mxcsr_round;
  #else
  // TODO: arm64 & riscv
  return 0;
  #endif
}

static void set_mxcsr_round_daz_ftz(ucontext_t *uc, uint32_t mask) {
  #ifdef __x86_64__
  if (control_mxcsr_round_daz_ftz) {
    uc->uc_mcontext.fpregs->mxcsr &= MXCSR_ROUND_DAZ_FTZ_MASK;
    uc->uc_mcontext.fpregs->mxcsr |= mask;
    DEBUG("mxcsr masked to 0x%08x after round daz ftz update (0x%08x)\n",
        uc->uc_mcontext.fpregs->mxcsr, mask);
    // dump_mxcsr("set_mxcsr_round_daz_ftz: ", uc);
  }
  #else
  // TODO: arm64 & riscv
  #endif
}

inline static fpvm_inst_t *decode_cache_lookup(execution_context_t *c, void *rip);
inline static void decode_cache_insert(execution_context_t *c, fpvm_inst_t *inst);

// we got here from a correctness trap produced by
// a patch on the application binary.   uc is expected to
// be pointing to the faulting instruction (the patch
// should trigger us before the faulting instruction has
// been executed.
static int correctness_handler(ucontext_t *uc, execution_context_t *mc)
{
  int rc = 0;
  
  ORIG_IF_CAN(fedisableexcept, FE_ALL_EXCEPT);

  void *rip = (void *)MCTX_PC(&uc->uc_mcontext);
  void *rsp = (void *)MCTX_SP(&uc->uc_mcontext);

  printf(" correctness: %16p ", rip);
  for (int i = 0; i < 16; i++) {
    printf("%02x ", ((uint8_t*)rip)[i]);
  }
  fpvm_decoder_decode_and_print_any_inst(rip,stdout,"");
  
  DEBUG("correctness handling for instruction at RIP=%p RSP=%p\n", rip, rsp);

  fpvm_inst_t *fi = 0;
  int do_insert = 0;

  mc->correctness_traps++;
  
  fi = decode_cache_lookup(mc, rip);

  if (!fi) {
    DEBUG("instruction is not in the decode cache\n");
    fi = fpvm_decoder_decode_inst(rip);
    if (!fi) {
      ERROR("cannot decode instruction\n");
      fpvm_decoder_decode_and_print_any_inst(rip,stderr,"undecodable instruction: "); \
      rc = -1;
      goto out;
    }
    do_insert = 1;
  }


#if 0 && DEBUG_OUTPUT
  DEBUG("detailed instruction dump:\n");
  fpvm_decoder_print_inst(fi, stderr);
#endif

  fpvm_regs_t regs;

  regs.mcontext = &uc->uc_mcontext;

  // This stupidly just treats everything as SSE2
  // and must be fixed
  regs.fprs = MCTX_FPRS(&uc->uc_mcontext);
  regs.fpr_size = 16;

  // bind operands
  // not relevant for a call instruction
  // critical for a memory instruction
  if (fpvm_decoder_bind_operands(fi, &regs)) {
    ERROR("Cannot bind operands of instruction\n");
    rc = -1;
    goto out;
  }

#if 0 && DEBUG_OUTPUT
  DEBUG("about to invoke correctness handler, register contents follow:\n"); 
  fpvm_dump_xmms_double(stderr, regs.fprs);
  fpvm_dump_xmms_float(stderr, regs.fprs);
  fpvm_dump_float_control(stderr, uc);
  fpvm_dump_gprs(stderr, uc);
#endif

  int demotions=0;
  fpvm_emulator_correctness_response_t r =
    fpvm_emulator_handle_correctness_for_inst(fi, &regs, &demotions);


#if CONFIG_TELEMETRY_PROMOTIONS
  mc->correctness_demotions+=demotions;
  DEBUG("handling resulted in %d demotions (total %lu so far)\n",demotions,mc->correctness_demotions);
#endif
  
  switch (r) {
  case FPVM_CORRECT_ERROR:
    ERROR("failed to handle correctness for instruction...\n");
    break;
  case FPVM_CORRECT_CONTINUE:
    DEBUG("handled correctness, allowing instruction to proceed\n");
    break;
  case FPVM_CORRECT_SKIP:
    DEBUG("handled correctness, skipping instruction\n");
    MCTX_PC(&uc->uc_mcontext) += fi->length;
    break;
  default:
    ERROR("unknown response from correctness handler: %d\n",r);
    rc = -1;
    break;
  }

#if 0 && DEBUG_OUTPUT
  DEBUG("correctness handling complete, registers follow:\n");
  fpvm_dump_xmms_double(stderr, regs.fprs);
  fpvm_dump_xmms_float(stderr, regs.fprs);
  fpvm_dump_float_control(stderr, uc);
  fpvm_dump_gprs(stderr, uc);
#endif

  if (do_insert) {
    decode_cache_insert(mc, fi);
    DEBUG("problematic instruction added to decode cache\n");
  }

out:

  ORIG_IF_CAN(feenableexcept, FE_ALL_EXCEPT);
  ORIG_IF_CAN(feclearexcept, FE_ALL_EXCEPT);

  return rc;
}

// The correctness trap handler is invoked in the following
// situations:
//
//   bootstrap    - to initially set the FP exceptions/masks/etc for the thread
//   correctness  - invoked by a correctness trap inserted into the application
//                  binary via static analysis and
//   single step  - indirectly after an FP trap if we cannot emulate the
//                  trapping instruction.   This should really not occur
//   abort        - we are in the process of aborting operation process-wide
static int correctness_trap_handler(ucontext_t *uc)
{
  execution_context_t *mc = find_my_execution_context();
  if (!mc || mc->state == ABORT) {
    // ABORT case
    DEBUG("Aborting: mc=%p, mc->state=%d\n",mc,mc?mc->state:-1);
    clear_fp_exceptions_context(uc);        // exceptions cleared
    set_mask_fp_exceptions_context(uc, 1);  // exceptions masked
    set_mxcsr_round_daz_ftz(uc, orig_mxcsr_round_daz_ftz_mask);
    // the trap flag (rflags.
    set_trap_flag_context(uc, 0);  // traps disabled
    if (!mc) {
      // this may end badly
      abort_operation("Cannot find execution context during correctness trap handler exec");
    } else {
      DEBUG("FP and TRAP mcontext restored on abort\n");
    }
    return -1;
  }

  // if we got here, we have an mc, and are in INIT, AWAIT_TRAP, or AWAIT_FPE

  int rc = 0;
  
  switch (mc->state) {
  case INIT:
    DEBUG("initialization trap received\n");
    zero_fp_xmm_context(uc);

#ifdef CONFIG_FPTRAPALL
    // Register this process with the kernel module,
    // and tell it we are inside a signal handler
    fptrapall_register();
    fptrapall_mark_in_signal();
#endif

    // we have completed startup of the thread
    break;
  case AWAIT_TRAP:
    DEBUG("single stepping trap received\n");
#ifdef CONFIG_FPTRAPALL
    // We need to tell the kernel module that we are in a signal
    // (It will only see #NM exceptions)
    fptrapall_mark_in_signal();
#endif

    // we are completing this single step operation
    break;
  case AWAIT_FPE:
    // this must be a correctness trap from the patched binary
    DEBUG("correctness patch-driven trap received\n");
    START_PERF(mc, correctness);
    rc = correctness_handler(uc,mc);
    END_PERF(mc, correctness);
    if (rc) {
      ERROR("correctness handler failed\n");
    }
    break;
  default:
    ERROR("unknown state %d (only INIT, AWAIT_TRAP, and AWAIT_FPE are expected\n",mc->state);
    rc = -1;
    break;
  }
    
  // reconfigure state to reflect waiting for the next FP trap in all cases
  orig_mxcsr_round_daz_ftz_mask = get_mxcsr_round_daz_ftz(uc);
  clear_fp_exceptions_context(uc);        // exceptions cleared
  set_mask_fp_exceptions_context(uc, 0);  // exceptions unmasked
  set_mxcsr_round_daz_ftz(uc, our_mxcsr_round_daz_ftz_mask);
  set_trap_flag_context(uc,0);         // traps disabled

  mc->state = AWAIT_FPE;

  //DEBUG("correctness handling done for thread %lu context %p state %d rc %d\n",gettid(),mc,mc->state,rc);

  return rc;

}

// ENTRY point for SIGTRAP
static void sigtrap_handler(int sig, siginfo_t *si, void *priv)
{
  ucontext_t *uc = (ucontext_t *)priv;

  DEBUG("SIGTRAP signo 0x%x errno 0x%x code 0x%x rip %p\n", si->si_signo, si->si_errno, si->si_code,
      si->si_addr);

  if (correctness_trap_handler(uc)) {
    abort_operation("correctness trap handler failed\n");
    ASSERT(0);
  }
  
  DEBUG("SIGTRAP done (mc->state=%d)\n",find_my_execution_context()->state);
}

#if CONFIG_MAGIC_CORRECTNESS_TRAP
// Entry via magic (e9patch call)
static void *magic_page=0;

void NO_TOUCH_FLOAT fpvm_magic_trap_entry(void *priv)
{
  // Build up a sufficiently detailed ucontext_t and
  // call the shared handler.  Copy in/out the FP and GP
  // state 
  fpvm_fpstate_t fpvm_fpregs FXSAVE_ALIGN;
  ucontext_t fake_ucontext;
  
  // capture FP state (note that this eventually needs to do xsave)
  fxsave(&fpvm_fpregs);
  #ifdef __x86_64__
  // TODO: arm64 & riscv
  fake_ucontext.uc_mcontext.fpregs = &fpvm_fpregs;
  // capture greg state
  // consider memcpy
  for (int i = 0; i < 18; i++) {
    fake_ucontext.uc_mcontext.gregs[i] = *((greg_t*)priv + i);
  }
  #endif

  ucontext_t *uc = (ucontext_t *)&fake_ucontext;

  // This is to handle e9patch's lea instruction
  MCTX_PC(&uc->uc_mcontext) += 8;

  if (correctness_trap_handler(uc)) {
    abort_operation("correctness trap handler failed\n");
    ASSERT(0);
  }

  #ifdef __x86_64__
  // TODO: arm64 & riscv

  // restore GP state
  // consider memcpy
  for (int i = 0; i < 18; i++) {
    *((greg_t*)priv + i) = fake_ucontext.uc_mcontext.gregs[i];
  }
  #endif

  // restore FP state (note that this eventually needs to do xsave)
  // note that this is also doing the mxcsr restore for however
  // fp_trap_handler modified it
  fxrstor(&fpvm_fpregs); 
  return;
}
#endif

static  void hard_fail_show_foreign_func(char *str, void *func)
{
  Dl_info dli;
  dladdr(func,&dli);
  char buf[256];
  if (dli.dli_sname) {
    snprintf(buf,255,"fpvm hard failure: %s: %s\n",str,dli.dli_sname);
  } else {
    snprintf(buf,255,"fpvm hard failure: %s: %p\n",str,func);
  }
  // note that we have clobbered a lot of state in the
  // previous few lines
  DSTR(2,buf);
  abort();
}


void __fpvm_foreign_debug(void)
{
  SAFE_DEBUG_QUAD("fpvm_print_xmm0: ",get_xmm0());
  //  ERROR("args are %lf (%016lx), %lf, %lf, %lf\n",a,*(uint64_t*)&a,b,c,d);
}

void NO_TOUCH_FLOAT  __fpvm_foreign_entry(void **ret, void *tramp, void *func)
{
  fpvm_fpstate_t fstate FXSAVE_ALIGN;
  uint32_t oldmxcsr;

  execution_context_t *mc = find_my_execution_context();
  
  fpvm_regs_t regs;
  int demotions=0;


  SAFE_DEBUG("foreign entry\n");
  
  if (!inited) {
    hard_fail_show_foreign_func("impossible to handle pre-boot foreign call from unknown context - function ", func);
    return ;
  }

  START_PERF(mc, foreign_call);


  oldmxcsr = get_mxcsr();
  fxsave(&fstate);

  if (mc->foreign_return_addr!=&fpvm_panic) {
    hard_fail_show_foreign_func("recursive foreign entry detected - function ",func);
    END_PERF(mc, foreign_call);
    return;
  }

  //SAFE_DEBUG_QUAD("handling correctness for foreign call - trampoline",tramp);
  //SAFE_DEBUG_QUAD("handling correctness for foreign call - function",func);

  mc->correctness_foreign_calls++;
  

  regs.mcontext = 0;        // nothing should need this state
  regs.fprs = FPSTATE_FPRS(&fstate);  // note xmm only
  regs.fpr_size = 16;       // note bogus
    
  demotions = fpvm_emulator_demote_registers(&regs);

  if (demotions<0) {
    abort_operation("demotions in foreign call somehow failed\n");
    END_PERF(mc, foreign_call);
    return;
  }

#if CONFIG_TELEMETRY_PROMOTIONS
  mc->correctness_demotions+=demotions;
  // NOT SAFE TO DO HERE
  // DEBUG("handling foreign call resulted in %d demotions (total %lu so far)\n",demotions,mc->correctness_demotions);
#endif


  // stash the mxcsr we will enable on return
  mc->foreign_return_mxcsr = oldmxcsr;
  // stash the return address of the caller of the wrapper
  // we will ultimately want to return there
  mc->foreign_return_addr = *ret;
  // modify the current return address to return back to the
  // wrapper
  *ret = tramp;

  // disable our traps
  uint32_t newmxcsr = oldmxcsr | MXCSR_MASK_MASK;
  
  // NOT SAFE TO DO HERE WILL POLLUTE FPRS
  //DEBUG("setting mxcsr to %08x (previously %08x)\n", mxcsr, oldmxcsr);
  SAFE_DEBUG("setting fp regs and mxcsr\n");

  fxrstor(&fstate);  // restore demoted registers to machine
  set_mxcsr(newmxcsr); // Write the new mxcsr, with traps disabled

  SAFE_DEBUG("foreign call begins\n");

  END_PERF(mc, foreign_call);

}

void NO_TOUCH_FLOAT  __fpvm_foreign_exit(void **ret)
{
  execution_context_t *mc = find_my_execution_context();

  START_PERF(mc, foreign_call);

  SAFE_DEBUG("foreign call ends\n");
  
  // do mxcsr restore
  set_mxcsr(mc->foreign_return_mxcsr);

  // now modify the return address to go back to
  // the original caller
  *ret = mc->foreign_return_addr;

  mc->foreign_return_addr=&fpvm_panic;

  SAFE_DEBUG("foreign exit\n");

  END_PERF(mc, foreign_call);

}


inline static uint64_t decode_cache_hash_rip(void *rip, uint64_t table_len) {
  return ((uint64_t)rip) % table_len;
}

inline static fpvm_inst_t *decode_cache_lookup(execution_context_t *c, void *rip) {
  uint64_t bin = decode_cache_hash_rip(rip, c->decode_cache_size);

  fpvm_inst_t *cur = c->decode_cache[bin];
  uint64_t count = 0;

  while (cur) {
    if (cur->addr == rip) {
      DEBUG("Found instruction %p in the decode cache bin %lu chain %lu\n", rip, bin, count);
      c->decode_cache_hits++;
      return cur;
    }
    cur = (fpvm_inst_t *)cur->link;
    count++;
  }

  DEBUG("Instruction %p is not in the decode cache bin %lu chain %lu\n", rip, bin, count);

  return 0;
}

inline static void decode_cache_insert(execution_context_t *c, fpvm_inst_t *inst) {
  uint64_t bin = decode_cache_hash_rip(inst->addr, c->decode_cache_size);

  inst->link = (void *)c->decode_cache[bin];
  c->decode_cache[bin] = inst;
  c->decode_cache_unique++;

  DEBUG("Instruction %p inserted in the decode cache bin %lu chain 0\n", inst->addr, bin);
}


inline static int decode_cache_insert_undecodable(execution_context_t *c, void *rip) {
  fpvm_inst_t *inst = malloc(sizeof(fpvm_inst_t));
  
  if (!inst) {
    ERROR("cannot allocate marker for undecodable instruction\n");
    return -1;
  }

  memset(inst,0,sizeof(*inst));

  // zero length instruction marks undecodable
  inst->addr = rip;

  decode_cache_insert(c,inst);

  return 0;
}


#define IS_UNDECODABLE(inst) (!(inst->length))

//
// Shared, common FP trap handling, regardless of how the
// trap is delivered
//
// Note that if a faulting instruction cannot be emulated, the 
// system will switch to single-step mode (x86 trap mode) in order
// to allow the instruction to execute, and then get control back
// to renable FP traps:
//
//   FP Trap -> Emulation Failure -> Single Step Mode + FP Traps Off
//     -> Instruction Executes -> Next Instruction ->
//        Correctness Trap via SIGTRAP
//     -> FP Traps On + Single Step Mode Off
//
static void fp_trap_handler_emu(ucontext_t *uc)
{
  execution_context_t *mc = find_my_execution_context();
  uint8_t *rip = (uint8_t *)MCTX_PC(&uc->uc_mcontext);
  uint8_t *start_rip = rip;

  int inst_promotions = 0, inst_demotions = 0, inst_clobbers = 0;
#if CONFIG_TELEMETRY_PROMOTIONS
  int seq_promotions = 0, seq_demotions = 0, seq_clobbers = 0;
#endif
  
  START_PERF(mc, gc);
  fpvm_gc_run();
  END_PERF(mc, gc);

  
  if (!mc || mc->state != AWAIT_FPE) {
    clear_fp_exceptions_context(uc);        // exceptions cleared
    set_mask_fp_exceptions_context(uc, 1);  // exceptions masked
    set_mxcsr_round_daz_ftz(uc, orig_mxcsr_round_daz_ftz_mask);
    set_trap_flag_context(uc, 0);  // traps disabled
    if (mc) { 
      abort_operation("Caught FP trap while not in AWAIT_TRAP\n");
    } else {
      abort_operation("Cannot find execution context during sigfpvm_handler exec");
    }
    ASSERT(0);
    return;
  }

  mc->fp_traps++;

#define ON_SAME_PAGE(x,y) ((((uint64_t)(x))&(~0xfffUL))==(((uint64_t)(y))&(~0xfffUL)))
  
#if 0 && CONFIG_INSTR_SEQ_EMULATION && DEBUG_OUTPUT
#define DUMP_SEQUENCE_ENDING_INSTR()					\
  if (instindex>0) {							\
    void *__startrip=rip;						\
    void *__currip=rip;							\
    DEBUG("sequence of %d instructions broken by instruction at rip=%p: (plus next 4 (if possible) instructions on page)\n",instindex,__currip); \
    for (int __inst_count=0;__inst_count<5;__inst_count++) {		\
      if (ON_SAME_PAGE(__currip+14,__startrip)) {				\
	__currip+=fpvm_decoder_decode_and_print_any_inst(__currip,stderr,""); \
      } else {								\
	break;								\
      }									\
    }									\
  }
#else
#define DUMP_SEQUENCE_ENDING_INSTR()
#endif

#if 0 && DEBUG_OUTPUT
#define DUMP_CUR_INSTR() fpvm_decoder_print_inst(fi, stderr);
#else
#define DUMP_CUR_INSTR()
#endif
    
  fpvm_inst_t *fi = 0;
  int do_insert = 0;
  char instbuf[256];
  int instindex = 0;
  
  int end_reason = TRACE_END_INSTR_SEQUENCE_MAX;
  
  // repeat until we run out of instructions that
  // need to be emulated or we run off the page
  // instindex = index of current instruction in sequence
  // rip = address of current instruction
  
  for (instindex=0;CONFIG_INSTR_SEQ_EMULATION || instindex<1; instindex++) {

    DEBUG("Handling instruction %d (rip %p) of sequence\n",instindex,rip);

    if (instindex>0 && !ON_SAME_PAGE(rip+14,start_rip)) {
      // note that we care about 15 bytes, so let's just see if we can get 16...
      if (!fpvm_memaddr_probe_readable_long(rip) || !fpvm_memaddr_probe_readable_long(rip+8)) {
	DEBUG("Ending sequence as instruction %d (rip %p) involves a new, unreadable page\n", instindex,rip);
	end_reason = TRACE_END_INSTR_UNREADABLE;
	DUMP_SEQUENCE_ENDING_INSTR();
	fi = 0;
	do_insert = 0;
	break; // done with the sequence
      }
    }
      

    START_PERF(mc, decode_cache);
    fi = decode_cache_lookup(mc, rip);
    END_PERF(mc, decode_cache);

    if (!fi) {
      DEBUG("Instruction is not in the decode cache\n");
      START_PERF(mc, decode);
      fi = fpvm_decoder_decode_inst(rip);
      END_PERF(mc, decode);
      do_insert = 1;
    } else {
      DEBUG("Instruction already found in the decode cache\n");
      do_insert = 0;
    }

    if (!fi || IS_UNDECODABLE(fi)) {
      // The first instruction of the sequence must be decodable...
      if (instindex==0) {
	// -KJH this used to be an "error" but with single stepping we can survive
	DEBUG("Cannot decode instruction %d (rip %p) of sequence: ",instindex,rip);
#if DEBUG_OUTPUT
	fpvm_decoder_decode_and_print_any_inst(rip,stderr," ");
#endif
	//ASSERT(0);
	end_reason = TRACE_END_INSTR_UNDECODABLE;
	// BAD
	goto fail_do_trap;
      } else {
	DEBUG("Ending sequence as instruction %d (rip %p) is not decodable - marking instruction as undecodable if new\n", instindex,rip);
	end_reason = TRACE_END_INSTR_UNDECODABLE;
	DUMP_SEQUENCE_ENDING_INSTR();
	if (!fi) {  // meaning the decoder failed
	  // this means we have not placed the undecodable instruction in the cache previously
	  // so let's do it now
	  if (decode_cache_insert_undecodable(mc,rip)) {
	    ERROR("failed to insert undecodable instruction at index %lu into decode cache\n", instindex);
	  } else {
	    DEBUG("inserted undecodable instruction at index %lu into the decode cache\n", instindex);
	  }
	}
	break; // done with the sequence
      }
    }
    
    DUMP_CUR_INSTR();
    
    // acquire pointers to the GP and FP register state
    // from the mcontext.
    //
    // Note that we update the mcontext each time we
    // complete an instruction in the current sequence
    // so this always reflects the current
    fpvm_regs_t regs;
    
    regs.mcontext = &uc->uc_mcontext;
    
    // PAD: This stupidly just treats everything as SSE2
    // and must be fixed
    regs.fprs = MCTX_FPRS(&uc->uc_mcontext);
    regs.fpr_size = 16;

#if DEBUG_OUTPUT
    fpvm_decoder_decode_and_print_any_inst(fi->addr,stderr,"about to bind: ");
#endif
    
    // bind operands
    START_PERF(mc, bind);
    if (fpvm_decoder_bind_operands(fi, &regs)) {
      if (instindex == 0) ERROR("Could not bind operands. instindex=%d\n", instindex);
      END_PERF(mc, bind);
      if (instindex==0) { 
	ERROR("Cannot bind operands of first (rip %p) of sequence:",rip);
	fpvm_decoder_decode_and_print_any_inst(rip,stderr," ");
	end_reason = TRACE_END_INSTR_UNBINDABLE;
	//ASSERT(0);
	goto fail_do_trap;
      } else {
	ERROR("failed to bind operands of instruction %d (rip %p) of sequence - terminating sequence and marking instruction as undecodable\n",instindex,rip);
	fpvm_decoder_decode_and_print_any_inst(rip,stderr," ");
	DUMP_SEQUENCE_ENDING_INSTR();
	// only free if we didn't find it in the decode cache...
	if (do_insert) {
	  fpvm_decoder_free_inst(fi);
	  // but then insert it into the cache as undecodable
	  if (decode_cache_insert_undecodable(mc,rip)) {
	    ERROR("failed to insert unbindable instruction at index %lu into decode cache\n", instindex);
	  } else {
	    DEBUG("inserted unbindable instruction at index %lu into the decode cache\n", instindex);
	  }
	}
	end_reason = TRACE_END_INSTR_UNBINDABLE;
	break;
      }
    }
    END_PERF(mc, bind);


    
    if (instindex>0 && !fpvm_emulator_should_emulate_inst(fi)) {
      DEBUG("Should not emulate instruction %d (rip %p) of sequence - terminating sequence\n",instindex,rip);
      DUMP_SEQUENCE_ENDING_INSTR();
      // only free if we didn't find it in the decode cache...
      if (do_insert) {
	// at this point we know we have a valid instruction and that it is
	// bindable, but we currently don't want to emulate it due to the data in it
	// so we will add it to the cache
	decode_cache_insert(mc,fi);
      }
      end_reason = TRACE_END_INSTR_SHOULDNOT;
      break;
    }
    
    // #if DEBUG_OUTPUT
    //   DEBUG("Detailed instruction dump:\n");
    //   fpvm_decoder_print_inst(fi, stderr);
    // #endif
    
    //   DEBUG("About to emulate:\n");
    // #if DEBUG_OUTPUT
    //   fpvm_dump_xmms_double(stderr, regs.fprs);
    //   fpvm_dump_xmms_float(stderr, regs.fprs);
    //   fpvm_dump_float_control(stderr, uc);
    //   fpvm_dump_gprs(stderr, uc);
    // #endif
    
    START_PERF(mc, emulate);
    perf_stat_t *altmath_stat = 0;
#if CONFIG_PERF_STATS
    altmath_stat = &mc->altmath_stat;
#endif
    
    if (fpvm_emulator_emulate_inst(fi, &inst_promotions, &inst_demotions, &inst_clobbers, altmath_stat)) {
      END_PERF(mc, emulate);
      if (instindex == 0) {
        DEBUG("Failed to emulate first instruction (rip %p) of sequence - doing trap: ",rip);
#if DEBUG_OUTPUT
	fpvm_decoder_decode_and_print_any_inst(rip,stderr," ");
#endif
	end_reason = TRACE_END_INSTR_UNEMULATABLE;
        //ASSERT(0);
        goto fail_do_trap;
      } else {
	ERROR("Failed to emulate instruction %d (rip %p) of sequence - terminating sequence and marking instruction as undecodable\n",instindex,rip);
#if DEBUG_OUTPUT
	fpvm_decoder_decode_and_print_any_inst(rip,stderr," ");
#endif
	DUMP_SEQUENCE_ENDING_INSTR();
	// we will consider this further - if it happens often, it's probably an emulator issue
	// however, in either case, it's not clear why we would not add the instruction to the decode
	// cache at this point
	//
	//  what happened in dp:  movq		rbx, xmm5 (5 bytes)
	//
	if (do_insert) {
	  // only free if we didn't find it in the decode cache...
	  fpvm_decoder_free_inst(fi);
	  // since we have seen this instruction for the first time, and we
	  // cannot emulate it, we will mark it as sequence-ending in the cache
	  // so we stop immediately when we encounter it the next time
	  if (decode_cache_insert_undecodable(mc,rip)) {
	    ERROR("failed to insert unemulatable instruction at index %lu into decode cache\n", instindex);
	  } else {
	    DEBUG("inserted unemulatable instruction at index %lu into the decode cache\n", instindex);
	  }
	}
	end_reason = TRACE_END_INSTR_UNEMULATABLE;
        break;
      }
    }
    END_PERF(mc, emulate);
    
#if CONFIG_TELEMETRY_PROMOTIONS
    seq_promotions += inst_promotions;
    seq_demotions += inst_demotions;
    seq_clobbers += inst_clobbers;
    DEBUG("instruction emulation created %d promotions, %d demotions, and %d clobbers; sequence so far has %d promotions, %d demotions, and %d clobbers\n", inst_promotions, inst_demotions, inst_clobbers, seq_promotions, seq_demotions, seq_clobbers);
#endif
    
    rip += fi->length;
    
    // DEBUG("Emulation done:\n");
    // #if DEBUG_OUTPUT
    //   fpvm_dump_xmms_double(stderr, regs.fprs);
    //   fpvm_dump_xmms_float(stderr, regs.fprs);
    //   fpvm_dump_float_control(stderr, uc);
    //   fpvm_dump_gprs(stderr, uc);
    // #endif
    
    // Skip those instructions we just emulated.
    MCTX_PC(&uc->uc_mcontext) = (greg_t)rip;
    
    if (do_insert) {
      // put into the cache for next time
      decode_cache_insert(mc, fi);
    }
    
    // stay in state AWAIT_FPE
    
    mc->emulated_inst++;

    
  }

  // At this point, we have successfully finished at least one instruction
  RECORD_TRACE(mc,end_reason,(uint64_t)start_rip,instindex);

  (void)end_reason;
  

#if CONFIG_TELEMETRY
  if (CONFIG_TELEMETRY_PERIOD && !(mc->fp_traps % CONFIG_TELEMETRY_PERIOD)) {
    PRINT_TELEMETRY(mc);
  }
#endif
#if CONFIG_INSTR_TRACES
  if (CONFIG_INSTR_TRACES_PERIOD && !(mc->fp_traps % CONFIG_INSTR_TRACES_PERIOD)) {
    PRINT_TRACES(mc);
  }
#endif
#if CONFIG_PERF_STATS
  if (CONFIG_PERF_STATS_PERIOD && !(mc->fp_traps % CONFIG_PERF_STATS_PERIOD)) {
    PRINT_PERFS(mc);
  }
#endif

#if CONFIG_TELEMETRY_PROMOTIONS
  mc->promotions += seq_promotions;
  mc->demotions += seq_demotions;
  mc->clobbers += seq_clobbers;
  DEBUG("sequence had %d promotions, %d demotions, and %d clobbers\n", seq_promotions, seq_demotions, seq_clobbers);
#endif

  DEBUG("FPE succesfully done (emulated sequence of %d instructions)\n",instindex);

  // DEBUG("mxcsr was %08lx\n",uc->uc_mcontext.fpregs->mxcsr);

  clear_fp_exceptions_context(uc);        // exceptions cleared

  // DEBUG("mxcsr is now %08lx\n",uc->uc_mcontext.fpregs->mxcsr);

  return;
  
  // we should only get here if the first instruction
  // of a sequence could not be decoded, bound, or emulated
fail_do_trap:

  DEBUG("doing fail do trap for %p\n",rip);

  if (fi) {
    DEBUG("have decoded failing instruction\n");
    // only free if we didn't find it in the decode cache...
    if (do_insert) {
      fpvm_decoder_free_inst(fi);
    }
  }

#if CONFIG_TELEMETRY_PROMOTIONS
  mc->promotions += seq_promotions;
  mc->demotions += seq_demotions;
  mc->clobbers += seq_clobbers;
  DEBUG("evil sequence had %d promotions, %d demotions, and %d clobbers\n", seq_promotions, seq_demotions, seq_clobbers);
#endif

  DEBUG("switching to trap mode\n");

  // switch to trap mode, so we can re-enable FP traps after this instruction is
  // done
  clear_fp_exceptions_context(uc);        // exceptions cleared
  set_mask_fp_exceptions_context(uc, 1);  // exceptions masked
  set_mxcsr_round_daz_ftz(uc, our_mxcsr_round_daz_ftz_mask);
  set_trap_flag_context(uc, 1);  // traps disabled
  
  mc->state = AWAIT_TRAP;

  // our next stop should be the instruction, and then, immediately afterwards,
  // the sigtrap handler

  return;
}


// Attempt at handler for simple single instruction trap
static void fp_trap_handler_nvm(ucontext_t *uc)
{
  execution_context_t *mc = find_my_execution_context();
  uint8_t *rip = (uint8_t *)MCTX_PC(&uc->uc_mcontext);

  // Let the garbage collector run
  fpvm_gc_run();

  // sanity check state and abort if needed
  if (!mc || mc->state != AWAIT_FPE) {
    clear_fp_exceptions_context(uc);        // exceptions cleared
    set_mask_fp_exceptions_context(uc, 1);  // exceptions masked
    set_mxcsr_round_daz_ftz(uc, orig_mxcsr_round_daz_ftz_mask);
    set_trap_flag_context(uc, 0);  // traps disabled
    if (mc) { 
      abort_operation("Caught FP trap while not in AWAIT_TRAP\n");
    } else {
      abort_operation("Cannot find execution context during sigfpvm_handler exec");
    }
    ASSERT(0);
    return;
  }

  mc->fp_traps++;

#if 0 && DEBUG_OUTPUT
#define DUMP_CUR_INSTR() fpvm_decoder_print_inst(fi, stderr);
#else
#define DUMP_CUR_INSTR()
#endif
    
  fpvm_inst_t *fi = 0;
  int do_insert = 0;
  fpvm_regs_t regs;
  
  regs.mcontext = &uc->uc_mcontext;
    
  // PAD: This stupidly just treats everything as SSE2
  // and must be fixed
  // we get the registers early since
  // we will need to do a fake bind the first
  // time we see an instruction
  regs.fprs = MCTX_FPRS(&uc->uc_mcontext);
  regs.fpr_size = 16;  
  
  DEBUG("Handling instruction (rip = %p)\n",rip);

  fi = decode_cache_lookup(mc, rip);

  if (!fi) {
    DEBUG("Instruction is not in the decode cache\n");
    fi = fpvm_decoder_decode_inst(rip);
    if (!fi) {
      DEBUG("failed to decode instruction at %p\n",rip);
      goto fail_do_trap;
    }
    // Doing fake bind here to capture operand sizes
    // which is needed by the vm compilation
    if (fpvm_decoder_bind_operands(fi, &regs)) {
      DEBUG("Cannot fake-bind operands of instruction\n");
      goto fail_do_trap;
    }
    if (fpvm_vm_compile(fi)) {
      DEBUG("cannot compile instruction\n");
      goto fail_do_trap;
    }
    DEBUG("successfully decoded and compiled instruction, which follows:\n");
    fpvm_builder_disas(stderr, (fpvm_builder_t*)fi->codegen);
    do_insert = 1;
  } else {
    DEBUG("Instruction already found in the decode cache, ignoring decode, bind, codegen, and vm context creation\n");
    do_insert = 0;
  }

  DEBUG("vm init\n");
  fpvm_vm_init(mc->vm, fi, &regs);
  
  DEBUG("vm run\n");
  if (fpvm_vm_run(mc->vm)) {
    DEBUG("failed to execute VM successfully for instruction at %p\n");
    // this would be very bad since it could have partially completed, mangling stuff
    goto fail_do_trap;
  }

  
  rip += fi->length;
    
  // DEBUG("Emulation done:\n");
  // #if DEBUG_OUTPUT
  //   fpvm_dump_xmms_double(stderr, regs.fprs);
  //   fpvm_dump_xmms_float(stderr, regs.fprs);
  //   fpvm_dump_float_control(stderr, uc);
  //   fpvm_dump_gprs(stderr, uc);
  // #endif
    
  // Skip those instructions we just emulated.
  MCTX_PC(&uc->uc_mcontext) = (greg_t)rip;
  
  if (do_insert) {
    // put into the cache for next time
    decode_cache_insert(mc, fi);
  }
    
  // stay in state AWAIT_FPE
    
  mc->emulated_inst++;
  
  DEBUG("FPE succesfully done (emulated one instruction)\n");
  
  // DEBUG("mxcsr was %08lx\n",uc->uc_mcontext.fpregs->mxcsr);
  
  clear_fp_exceptions_context(uc);        // exceptions cleared
  
  // DEBUG("mxcsr is now %08lx\n",uc->uc_mcontext.fpregs->mxcsr);
  
  return;
  
  // we should only get here if the instruction
  // could not be handled
fail_do_trap:

  DEBUG("doing fail do trap for %p\n",rip);

  if (fi) {
    DEBUG("have decoded failing instruction\n");
    // only free if we didn't find it in the decode cache...
    if (do_insert) {
      fpvm_decoder_free_inst(fi);
    }
  }

  DEBUG("switching to trap mode\n");

  // switch to trap mode, so we can re-enable FP traps after this instruction is
  // done
  clear_fp_exceptions_context(uc);        // exceptions cleared
  set_mask_fp_exceptions_context(uc, 1);  // exceptions masked
  set_mxcsr_round_daz_ftz(uc, our_mxcsr_round_daz_ftz_mask);
  set_trap_flag_context(uc, 1);  // traps disabled
  
  mc->state = AWAIT_TRAP;

  // our next stop should be the instruction, and then, immediately afterwards,
  // the sigtrap handler

  return;
}


static inline void fp_trap_handler(ucontext_t *uc)
{
#if CONFIG_USE_NVM
  return fp_trap_handler_nvm(uc);
#else
  return fp_trap_handler_emu(uc);
#endif
}

//
// Entry point for FP Trap for trap short circuiting (kernel module)
// is used
//
#if CONFIG_TRAP_SHORT_CIRCUITING
void fpvm_short_circuit_handler(void *priv)
{
  // Build up a sufficiently detailed ucontext_t and
  // call the shared handler.  Copy in/out the FP and GP
  // state 
  
  siginfo_t fake_siginfo;
  fpvm_fpstate_t fpvm_fpregs; 
  ucontext_t fake_ucontext;
  uint32_t old;
  
  // capture FP state (note that this eventually needs to do xsave)
  fxsave(&fpvm_fpregs);

  // disable FP traps during our handler execution
  mxcsr_disable_save(&old);

  
  uint32_t err = ~(old >> 7) & old;
  if (err & 0x001) {	/* Invalid op*/
    fake_siginfo.si_code = FPE_FLTINV;
  } else if (err & 0x004) { /* Divide by Zero */
    fake_siginfo.si_code = FPE_FLTDIV;
  } else if (err & 0x008) { /* Overflow */
    fake_siginfo.si_code = FPE_FLTOVF;
  } else if (err & 0x012) { /* Denormal, Underflow */
    fake_siginfo.si_code = FPE_FLTUND;
  } else if (err & 0x020) { /* Precision */
    fake_siginfo.si_code = FPE_FLTRES;
  }
  
  siginfo_t * si = (siginfo_t *)&fake_siginfo;

  #ifdef __x86_64__
  // TODO: arm64 & riscv
  fake_ucontext.uc_mcontext.fpregs = &fpvm_fpregs;

  // consider memcpy
  for (int i = 0; i < 18; i++) {
    fake_ucontext.uc_mcontext.gregs[i] = *((greg_t*)priv + i);
  }
  #endif

  ucontext_t *uc = (ucontext_t *)&fake_ucontext;
 
  uint8_t *rip = (uint8_t*) MCTX_PC(&uc->uc_mcontext);

  DEBUG(
	"SCFPE signo 0x%x errno 0x%x code 0x%x rip %p %02x %02x %02x %02x %02x "
	"%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
	si->si_signo, si->si_errno, si->si_code, si->si_addr, rip[0], rip[1], rip[2], rip[3], rip[4],
	rip[5], rip[6], rip[7], rip[8], rip[9], rip[10], rip[11], rip[12], rip[13], rip[14], rip[15]);
  DEBUG("SCFPE RIP=%p RSP=%p\n", rip, MCTX_SP(&uc->uc_mcontext));
  
#if DEBUG_OUTPUT
  char buf[80];
#define CASE(X)      \
  case X:            \
    strcpy(buf, #X); \
    break;
  switch (si->si_code) {
    CASE(FPE_FLTDIV);
    CASE(FPE_FLTINV);
    CASE(FPE_FLTOVF);
    CASE(FPE_FLTUND);
    CASE(FPE_FLTRES);
    CASE(FPE_FLTSUB);
    CASE(FPE_INTDIV);
    CASE(FPE_INTOVF);
  default:
    sprintf(buf, "UNKNOWN(0x%x)\n", si->si_code);
    break;
  }
  DEBUG("FPE exceptions: %s\n", buf);
#endif
  
  fp_trap_handler(uc);
  
  DEBUG("SCFPE  done\n");

  #ifdef __x86_64__
  // TODO: arm64 & riscv

  // restore GP state
  // consider memcpy
  for (int i = 0; i < 18; i++) {
    *((greg_t*)priv + i) = fake_ucontext.uc_mcontext.gregs[i];
  }
  #endif

  // restore FP state (note that this eventually needs to do xsave)
  // note that this is also doing the mxcsr restore for however
  // fp_trap_handler modified it
  fxrstor(&fpvm_fpregs);
  
  return;
}
#endif
  

//
// Entry point for FP Trap when the SIGFPE (normal kernel delivery)
// mechanism is used
//
static void sigfpe_handler(int sig, siginfo_t *si, void *priv) {

    uint32_t saved_mxcsr;
    mxcsr_disable_save(&saved_mxcsr);
  
  ucontext_t *uc = (ucontext_t *)priv;
  uint8_t *rip = (uint8_t*) MCTX_PC(&uc->uc_mcontext);

  DEBUG(
      "SIGFPE signo 0x%x errno 0x%x code 0x%x rip %p %02x %02x %02x %02x %02x "
      "%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
      si->si_signo, si->si_errno, si->si_code, si->si_addr, rip[0], rip[1], rip[2], rip[3], rip[4],
      rip[5], rip[6], rip[7], rip[8], rip[9], rip[10], rip[11], rip[12], rip[13], rip[14], rip[15]);
  DEBUG("FPE PC=%p SP=%p\n", rip, (void *)MCTX_SP(&uc->uc_mcontext));

#if DEBUG_OUTPUT
  char buf[80];
#define CASE(X)      \
  case X:            \
    strcpy(buf, #X); \
    break;
  switch (si->si_code) {
    CASE(FPE_FLTDIV);
    CASE(FPE_FLTINV);
    CASE(FPE_FLTOVF);
    CASE(FPE_FLTUND);
    CASE(FPE_FLTRES);
    CASE(FPE_FLTSUB);
    CASE(FPE_INTDIV);
    CASE(FPE_INTOVF);
    default:
      sprintf(buf, "UNKNOWN(0x%x)\n", si->si_code);
      break;
  }
  DEBUG("FPE exceptions: %s\n", buf);
#endif

  fp_trap_handler(uc);
  mxcsr_restore(saved_mxcsr);
}

static __attribute__((destructor)) void fpvm_deinit(void);

static void sigint_handler(int sig, siginfo_t *si, void *priv) {
  DEBUG("SIGINT\n");

  if (oldsa_int.sa_sigaction) {
    fpvm_deinit();  // dump everything out
    // invoke underlying handler
    oldsa_int.sa_sigaction(sig, si, priv);
  } else {
    // exit - our deinit will be called
    exit(-1);
  }
}

static void sigsegv_handler(int sig, siginfo_t *si, void *priv)
{
  ucontext_t *uc = (ucontext_t *)priv;
  void *rip = (uint8_t*) MCTX_PC(&uc->uc_mcontext);
  void *addr = si->si_addr;
  int probe = rip==fpvm_memaddr_probe_readable_long;
  
  DEBUG("SIGSEGV rip=%p (%s) addr=%p reason: %d (%s)\n",rip,probe ? "probe" : "NOT PROBE",addr,
	si->si_code, si->si_code==SEGV_MAPERR ? "MAPERR" : si->si_code==SEGV_ACCERR ? "PERM" : "UNKNOWN");
  if (probe) {
    // this means we faulted, in the probe address
    // and so it is unwritable, so return to retbad
    // if it did not fault, then it would continue to retgood
    MCTX_PC(&uc->uc_mcontext) += 0xb;
  } else {
    // this means it is a fault somewhere in FPVM (impossible!) or
    // in the program, so continue with original handling
    if (oldsa_segv.sa_sigaction) {
      // invoke underlying handler
      oldsa_segv.sa_sigaction(sig, si, priv);
      return;
    } else {
#define DUMP(p,cp) (((((uint64_t)(p))&(~0xfffUL))==(((uint64_t)(cp))&(~0xfffUL))) ? *(uint8_t*)(cp) : 0 )
      // exit - our deinit will be called
      ERROR("not our segfault and don't know what to do with it:  rip=%p addr=%p reason: %d (%s) instruction bytes on page follow: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
	    rip,addr,  si->si_code, si->si_code==SEGV_MAPERR ? "MAPERR" : si->si_code==SEGV_ACCERR ? "PERM" : "UNKNOWN",
	    DUMP(rip,rip+0),
	    DUMP(rip,rip+1),
	    DUMP(rip,rip+2),
	    DUMP(rip,rip+3),
	    DUMP(rip,rip+4),
	    DUMP(rip,rip+5),
	    DUMP(rip,rip+6),
	    DUMP(rip,rip+7),
	    DUMP(rip,rip+8),
	    DUMP(rip,rip+9),
	    DUMP(rip,rip+10),
	    DUMP(rip,rip+11),
	    DUMP(rip,rip+12),
	    DUMP(rip,rip+13),
	    DUMP(rip,rip+14),
	    DUMP(rip,rip+15));	    
      
      //exit(-1);
      abort();
    }
  }
}


static int bringup_execution_context(int tid) {
  execution_context_t *c;

  if (!(c = alloc_execution_context(tid))) {
    ERROR("Cannot allocate execution context\n");
    return -1;
  }

  c->state = INIT;
  c->foreign_return_mxcsr=0;
  c->foreign_return_addr=&fpvm_panic;
  c->aborting_in_trap = 0;
  c->fp_traps = 0;
  c->demotions = 0;
  c->promotions = 0;
  c->clobbers = 0;
  c->correctness_traps = 0;
  c->correctness_foreign_calls = 0;
  c->correctness_demotions = 0;
  c->emulated_inst = 0;
  c->decode_cache = malloc(sizeof(fpvm_inst_t *) * decode_cache_size);
  if (!c->decode_cache) {
    ERROR("Cannot allocate code cache for context\n");
    c->decode_cache_size = 0;
  } else {
    c->decode_cache_size = decode_cache_size;
    memset(c->decode_cache, 0, sizeof(fpvm_inst_t *) * c->decode_cache_size);
  }
#if CONFIG_USE_NVM
  c->vm = malloc(sizeof(*(c->vm)));
  if (!c->vm) {
    ERROR("Cannot allocate vm for context\n");
  } else {
    memset(c->vm, 0, sizeof(*(c->vm)));
  }
#endif
  __fpvm_current_execution_context = c;

  DEBUG("brought up execution context for thread %lu at %p (state %d)\n",gettid(),c,c->state);
  
  return 0;
}

static int teardown_execution_context(int tid) {
  execution_context_t *mc = find_execution_context(tid);

  if (!mc) {
    ERROR("Cannot find execution context for %d\n", tid);
    return -1;
  }

  ORIG_IF_CAN(fedisableexcept, FE_ALL_EXCEPT);
  PRINT_PERFS(mc);
  ORIG_IF_CAN(feenableexcept, FE_ALL_EXCEPT);

  if (mc->decode_cache) {
    int i;
    fpvm_inst_t *next, *cur;
    for (i = 0; i < mc->decode_cache_size; i++) {
      next = mc->decode_cache[i];
      while (next) {
        cur = next;
        next = (fpvm_inst_t *)cur->link;
        fpvm_decoder_free_inst(cur);
      }
    }
    free(mc->decode_cache);
  }

  free_execution_context(tid);

  DEBUG("Tore down execution context for %d\n", tid);

  return 0;
}


#if CONFIG_TRAP_SHORT_CIRCUITING
// trampoline entry stub - from the assembly code
extern void * _user_fpvm_entry;
#endif

#if !CONFIG_HAVE_MAIN
// This is defined in the LD_PRELOAD for the wrapper
extern int fpvm_setup_additional_wrappers();
#endif

int fpvm_demote_in_place(void *v) {
  execution_context_t *mc = find_my_execution_context();

  START_PERF(mc, correctness);
  uint64_t *p = v;
  uint64_t orig = *p;

  restore_double_in_place(v);
  
  END_PERF(mc, correctness);
  return *p != orig;
}

static int bringup() {

  // fpvm_gc_init();
  fpvm_gc_init(fpvm_number_init, fpvm_number_deinit);

  if (fpvm_decoder_init()) {
    ERROR("Failed to initialized decoder\n");
    return -1;
  }

  if (setup_shims()) {
    ERROR("Cannot setup shims\n");
    return -1;
  }

#if !CONFIG_HAVE_MAIN
  //if (fpvm_setup_additional_wrappers()) {
  //  ERROR("Some additional wrapper setup failed - ignoring\n");
  //}
#endif
  
  ORIG_IF_CAN(feclearexcept, exceptmask);

  init_execution_contexts();

  if (bringup_execution_context(gettid())) {
    ERROR("Failed to start up execution context at startup\n");
    return -1;
  }


  struct sigaction sa;

#if CONFIG_TRAP_SHORT_CIRCUITING
  if (kernel) { 
    int file_desc = open("/dev/fpvm_dev", O_RDWR);
    
    if (file_desc < 0) {
      ERROR("SC failed to open FPVM kernel support (/dev/fpvm_dev), falling back to signal handler\n");
      goto setup_sigfpe;
    } else {
	if (ioctl(file_desc, FPVM_IOCTL_REG, &_user_fpvm_entry)) {
	  ERROR("SC failed to ioctl FPVM kernel support (/dev/fpvm_dev), falling back to signal handler\n");
	  goto setup_sigfpe;
	} else {
	  DEBUG(":) FPVM kernel support setup successful\n");
	  goto skip_setup_sigfpe;
	} 
      }
  }else {
    DEBUG("skipping FPVM kernel support, even though it is enabled\n");
    goto setup_sigfpe;
  }

 setup_sigfpe:

#endif
    
  memset(&sa,0,sizeof(sa));
  sa.sa_sigaction = sigfpe_handler;
  sa.sa_flags |= SA_SIGINFO;
  sigemptyset(&sa.sa_mask);
  sigaddset(&sa.sa_mask, SIGINT);
  sigaddset(&sa.sa_mask, SIGTRAP);
  ORIG_IF_CAN(sigaction,SIGFPE,&sa,&oldsa_fpe);

#if CONFIG_TRAP_SHORT_CIRCUITING
 skip_setup_sigfpe:
#endif

  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = sigtrap_handler;
  sa.sa_flags |= SA_SIGINFO;
  sigemptyset(&sa.sa_mask);
  sigaddset(&sa.sa_mask, SIGINT);
  sigaddset(&sa.sa_mask, SIGTRAP);
  sigaddset(&sa.sa_mask, SIGFPE);
  ORIG_IF_CAN(sigaction, SIGTRAP, &sa, &oldsa_trap);

  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = sigint_handler;
  sa.sa_flags |= SA_SIGINFO;
  sigemptyset(&sa.sa_mask);
  sigaddset(&sa.sa_mask, SIGTRAP);
  ORIG_IF_CAN(sigaction, SIGINT, &sa, &oldsa_int);

  // memset(&sa, 0, sizeof(sa));
  // sa.sa_sigaction = sigsegv_handler;
  // sa.sa_flags |= SA_SIGINFO;
  // sigemptyset(&sa.sa_mask);
  // sigaddset(&sa.sa_mask, SIGSEGV);
  // ORIG_IF_CAN(sigaction, SIGSEGV, &sa, &oldsa_segv);

  ORIG_IF_CAN(feenableexcept, exceptmask);

#if CONFIG_MAGIC_CORRECTNESS_TRAP
  // see if the binary has magic trap support
  fpvm_magic_trap_entry_t *f;

  f = dlsym(RTLD_NEXT, FPVM_MAGIC_TRAP_ENTRY_NAME_STR);

  if (f) {
    *f = (fpvm_magic_trap_entry_t)&fpvm_magic_trap_entry;
    DEBUG("airdropped magic trap location\n");
  } else {
    DEBUG("no airdrop of magic trap is possible, can't find %s\n",FPVM_MAGIC_TRAP_ENTRY_NAME_STR);
    DEBUG("setting up magic page instead\n");
    magic_page=mmap(FPVM_MAGIC_ADDR,
		    4096,
		    PROT_READ | PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
		    0,0);
    if (magic_page!=FPVM_MAGIC_ADDR) {
      DEBUG("unable to allocate magic page at %p\n",FPVM_MAGIC_ADDR);
      if (magic_page!=MAP_FAILED) {
	munmap(magic_page,4096);
      }
      magic_page = 0;
    } else {
      struct fpvm_trap_magic *magic = magic_page;
      magic->magic_cookie = FPVM_MAGIC_COOKIE;
      magic->trap = fpvm_magic_trap_entry;
      magic->demote = fpvm_demote_in_place;

      // *(uint64_t*)magic_page = FPVM_MAGIC_COOKIE;
      // *(fpvm_magic_trap_entry_t *)(magic_page+FPVM_TRAP_OFFSET) = (fpvm_magic_trap_entry_t)&fpvm_magic_trap_entry;
      DEBUG("magic page initialized at %p\n",magic_page);
    }
  }
#endif

  // now kick ourselves to set the sse bits; we are currently in state INIT

  kill(getpid(), SIGTRAP);

  inited = 1;
  DEBUG("Done with setup\n");
  return 0;
}

// This should probably be specific to FPVM, but
// when we invoke
static void config_exceptions(char *buf) {
  exceptmask = 0;
  mxcsrmask_base = 0;

  if (strcasestr(buf, "inv")) {
    DEBUG("tracking INVALID\n");
    exceptmask |= FE_INVALID;
    mxcsrmask_base |= 0x1;
  }
  if (strcasestr(buf, "den")) {
    DEBUG("tracking DENORM\n");
    exceptmask |= 0;  // not provided...
    mxcsrmask_base |= 0x2;
  }
  if (strcasestr(buf, "div")) {
    DEBUG("tracking DIVIDE_BY_ZERO\n");
    exceptmask |= FE_DIVBYZERO;
    mxcsrmask_base |= 0x4;
  }
  if (strcasestr(buf, "over")) {
    DEBUG("tracking OVERFLOW\n");
    exceptmask |= FE_OVERFLOW;
    mxcsrmask_base |= 0x8;
  }
  if (strcasestr(buf, "under")) {
    DEBUG("tracking UNDERFLOW\n");
    exceptmask |= FE_UNDERFLOW;
    mxcsrmask_base |= 0x10;
  }
  if (strcasestr(buf, "prec")) {
    DEBUG("tracking PRECISION\n");
    exceptmask |= FE_INEXACT;
    mxcsrmask_base |= 0x20;
  }
}

static void config_round_daz_ftz(char *buf) {
  uint32_t r = 0;

  if (strcasestr(buf, "pos")) {
    r = 0x4000UL;
  } else if (strcasestr(buf, "neg")) {
    r = 0x2000UL;
  } else if (strcasestr(buf, "zer")) {
    r = 0x6000UL;
  } else if (strcasestr(buf, "nea")) {
    r = 0x0000UL;
  } else {
    ERROR("Unknown rounding mode - avoiding rounding control\n");
    control_mxcsr_round_daz_ftz = 0;
    return;
  }

  if (strcasestr(buf, "daz")) {
    r |= 0x0040UL;
  }
  if (strcasestr(buf, "ftz")) {
    r |= 0x8000UL;
  }

  control_mxcsr_round_daz_ftz = 1;
  our_mxcsr_round_daz_ftz_mask = r;

  DEBUG("Configuring rounding control to 0x%08x\n", our_mxcsr_round_daz_ftz_mask);
}





// Called on load of preload library
#if CONFIG_HAVE_MAIN
static void fpvm_init(void) {
#else
static __attribute__((constructor )) void fpvm_init(void) {
#endif
  INFO("init\n");
  //SAFE_DEBUG("we are not in crazy town, ostensibly\n");

  if (!inited) {

    pulse_start("fpvm.json");
    // Grab the log destination
    char *log_dst = getenv("FPVM_LOG_FILE");
    if (log_dst != NULL) {
      fpvm_log_file = fopen(log_dst, "w");
      if (!fpvm_log_file) {
	ERROR("cannot open log file %s, reverting to stderr\n",log_dst);
      } else {
	DEBUG("opening log file %s\n",log_dst);
      }
    } else {
      DEBUG("no log file specified, using stderr\n");
    }

    kernel = 1;
    if (getenv("FPVM_KERNEL") && tolower(getenv("FPVM_KERNEL")[0])=='y') {
      DEBUG("Attempting to use FPVM kernel suppport\n");
      kernel = 1;
    }


    INFO("LD_PRELOAD=%s\n", getenv("LD_PRELOAD"));
    for (int i = 0; enabled_configurations[i]; i++) {
        INFO("Enabled config %s\n", enabled_configurations[i]);
    }

    if (getenv("FPVM_AGGRESSIVE") && tolower(getenv("FPVM_AGGRESSIVE")[0]) == 'y') {
      DEBUG("Setting AGGRESSIVE\n");
      aggressive = 1;
    }
    if ((getenv("FPVM_DISABLE_PTHREADS") && tolower(getenv("FPVM_DISABLE_PTHREADS")[0]) == 'y') ||
        (getenv("DISABLE_PTHREADS") && tolower(getenv("DISABLE_PTHREADS")[0]) == 'y')) {
      disable_pthreads = 1;
    }
    if (getenv("FPVM_EXCEPT_LIST")) {
      config_exceptions(getenv("FPVM_EXCEPT_LIST"));
    }
    if (getenv("FPVM_FORCE_ROUNDING")) {
      config_round_daz_ftz(getenv("FPVM_FORCE_ROUNDING"));
    }
    if (bringup()) {
      ERROR("cannot bring up framework\n");
      return;
    }

    DEBUG("fpvm_init done\n");
    return;
  } else {
    ERROR("already inited!\n");
    return;
  }
}

// Called on unload of preload library
#if CONFIG_HAVE_MAIN
static void fpvm_deinit(void) {
#else
static __attribute__((destructor)) void fpvm_deinit(void) {
#endif


  pulse_stop();
  DEBUG("deinit\n");
  dump_execution_contexts_info();

  // If a different log file was chosen, close it.
  if (fpvm_log_file) fclose(fpvm_log_file);
  inited = 0;
  DEBUG("done\n");
}


 

#if CONFIG_HAVE_MAIN

/*
asm (
".global my_instruction\n"
"my_instruction:\n"
"   vfmaddsd %xmm1, %xmm2, %xmm3, %xmm4\n"
// "   sqrtpd %xmm2, %xmm3\n"
// "   maxsd %xmm2, %xmm3\n"
// "   subpd %xmm2, %xmm3\n"
// "   mulpd %xmm2, %xmm3\n"
);
*/

 
extern uint8_t my_instruction[];
struct xmm {
  double low;
  double high;
};


void fpvm_test_instr(struct xmm *p);

void print_fpregs_decimal(struct xmm *fpregs) {
  for (int i = 0; i < 16; i++) {
    printf("%16.8lf ", fpregs[i].low);
    if (i == 7) {
      printf("\n");
    }
  }
  printf("\n");
}

void print_fpregs_hex(struct xmm *fpregs) {
  for (int i = 0; i < 16; i++) {
    uint64_t *bits = (uint64_t *)&fpregs[i].low;
    printf("0x%016lX ", *bits);
    if (i == 7) {
      printf("\n");
    }
  }
  printf("\n");
}

int main(int argc, char *argv[])
{
  
  INFO("hello world\n");

  if (fpvm_decoder_init()) {
    ERROR("cannot initialize decoder\n");
    abort();
  }
  
  fpvm_inst_t *fi = fpvm_decoder_decode_inst(my_instruction);

  if (!fi) {
    ERROR("cannot decode instruction\n");
    abort();
  }

  // acquire pointers to the GP and FP register state
  // from the mcontext.
  //
  // Note that we update the mcontext each time we
  // complete an instruction in the current sequence
  // so this always reflects the current
  fpvm_regs_t regs;
    
  ucontext_t uc;
  getcontext(&uc);
  regs.mcontext = &uc.uc_mcontext;
  
  // PAD: This stupidly just treats everything as SSE2
  // and must be fixed
  regs.fprs = MCTX_FPRS(&uc.uc_mcontext);
  regs.fpr_size = 16;
  
  // Doing fake bind here to capture operand sizes
  // If we do it this way, we will only bind the first time we see the instruction
  // and otherwise keep it in the decode cache
  if (fpvm_decoder_bind_operands(fi, &regs)) {
    ERROR("Cannot bind operands of instruction\n");
    abort();
  }

  if (fpvm_vm_compile(fi)) {
    ERROR("cannot compile instruction\n");
    abort();
  }

  INFO("successfully decoded and compiled instruction\n");
  
  INFO("Now displaying generated code\n");
  fpvm_builder_disas(stdout, (fpvm_builder_t*)fi->codegen);


  INFO("Now trying to execute generated code\n");

  INFO("Now testing with VM\n");
  

  fpvm_vm_t vm;

  struct xmm fpregs[16];

  for (int i = 0; i < 16; i++) {
    fpregs[i].low = (double)i;
    fpregs[i].high = (double)i + 0.5;
  }

  regs.fprs = fpregs;
  regs.fpr_size = 16;

  INFO("Register initial state\n");
  // print_fpregs_decimal(fpregs);
  fpvm_dump_xmms_double(stderr, fpregs);

  printf("\n");

  // INFO("Register initial state (in hex)\n");
  // print_fpregs_hex(fpregs);

  printf("\n\n");

  fpvm_vm_init(&vm, fi, &regs);

  fpvm_vm_run(&vm);

  INFO("Register final state\n");
  // print_fpregs_decimal(fpregs);
  fpvm_dump_xmms_double(stderr, fpregs);

  printf("\n");

  // INFO("Register final state (in hex)\n");
  // print_fpregs_hex(fpregs);

  printf("\n\n");

  INFO("Testing ground truth\n");
  for (int i = 0; i < 16; i++) {
    fpregs[i].low = (double)i;
    fpregs[i].high = (double)i + 0.5;
  }
  INFO("Register initial state\n");
  // print_fpregs_decimal(fpregs);
  fpvm_dump_xmms_double(stderr, fpregs);

  fpvm_test_instr(fpregs);

  printf("\n");
  
  INFO("Register final state\n");
  // print_fpregs_decimal(fpregs);
  fpvm_dump_xmms_double(stderr, fpregs);

  printf("\n");

  // INFO("Register final state (in hex)\n");
  // print_fpregs_hex(fpregs);

  return 0;
}
#endif
