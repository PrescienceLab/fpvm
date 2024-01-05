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
#include <sys/reg.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <time.h>
#include <ucontext.h>
#include <unistd.h>

#include <math.h>

#include <sys/time.h>

#include <fpvm/decoder.h>
#include <fpvm/emulator.h>
#include <fpvm/fpvm_common.h>
#include <fpvm/gc.h>
#include <fpvm/util.h>

#include <fpvm/perf.h>

#include <fpvm/fpvm_fenv.h>
#include <fpvm/fpvm_math.h>
#include <fpvm/number_system.h>

#ifdef CONFIG_KERNEL_MODULE
#include <sys/ioctl.h>
#include <kmod/fpvm_ioctl.h>

extern void * _user_fpvm_entry;
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

static struct sigaction oldsa_fpe, oldsa_trap, oldsa_int;

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

// This is to allow us to handle multiple threads
// and to follow forks later
typedef struct execution_context {
  enum { INIT, AWAIT_FPE, ABORT } state;
  int aborting_in_trap;
  int tid;
  uint64_t total_inst;
  uint64_t emulated_inst;

  fpvm_inst_t **decode_cache;  // chaining hash - array of pointers to instructions
  uint64_t decode_cache_size;
  uint64_t decode_cache_hits;
  uint64_t decode_cache_unique;

#ifdef CONFIG_PERF_STATS
  perf_stat_t gc_stat;
  perf_stat_t decode_cache_stat;
  perf_stat_t decode_stat;
  perf_stat_t bind_stat;
  perf_stat_t emulate_stat;
  perf_stat_t patch_stat;

#define START_PERF(c, x) perf_stat_start(&c->x##_stat)
#define END_PERF(c, x) perf_stat_end(&c->x##_stat)
#define PRINT_PERF(c, x) perf_stat_print(&c->x##_stat, stderr)
#define PRINT_PERFS(c)         \
  PRINT_PERF(c, gc);           \
  PRINT_PERF(c, decode_cache); \
  PRINT_PERF(c, decode);       \
  PRINT_PERF(c, bind);         \
  PRINT_PERF(c, emulate);      \
  PRINT_PERF(c, patch);
#else
#define START_PERF(c, x)
#define END_PERF(c, x)
#define PRINT_PERF(c, x)
#define PRINT_PERFS(c)
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

static uint32_t get_mxcsr() {
  uint32_t val = 0;
  __asm__ __volatile__("stmxcsr %0" : "=m"(val) : : "memory");
  return val;
}

static void set_mxcsr(uint32_t val) {
  __asm__ __volatile__("ldmxcsr %0" : : "m"(val) : "memory");
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

static execution_context_t *find_execution_context(int tid) {
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

static execution_context_t *alloc_execution_context(int tid) {
  int i;
  lock_contexts();
  for (i = 0; i < MAX_CONTEXTS; i++) {
    if (!context[i].tid) {
      context[i].tid = tid;
      unlock_contexts();
#ifdef CONFIG_PERF_STATS
      perf_stat_init(&context[i].gc_stat, "garbage collector");
      perf_stat_init(&context[i].decode_cache_stat, "decode cache");
      perf_stat_init(&context[i].decode_stat, "decoder");
      perf_stat_init(&context[i].bind_stat, "bind");
      perf_stat_init(&context[i].emulate_stat, "emulate");
      perf_stat_init(&context[i].patch_stat, "patched trap");
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

static __attribute__((constructor)) void fpvm_init(void);

#if DEBUG_OUTPUT

static void dump_rflags(char *pre, ucontext_t *uc) {
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
}

static void dump_mxcsr(char *pre, ucontext_t *uc) {
  char buf[256];

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
}

#endif

// trap should never be enabled...   this can probably go
static inline void set_trap_flag_context(ucontext_t *uc, int val) {
  if (val) {
    uc->uc_mcontext.gregs[REG_EFL] |= 0x100UL;
  } else {
    uc->uc_mcontext.gregs[REG_EFL] &= ~0x100UL;
  }
}

static inline void clear_fp_exceptions_context(ucontext_t *uc) {
  uc->uc_mcontext.fpregs->mxcsr &= ~MXCSR_FLAG_MASK;
}

static inline void set_mask_fp_exceptions_context(ucontext_t *uc, int mask) {
  if (mask) {
    uc->uc_mcontext.fpregs->mxcsr |= MXCSR_MASK_MASK;
  } else {
    uc->uc_mcontext.fpregs->mxcsr &= ~MXCSR_MASK_MASK;
  }
}

static void abort_operation(char *reason) {
  if (!inited) {
    DEBUG("Initializing before aborting\n");
    fpvm_init();
    DEBUG("Done with fpvm_preload_init()\n");
  }

  if (!aborted) {
    ORIG_IF_CAN(fedisableexcept, FE_ALL_EXCEPT);
    ORIG_IF_CAN(feclearexcept, FE_ALL_EXCEPT);
    ORIG_IF_CAN(sigaction, SIGFPE, &oldsa_fpe, 0);

    execution_context_t *mc = find_execution_context(gettid());

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

  DEBUG("Setting up thread %d\n", gettid());

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
    return -1;                                  \
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
  uint32_t mxcsr = uc->uc_mcontext.fpregs->mxcsr;
  uint32_t mxcsr_round = mxcsr & MXCSR_ROUND_DAZ_FTZ_MASK;
  DEBUG("mxcsr (0x%08x) round faz dtz at 0x%08x\n", mxcsr, mxcsr_round);
  // dump_mxcsr("get_mxcsr_round_daz_ftz: ", uc);
  return mxcsr_round;
}

static void set_mxcsr_round_daz_ftz(ucontext_t *uc, uint32_t mask) {
  if (control_mxcsr_round_daz_ftz) {
    uc->uc_mcontext.fpregs->mxcsr &= MXCSR_ROUND_DAZ_FTZ_MASK;
    uc->uc_mcontext.fpregs->mxcsr |= mask;
    DEBUG("mxcsr masked to 0x%08x after round daz ftz update (0x%08x)\n",
        uc->uc_mcontext.fpregs->mxcsr, mask);
    // dump_mxcsr("set_mxcsr_round_daz_ftz: ", uc);
  }
}

inline static fpvm_inst_t *decode_cache_lookup(execution_context_t *c, void *rip);
inline static void decode_cache_insert(execution_context_t *c, fpvm_inst_t *inst);

static void fp_restore_handler(void *priv) {
  ORIG_IF_CAN(fedisableexcept, FE_ALL_EXCEPT);

  execution_context_t *mc = find_execution_context(gettid());
  ucontext_t *uc = (ucontext_t *)priv;
  uint8_t *rip = (uint8_t *)uc->uc_mcontext.gregs[REG_RIP];
  DEBUG("Restore RIP=%p RSP=%p\n", rip, (void *)uc->uc_mcontext.gregs[REG_RSP]);

  fpvm_inst_t *fi = 0;
  int do_insert = 0;
  // char instbuf[256];

  fi = decode_cache_lookup(mc, rip);

  if (!fi) {
    DEBUG("Instruction is not in the decode cache\n");
    fi = fpvm_decoder_decode_inst(rip);
    do_insert = 1;
  }

  if (!fi) {
    ERROR("Cannot decode instruction\n");
    // BAD
    // return;
    goto out;
  }
#if DEBUG_OUTPUT
  ERROR("Detailed instruction dump:\n");
  fpvm_decoder_print_inst(fi, stderr);
#endif

  fpvm_regs_t regs;

  regs.mcontext = &uc->uc_mcontext;

  // This stupidly just treats everything as SSE2
  // and must be fixed
  regs.fprs = uc->uc_mcontext.fpregs->_xmm;
  regs.fpr_size = 16;

  // bind operands
  if (fpvm_decoder_bind_operands(fi, &regs)) {
    ERROR("Cannot bind operands of instruction\n");
    goto out;
  }

  DEBUG("About to emulate:\n");
#if DEBUG_OUTPUT
  fpvm_dump_xmms_double(stderr, regs.fprs);
  fpvm_dump_xmms_float(stderr, regs.fprs);
  fpvm_dump_float_control(stderr, uc);
  fpvm_dump_gprs(stderr, uc);
#endif

  // 0 or -1 will reexecute the program
  if (fpvm_fp_restore(fi, &regs) == 1) {
    // restore happen; skip the instruction; otherwise re-execute;
    // ERROR("fp restore Failed to emulate instruction\n");
    // return ;
    // skip instruction
    uc->uc_mcontext.gregs[REG_RIP] += fi->length;
  }

  DEBUG("Emulation done:\n");
#if DEBUG_OUTPUT
  fpvm_dump_xmms_double(stderr, regs.fprs);
  fpvm_dump_xmms_float(stderr, regs.fprs);
  fpvm_dump_float_control(stderr, uc);
  fpvm_dump_gprs(stderr, uc);
#endif

  if (do_insert) {
    // put into the cache for next time
    decode_cache_insert(mc, fi);
  }

out:

  ORIG_IF_CAN(feenableexcept, FE_ALL_EXCEPT);
  ORIG_IF_CAN(feclearexcept, FE_ALL_EXCEPT);
}

// SIGTRAP is used for three scenarios:
//    bootstrap  - to initially set the FP exceptions/masks/etc
//    singlestop - when cannot emulate an instruction and execute it instead
//    abort      - when we need to revert back
static void sigtrap_handler(int sig, siginfo_t *si, void *priv) {
  execution_context_t *mc = find_execution_context(gettid());
  ucontext_t *uc = (ucontext_t *)priv;
  DEBUG("TRAP signo 0x%x errno 0x%x code 0x%x rip %p\n", si->si_signo, si->si_errno, si->si_code,
      si->si_addr);

  if (!mc || mc->state == ABORT) {
    clear_fp_exceptions_context(uc);        // exceptions cleared
    set_mask_fp_exceptions_context(uc, 1);  // exceptions masked
    set_mxcsr_round_daz_ftz(uc, orig_mxcsr_round_daz_ftz_mask);
    set_trap_flag_context(uc, 0);  // traps disabled
    if (!mc) {
      // this may end badly
      abort_operation("Cannot find execution context during sigtrap_handler exec");
    } else {
      DEBUG("FP and TRAP mcontext restored on abort\n");
    }
    return;
  }

  // turn FP exceptions back on
  if (mc) {
    orig_mxcsr_round_daz_ftz_mask = get_mxcsr_round_daz_ftz(uc);
    clear_fp_exceptions_context(uc);        // exceptions cleared
    set_mask_fp_exceptions_context(uc, 0);  // exceptions unmasked
    set_mxcsr_round_daz_ftz(uc, our_mxcsr_round_daz_ftz_mask);
    // set_trap_flag_context(uc,0);         // traps disabled

    if (mc->state == AWAIT_FPE) {
      START_PERF(mc, patch);
      fp_restore_handler(priv);
      END_PERF(mc, patch);
    } else {
      ERROR("not await fpe %d \n", mc->state);
    }

    mc->state = AWAIT_FPE;
    DEBUG("MXCSR state initialized\n");
    return;
  } else {
    ERROR("Caught trap with no matching context.... WTF\n");
    return;
  }

  /*
  if (mc->state == AWAIT_TRAP) {
    mc->count++;
    clear_fp_exceptions_context(uc);      // exceptions cleared
    if (maxcount!=-1 && mc->count >= maxcount) {
      // disable further operation since we've recorded enough
      set_mask_fp_exceptions_context(uc,1); // exceptions masked
      set_mxcsr_round_daz_ftz(uc,orig_mxcsr_round_daz_ftz_mask);
    } else {
      set_mask_fp_exceptions_context(uc,0); // exceptions unmasked
      set_mxcsr_round_daz_ftz(uc,our_mxcsr_round_daz_ftz_mask);
    }
    set_trap_flag_context(uc,0);          // traps disabled
    mc->state = AWAIT_FPE;
    if (mc->sampler.delayed_processing) {
        DEBUG("Delayed sampler handling\n");
        update_sampler(mc,uc);
    }
  } else {
    clear_fp_exceptions_context(uc);     // exceptions cleared
    set_mask_fp_exceptions_context(uc,1);// exceptions masked
    set_mxcsr_round_daz_ftz(uc,orig_mxcsr_round_daz_ftz_mask);
    set_trap_flag_context(uc,0);         // traps disabled
    mc->aborting_in_trap = 1;
    abort_operation("Surprise state during sigtrap_handler exec");
  }

  */

  DEBUG("TRAP done\n");
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
#ifdef CONFIG_KERNEL_MODULE
siginfo_t fake_siginfo = {0};       // Doing this to mod less code rn
struct _libc_fpstate fpvm_fpregs;   // Save and restore fp state here
ucontext_t fake_ucontext;

void sigfpe_handler(void *priv)
{
  // ORIG_IF_CAN(fedisableexcept,FE_ALL_EXCEPT);
  uint32_t old;
  mxcsr_disable_save(&old);
  __asm__ __volatile__("fxsave (%0)" :: "r"(&fpvm_fpregs));
  
  // puts("[+] Hit sigfpe!");
  execution_context_t *mc = find_execution_context(gettid());

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
  // greg_t * gregs = (greg_t *) priv;       // Pointer to saved regs on stack

  fake_ucontext.uc_mcontext.fpregs = &fpvm_fpregs;

  for (int i = 0; i < 18; i++) {
    fake_ucontext.uc_mcontext.gregs[i] = *((greg_t*)priv + i);
  }

  ucontext_t *uc = (ucontext_t *)&fake_ucontext;
 
  uint8_t *rip = (uint8_t*) uc->uc_mcontext.gregs[REG_RIP];
  /* End mod */

  // fpvm_gc_run();

  START_PERF(mc,gc);
  fpvm_gc_run();
  END_PERF(mc,gc);
  
  DEBUG("FPE signo 0x%x errno 0x%x code 0x%x rip %p %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
        si->si_signo, si->si_errno, si->si_code, si->si_addr,
	rip[0], rip[1], rip[2], rip[3], rip[4], rip[5], rip[6], rip[7],
	rip[8], rip[9], rip[10], rip[11], rip[12], rip[13], rip[14], rip[15]);
  DEBUG("FPE RIP=%p RSP=%p\n",
        rip, (void*)  uc->uc_mcontext.gregs[REG_RSP]);

  if (!mc) {
    clear_fp_exceptions_context(uc);     // exceptions cleared
    set_mask_fp_exceptions_context(uc,1);// exceptions masked
    set_mxcsr_round_daz_ftz(uc,orig_mxcsr_round_daz_ftz_mask);
    set_trap_flag_context(uc,0);         // traps disabled
    abort_operation("Cannot find execution context during sigfpvm_handler exec");
    ASSERT(0);
    return;
  }

  mc->total_inst++;

  
#if DEBUG_OUTPUT
  char buf[80];
#define CASE(X) case X : strcpy(buf, #X); break; 
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
    sprintf(buf,"UNKNOWN(0x%x)\n",si->si_code);
    break;
  }
  DEBUG("FPE exceptions: %s\n", buf);
#endif

  fpvm_inst_t *fi=0;
  int do_insert = 0;
  char instbuf[256];

  START_PERF(mc,decode_cache);
  fi = decode_cache_lookup(mc,rip);
  END_PERF(mc,decode_cache);

  if (!fi) {
    DEBUG("Instruction is not in the decode cache\n");
    START_PERF(mc,decode);
    fi = fpvm_decoder_decode_inst(rip);
    END_PERF(mc,decode);
    do_insert = 1;
  }
  // usleep(10000);
  // fpvm_decoder_print_inst(fi, stderr);
  
  if (!fi) {
    ERROR("Cannot decode instruction\n");
    ASSERT(0);
    // BAD
    goto fail_do_trap;
  }

  fpvm_regs_t regs;

  regs.mcontext = &uc->uc_mcontext;

  // PAD: This stupidly just treats everything as SSE2
  // and must be fixed
  regs.fprs = uc->uc_mcontext.fpregs->_xmm;
  regs.fpr_size = 16;

  // bind operands
  START_PERF(mc,bind);
  if (fpvm_decoder_bind_operands(fi,&regs)) {
    END_PERF(mc,bind);
    ERROR("Cannot bind operands of instruction\n");
    ASSERT(0);
    goto fail_do_trap;
  }
  END_PERF(mc,bind);

#if DEBUG_OUTPUT
  DEBUG("Detailed instruction dump:\n");
  fpvm_decoder_print_inst(fi,stderr);
#endif

  DEBUG("About to emulate:\n");
#if DEBUG_OUTPUT
  fpvm_dump_xmms_double(stderr,regs.fprs);
  fpvm_dump_xmms_float(stderr,regs.fprs);
  fpvm_dump_float_control(stderr,uc);
  fpvm_dump_gprs(stderr,uc);
#endif

  START_PERF(mc,emulate);
  if (fpvm_emulator_emulate_inst(fi)) {
    END_PERF(mc,emulate);
    ERROR("Failed to emulate instruction\n");
    ASSERT(0);
    goto fail_do_trap;;
  }
  END_PERF(mc,emulate);

  DEBUG("Emulation done:\n");
#if DEBUG_OUTPUT
  fpvm_dump_xmms_double(stderr,regs.fprs);
  fpvm_dump_xmms_float(stderr,regs.fprs);
  fpvm_dump_float_control(stderr,uc);
  fpvm_dump_gprs(stderr,uc);
#endif
  
  // skip instruction
  /* Start mod */
  // printf("Old RIP: %llx\n", *((greg_t*)priv + 19));
  // *((greg_t*)priv + 19) += fi->length;
  // printf("New RIP: %llx\n", *((greg_t*)priv + 19));

  // printf("Old RIP: %llx\n", fake_ucontext.uc_mcontext.gregs[REG_RIP]);
  fake_ucontext.uc_mcontext.gregs[REG_RIP] += fi->length;
  // printf("New RIP: %llx\n", fake_ucontext.uc_mcontext.gregs[REG_RIP]);
  /* End mod */

  if (do_insert) {
    // put into the cache for next time
    decode_cache_insert(mc,fi);
  }
  
  //stay in state AWAIT_FPE

  mc->emulated_inst++;

  if (!(mc->total_inst % 1000000)) {
    INFO("%lu total instructions handled, %lu emulated successfully, %lu decode cache hits, %lu unique instructions\n",
	 mc->total_inst, mc->emulated_inst, mc->decode_cache_hits,mc->decode_cache_unique);
    PRINT_PERFS(mc);
  }
  
  DEBUG("FPE done\n");

  /* Start mod */
  for (int i = 0; i < 18; i++) {
    *((greg_t*)priv + i) = fake_ucontext.uc_mcontext.gregs[i];
  }
  __asm__ __volatile__("fxrstor (%0)" :: "r"(&fpvm_fpregs));
  // puts("[*] Leaving sigfpe_handler, returning to user program\n\n");
  // feenableexcept(FE_ALL_EXCEPT);
  // ORIG_IF_CAN(feenableexcept,FE_ALL_EXCEPT);
  mxcsr_restore(old);
  /* End mod */
  return;


  
fail_do_trap:

  fpvm_decoder_get_inst_str(fi,instbuf,256);
  
  ERROR("Unable to emulate instruction and starting single step - instr %s - rip %p instr bytes %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
        instbuf, rip,
        rip[0], rip[1], rip[2], rip[3], rip[4], rip[5], rip[6], rip[7],
        rip[8], rip[9], rip[10], rip[11], rip[12], rip[13], rip[14], rip[15]);

  if (fi) {
    fpvm_decoder_free_inst(fi);
  }

  if (!(mc->total_inst % 1000000)) {
    INFO("%lu total instructions handled, %lu emulated successfully\n",
	 mc->total_inst, mc->emulated_inst);
  }


  // switch to trap mode, so we can re-enable FP traps after this instruction is done
  clear_fp_exceptions_context(uc);      // exceptions cleared
  set_mask_fp_exceptions_context(uc,1); // exceptions masked
  set_mxcsr_round_daz_ftz(uc,our_mxcsr_round_daz_ftz_mask);
  set_trap_flag_context(uc,1);          // traps disabled


  
  // our next stop should be the instruction, and then, immediately afterwards, the sigtrap handler
  
  return;	
}

#else
static void sigfpe_handler(int sig, siginfo_t *si, void *priv) {
  execution_context_t *mc = find_execution_context(gettid());
  ucontext_t *uc = (ucontext_t *)priv;
  uint8_t *rip = (uint8_t *)uc->uc_mcontext.gregs[REG_RIP];

  // fpvm_gc_run();

  START_PERF(mc, gc);
  fpvm_gc_run();
  END_PERF(mc, gc);

  DEBUG(
      "FPE signo 0x%x errno 0x%x code 0x%x rip %p %02x %02x %02x %02x %02x "
      "%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
      si->si_signo, si->si_errno, si->si_code, si->si_addr, rip[0], rip[1], rip[2], rip[3], rip[4],
      rip[5], rip[6], rip[7], rip[8], rip[9], rip[10], rip[11], rip[12], rip[13], rip[14], rip[15]);
  DEBUG("FPE RIP=%p RSP=%p\n", rip, (void *)uc->uc_mcontext.gregs[REG_RSP]);

  if (!mc) {
    clear_fp_exceptions_context(uc);        // exceptions cleared
    set_mask_fp_exceptions_context(uc, 1);  // exceptions masked
    set_mxcsr_round_daz_ftz(uc, orig_mxcsr_round_daz_ftz_mask);
    set_trap_flag_context(uc, 0);  // traps disabled
    abort_operation("Cannot find execution context during sigfpvm_handler exec");
    ASSERT(0);
    return;
  }

  mc->total_inst++;

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

  fpvm_inst_t *fi = 0;
  int do_insert = 0;
  char instbuf[256];
  long stream_index = 0;



  while (1) {
    // Construct the fpvm register state.
    fpvm_regs_t regs;
    regs.mcontext = &uc->uc_mcontext;
    // PAD: This stupidly just treats everything as SSE2
    // and must be fixed
    regs.fprs = uc->uc_mcontext.fpregs->_xmm;
    regs.fpr_size = 16;

    long ind = stream_index++;
    START_PERF(mc, decode_cache);
    fi = decode_cache_lookup(mc, rip);
    END_PERF(mc, decode_cache);

    if (!fi) {
      if (ind != 0) break;
      DEBUG("Instruction is not in the decode cache\n");
      START_PERF(mc, decode);
      fi = fpvm_decoder_decode_inst(rip);
      END_PERF(mc, decode);
      do_insert = 1;
    }
    // fpvm_decoder_print_inst(fi, stderr);

    if (!fi) {
      if (ind != 0) break;

      ERROR("Cannot decode instruction\n");
      ASSERT(0);
      // BAD
      goto fail_do_trap;
    }

    // bind operands
    START_PERF(mc, bind);
    if (fpvm_decoder_bind_operands(fi, &regs)) {
      if (ind == 0) {
        END_PERF(mc, bind);
        ERROR("Cannot bind operands of instruction\n");
        ASSERT(0);
        goto fail_do_trap;
      } else {
        break;
      }
    }
    END_PERF(mc, bind);

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
    if (fpvm_emulator_emulate_inst(fi)) {
      if (ind == 0) {
        END_PERF(mc, emulate);
        ERROR("Failed to emulate instruction\n");
        ASSERT(0);
        goto fail_do_trap;
      } else {
        break;
      }
    }
    END_PERF(mc, emulate);

    rip += fi->length;
    break;
  }



  // DEBUG("Emulation done:\n");
  // #if DEBUG_OUTPUT
  //   fpvm_dump_xmms_double(stderr, regs.fprs);
  //   fpvm_dump_xmms_float(stderr, regs.fprs);
  //   fpvm_dump_float_control(stderr, uc);
  //   fpvm_dump_gprs(stderr, uc);
  // #endif

  // Skip those instructions we just emulated.
  uc->uc_mcontext.gregs[REG_RIP] = (greg_t)rip;

  if (do_insert) {
    // put into the cache for next time
    decode_cache_insert(mc, fi);
  }

  // stay in state AWAIT_FPE

  mc->emulated_inst++;

  if (!(mc->total_inst % 1000000)) {
    INFO(
        "%lu total instructions handled, %lu emulated successfully, %lu "
        "decode cache hits, %lu unique instructions\n",
        mc->total_inst, mc->emulated_inst, mc->decode_cache_hits, mc->decode_cache_unique);
    PRINT_PERFS(mc);
  }

  DEBUG("FPE done\n");

  return;

fail_do_trap:

  fpvm_decoder_get_inst_str(fi, instbuf, 256);

  ERROR(
      "Unable to emulate instruction and starting single step - instr %s - "
      "rip %p instr bytes %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x "
      "%02x %02x %02x %02x %02x %02x\n",
      instbuf, rip, rip[0], rip[1], rip[2], rip[3], rip[4], rip[5], rip[6], rip[7], rip[8], rip[9],
      rip[10], rip[11], rip[12], rip[13], rip[14], rip[15]);

  if (fi) {
    fpvm_decoder_free_inst(fi);
  }

  if (!(mc->total_inst % 1000000)) {
    INFO("%lu total instructions handled, %lu emulated successfully\n", mc->total_inst,
        mc->emulated_inst);
  }

  // switch to trap mode, so we can re-enable FP traps after this instruction is
  // done
  clear_fp_exceptions_context(uc);        // exceptions cleared
  set_mask_fp_exceptions_context(uc, 1);  // exceptions masked
  set_mxcsr_round_daz_ftz(uc, our_mxcsr_round_daz_ftz_mask);
  set_trap_flag_context(uc, 1);  // traps disabled

  // our next stop should be the instruction, and then, immediately afterwards,
  // the sigtrap handler

  return;
}
#endif

static __attribute__((destructor)) void fpvm_deinit(void);

static void sigint_handler(int sig, siginfo_t *si, void *priv) {
  DEBUG("Handling break\n");

  if (oldsa_int.sa_sigaction) {
    fpvm_deinit();  // dump everything out
    // invoke underlying handler
    oldsa_int.sa_sigaction(sig, si, priv);
  } else {
    // exit - our deinit will be called
    exit(-1);
  }
}

static int bringup_execution_context(int tid) {
  execution_context_t *c;

  if (!(c = alloc_execution_context(tid))) {
    ERROR("Cannot allocate execution context\n");
    return -1;
  }

  c->state = INIT;
  c->aborting_in_trap = 0;
  c->total_inst = 0;
  c->emulated_inst = 0;
  c->decode_cache = malloc(sizeof(fpvm_inst_t *) * decode_cache_size);
  if (!c->decode_cache) {
    ERROR("Cannot allocate code cache for context\n");
    c->decode_cache_size = 0;
  } else {
    c->decode_cache_size = decode_cache_size;
    memset(c->decode_cache, 0, sizeof(fpvm_inst_t *) * c->decode_cache_size);
  }

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

  ORIG_IF_CAN(feclearexcept, exceptmask);

  init_execution_contexts();

  if (bringup_execution_context(gettid())) {
    ERROR("Failed to start up execution context at startup\n");
    return -1;
  }

  struct sigaction sa;

#ifdef CONFIG_KERNEL_MODULE

  // Open
  int file_desc = open("/dev/fpvm_dev", O_RDWR);
  
  if (file_desc < 0) {
      puts("[x] Failed to open /dev/fpvm_dev");
      exit(-1);
  }

  if (ioctl(file_desc, FPVM_IOCTL_REG, &_user_fpvm_entry)) {
      puts("[x] FPVM_IOCTL_REG");
      exit(-1);
  }


#else


  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = sigfpe_handler;
  sa.sa_flags |= SA_SIGINFO;
  sigemptyset(&sa.sa_mask);
  sigaddset(&sa.sa_mask, SIGINT);
  sigaddset(&sa.sa_mask, SIGTRAP);
  ORIG_IF_CAN(sigaction, SIGFPE, &sa, &oldsa_fpe);

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

  ORIG_IF_CAN(feenableexcept, exceptmask);

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
static __attribute__((constructor)) void fpvm_init(void) {
  INFO("init\n");
  if (!inited) {
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
    return;
  } else {
    ERROR("already inited!\n");
    return;
  }
}

// Called on unload of preload library
static __attribute__((destructor)) void fpvm_deinit(void) {
  DEBUG("deinit\n");
  inited = 0;
  DEBUG("done\n");
}
