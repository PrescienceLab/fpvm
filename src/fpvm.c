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
#include <fpvm/altcalc.h>
#include <fpvm/fpvm_magic.h>
#include <fpvm/config.h>
#include <fpvm/pulse.h>
#include <fpvm/trapall.h>

#define KICK_SIGNAL SIGUSR2

int fpvm_setup_additional_wrappers() {
 return 0;
}


volatile static int inited = 0;
volatile static int aborted = 0;  // set if the target is doing its own FPE processing

volatile static int exceptmask = FE_ALL_EXCEPT;  // which C99 exceptions to handle, default all


static fpvm_arch_fpregs_t fpregs_template;
static fpvm_arch_gpregs_t gpregs_template;

static int control_round_config = 0;                  // control the rounding bits
static fpvm_arch_round_config_t orig_round_config;    // captured at start
static fpvm_arch_round_config_t our_round_config = 0; // as we want to run

volatile static int fpsrmask_base = 0x9f;  // which exceptions 1001 1111

#define FPSR_FLAG_MASK   (fpsrmask_base << 0)
#define FPCR_ENABLE_MASK (fpsrmask_base << 7)



// trap short ciruiting requested / configured
volatile static int trap_sc = 0;
// kernel short ciruiting requested / configured
volatile static int kernel_sc = 0;
volatile static int aggressive = 0;
volatile static int disable_pthreads = 0;

static int (*orig_main)(int, char **, char **) = 0;
static int (*orig_fork)() = 0;
static int (*orig_pthread_create)(
    pthread_t *tid, const pthread_attr_t *attr, void *(*start)(void *), void *arg) = 0;
static int (*orig_pthread_exit)(void *ret) __attribute__((noreturn)) = 0;
static sighandler_t (*orig_signal)(int sig, sighandler_t func) = 0;
static int (*orig_sigaction)(int sig, const struct sigaction *act, struct sigaction *oldact) = 0;

// PAD: why are these not static?
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

// PAD: why are these not static?
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

// PAD: why are these not static?
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

static uint64_t decode_cache_size = DEFAULT_DECODE_CACHE_SIZE;

static FILE *fpvm_log_file = NULL;
#define FPVM_LOG_FILE (fpvm_log_file ? fpvm_log_file : stderr)

// This is to allow us to handle multiple threads
// and to follow forks later
typedef struct execution_context {
  enum { INIT, AWAIT_FPE, AWAIT_TRAP, ABORT } state;
  int aborting_in_trap;
  int tid;

  uint64_t trap_state;      // for breakpoints should we ever use them

  arch_fp_csr_t foreign_return_fpcsr; 
  void         *foreign_return_addr;

  uint64_t fp_traps; // Number of actual SIGFPE which occur
  uint64_t useful_emulated_insts; // The number of "useful" emulated instructions
  uint64_t extraneous_emulated_insts;
  uint64_t emulated_insts; // Should just be the sum of useful and extraneous
  uint64_t single_step_traps; // The number of instructions which result in a single step trap
  uint64_t promotions;
  uint64_t demotions;
  uint64_t clobbers;           // overwriting one of our nans
  uint64_t correctness_traps;
  uint64_t correctness_foreign_calls;
  uint64_t correctness_demotions;

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
  perf_stat_t single_step_inst_stat;
  perf_stat_t set_ts_stat;
  perf_stat_t clear_ts_stat;
  perf_stat_t mark_in_signal_stat;

#define START_PERF(c, x) perf_stat_start(&c->x##_stat)
#define END_PERF(c, x) perf_stat_end(&c->x##_stat)
#define PRINT_PERF(c, x) { char _buf[256]; sprintf(_buf,"fpvm info(%8d): perf: ",(c)->tid); perf_stat_print(&(c)->x##_stat, FPVM_LOG_FILE, _buf); }
#define PRINT_PERFS(c)             \
  PRINT_PERF(c, gc);               \
  PRINT_PERF(c, decode_cache);     \
  PRINT_PERF(c, decode);           \
  PRINT_PERF(c, bind);             \
  PRINT_PERF(c, emulate);          \
  PRINT_PERF(c, correctness);      \
  PRINT_PERF(c, foreign_call);     \
  PRINT_PERF(c, altmath);          \
  PRINT_PERF(c, single_step_inst); \
  PRINT_PERF(c, set_ts);           \
  PRINT_PERF(c, clear_ts);         \
  PRINT_PERF(c, mark_in_signal);

#else
#define START_PERF(c, x)
#define END_PERF(c, x)
#define PRINT_PERF(c, x)
#define PRINT_PERFS(c)
#endif


#if CONFIG_TELEMETRY_PROMOTIONS
#define PRINT_TELEMETRY(c) \
  fprintf(FPVM_LOG_FILE, "fpvm info(%8d): telemetry: "\
	                 "%lu fp traps, "\
	                 "%lu promotions, "\
			 "%lu demotions, "\
			 "%lu clobbers, "\
			 "%lu correctness traps, "\
			 "%lu correctness foreign calls, "\
			 "%lu correctness demotions, "\
			 "%lu instructions emulated (~%lu per trap), "\
			 "%lu useful instructions emulated (~%lu per trap), "\
			 "%lu extraneous instructions emulated (~%lu per trap), "\
			 "%lu decode cache hits, "\
			 "%lu unique instructions, "\
			 "%lu single step traps\n",\
			 (c)->tid,\
			 (c)->fp_traps,\
			 (c)->promotions,\
			 (c)->demotions,\
			 (c)->clobbers,\
			 (c)->correctness_traps,\
			 (c)->correctness_foreign_calls,\
			 (c)->correctness_demotions,\
			 (c)->emulated_insts,\
			 DIVU((c)->emulated_insts,(c)->fp_traps),\
			 (c)->useful_emulated_insts, \
			 DIVU((c)->useful_emulated_insts,(c)->fp_traps), \
			 (c)->extraneous_emulated_insts, \
			 DIVU((c)->extraneous_emulated_insts,(c)->fp_traps), \
			 (c)->decode_cache_hits,\
			 (c)->decode_cache_unique,\
			 (c)->single_step_traps\
			)
#else
#define PRINT_TELEMETRY(c) \
  fprintf(FPVM_LOG_FILE, "fpvm info(%8d): telemetry: " \
	                 "%lu fp traps, " \
			 "-1 promotions, " \
			 "-1 demotions, " \
			 "-1 clobbers, " \
			 "%lu correctness traps, " \
			 "%lu correctness foreign calls, " \
			 "-1 correctness demotions, " \
			 "%lu instructions emulated (~%lu per trap), " \
			 "%lu useful instructions emulated (~%lu per trap), " \
			 "%lu extraneous instructions emulated (~%lu per trap), " \
			 "%lu decode cache hits, " \
			 "%lu unique instructions, " \
			 "%lu single step traps" \
	                 "\n", \
			 (c)->tid, \
			 (c)->fp_traps, \
			 (c)->correctness_traps, \
			 (c)->correctness_foreign_calls, \
			 (c)->emulated_insts, \
			 DIVU((c)->emulated_insts,(c)->fp_traps), \
			 (c)->useful_emulated_insts, \
			 DIVU((c)->useful_emulated_insts,(c)->fp_traps), \
			 (c)->extraneous_emulated_insts, \
			 DIVU((c)->extraneous_emulated_insts,(c)->fp_traps), \
			 (c)->decode_cache_hits, \
			 (c)->decode_cache_unique, \
			 (c)->single_step_traps\
                        )
#endif

} execution_context_t;

static int context_lock;
static execution_context_t context[CONFIG_MAX_CONTEXTS];

// faster lookup of execution context
__thread execution_context_t *__fpvm_current_execution_context=0;



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
  for (i = 0; i < CONFIG_MAX_CONTEXTS; i++) {
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


int fpvm_current_execution_context_is_in_init(void)
{
  return __fpvm_current_execution_context && __fpvm_current_execution_context->state==INIT;
}

static void dump_execution_contexts_info(void)
{
  int i;
  arch_fp_csr_t old;
  lock_contexts();
  arch_config_machine_fp_csr_for_local(&old);
  for (i = 0; i < CONFIG_MAX_CONTEXTS; i++) {
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
  arch_set_machine_fp_csr(&old);
  unlock_contexts();
}


static execution_context_t *alloc_execution_context(int tid) {
  int i;
  lock_contexts();
  for (i = 0; i < CONFIG_MAX_CONTEXTS; i++) {
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
      perf_stat_init(&context[i].single_step_inst_stat, "single_step_inst");
      perf_stat_init(&context[i].set_ts_stat, "set_ts");
      perf_stat_init(&context[i].clear_ts_stat, "clear_ts");
      perf_stat_init(&context[i].mark_in_signal_stat, "mark_in_signal");
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
  for (i = 0; i < CONFIG_MAX_CONTEXTS; i++) {
    if (context[i].tid == tid) {
      DEINIT_TRACER(&context[i]);
      context[i].tid = 0;
      unlock_contexts();
    }
  }
  unlock_contexts();
}


#if CONFIG_HAVE_MAIN
static void fpvm_init(void);
#else
static __attribute__((constructor )) void fpvm_init(void);
#endif



static void kick_self(void) 
{
    if (trap_sc) {
#if CONFIG_TRAP_SHORT_CIRCUITING
	arch_trap_short_circuiting_kick_self();
#endif
    } else if (kernel_sc) {
#if CONFIG_KERNEL_SHORT_CIRCUITING
	arch_kernel_short_circuiting_kick_self();
#endif
    } else {
	kill(gettid(), KICK_SIGNAL);
    }
}



void abort_operation(char *reason) {
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
      kick_self();
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
      // now kick ourselves to set relevant bits; we are currently in state INIT
      // this will also do the architectural init
      kick_self();
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
    kick_self();
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

inline static void set_our_round_config(ucontext_t *uc)
{
    if (control_round_config) {
	arch_set_round_config(uc,our_round_config);
    }
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

  regs.fprs = MCTX_FPRS(&uc->uc_mcontext);
  regs.fpr_size = FPR_SIZE;

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
    arch_clear_fp_exceptions(uc);
    arch_mask_fp_traps(uc);
    TRAPALL_OFF();
    arch_set_round_config(uc,orig_round_config);
    if (!mc) {
      // this may end badly
      abort_operation("Cannot find execution context during correctness trap handler exec");
    } else {
      arch_reset_trap(uc,&mc->trap_state);
      DEBUG("FP and TRAP mcontext restored on abort\n");
    }
    return -1;
  }

  // if we got here, we have an mc, and are in INIT, AWAIT_TRAP, or AWAIT_FPE

  int rc = 0;

  switch (mc->state) {
  case INIT:
    DEBUG("initialization trap received\n");
    arch_zero_fpregs(uc);
    arch_thread_init(uc);
#if CONFIG_FPTRAPALL
    // Register this process with the kernel module,
    // and tell it we are inside a signal handler
    fptrapall_register(); // This marks us as in a signal
#endif
    // we have completed startup of the thread
    break;
  case AWAIT_TRAP:
    DEBUG("single stepping trap received\n");
    // we are completing this single step operation
#if CONFIG_FPTRAPALL
    // We need to tell the kernel module that we are in a signal
    // (It will only see #NM exceptions)
    if(inited) {
        fptrapall_mark_in_signal();
    }
#endif
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
  orig_round_config = arch_get_round_config(uc);


  arch_clear_fp_exceptions(uc);            // exceptions cleared
  arch_unmask_fp_traps(uc);                // exceptions unmasked

  set_our_round_config(uc);
  arch_reset_trap(uc,&mc->trap_state);    // traps disabled

  if(mc->state == AWAIT_TRAP) {
      // This doesn't account for the sigreturn
      END_PERF(mc, single_step_inst);
  }

  TRAPALL_ON();
  mc->state = AWAIT_FPE;

  //DEBUG("correctness handling done for thread %lu context %p state %d rc %d\n",gettid(),mc,mc->state,rc);

  return rc;

}

void brk_trap_handler(ucontext_t *uc)
{
  if (correctness_trap_handler(uc)) {
    abort_operation("correctness trap handler failed\n");
    ASSERT(0);
  }
}

// ENTRY point for SIGTRAP
static void sigtrap_handler(int sig, siginfo_t *si, void *priv)
{
  ucontext_t *uc = (ucontext_t *)priv;

  DEBUG("SIGTRAP signo 0x%x errno 0x%x code 0x%x rip %p\n", si->si_signo, si->si_errno, si->si_code,
      si->si_addr);

  brk_trap_handler(uc);

  DEBUG("SIGTRAP done (mc->state=%d)\n",find_my_execution_context()->state);
}

#if CONFIG_MAGIC_CORRECTNESS_TRAP
// Entry via magic (e9patch call)
static void *magic_page=0;


// This is to handle e9patch's lea instruction
#define MAGIC_TRAP_INSTRUCTION_SIZE 8

void NO_TOUCH_FLOAT fpvm_magic_trap_entry(void *priv, void *fpdata, size_t fpsize)
{
  // Build up a sufficiently detailed ucontext_t and
  // call the shared handler.  Copy in/out the FP and GP
  // state
  ucontext_t fake_ucontext;

  fpvm_arch_fpregs_t fpregs;
  fpregs.data = fpdata;
  fpregs.regsize_bytes = fpsize;

  // we will not modify this
  arch_fp_csr_t fpcsr;
  arch_get_machine_fp_csr(&fpcsr);
  
  // capture gpregs we were passed in our arch independent form
  fpvm_arch_gpregs_t gpregs;
  gpregs.data = 0;
  arch_get_gpregs(0,&gpregs);
  gpregs.data = priv;

  // now build out our ucontext using that info
  arch_set_fpregs(&fake_ucontext,&fpregs);
  arch_set_fp_csr(&fake_ucontext,&fpcsr);
  arch_set_gpregs(&fake_ucontext,&gpregs);

  arch_set_ip(&fake_ucontext,arch_get_ip(&fake_ucontext) + MAGIC_TRAP_INSTRUCTION_SIZE);

  if (correctness_trap_handler(&fake_ucontext)) {
    abort_operation("correctness trap handler failed\n");
    ASSERT(0);
  }

  fpvm_arch_gpregs_t gpregsout;
  fpvm_arch_fpregs_t fpregsout;
  
  // now copy the gpregs back out
  arch_get_gpregs(&fake_ucontext,&gpregsout);
  fpvm_safe_memcpy(priv,gpregsout.data,gpregsout.regalign_bytes*gpregs.numregs);
  
  // and copy the FP regs back out
  arch_get_fpregs(&fake_ucontext,&fpregsout);

  // Copy back onto the stack
  // (The assembly routine will actually restore
  //  the registers)
  memcpy(fpdata, fpregsout.data, fpsize);
  
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



void NO_TOUCH_FLOAT __fpvm_foreign_entry(void **ret, void *tramp, void *func, void *fpdata, unsigned long fpdata_byte_len)
{
    int demotions=0;

    execution_context_t *mc = find_my_execution_context();

    TRAPALL_OFF();

    SAFE_DEBUG("foreign entry\n");

    if (!inited) {
	hard_fail_show_foreign_func("impossible to handle pre-boot foreign call from unknown context - function ", func);
	return ;
    }
    
    START_PERF(mc, foreign_call);

    arch_fp_csr_t oldfpcsr;
    arch_config_machine_fp_csr_for_local(&oldfpcsr);
    
    // capture fp register state in our arch independent form
    //SAFE_DEBUG_QUAD("fpregs_template.regalign_bytes", fpregs_template.regalign_bytes);
    //SAFE_DEBUG_QUAD("fpregs_template.numregs", fpregs_template.numregs);

    /* Done in assembly -KJH
    uint8_t fpdata[fpregs_template.regalign_bytes*fpregs_template.numregs];
    fpvm_arch_fpregs_t fpregs;
    fpregs.data = fpdata;
    arch_get_fpregs_machine(&fpregs);
    */

  
    fpvm_regs_t regs;

    if (mc->foreign_return_addr!=&fpvm_panic) {
	hard_fail_show_foreign_func("recursive foreign entry detected - function ",func);
	END_PERF(mc, foreign_call);
	return;
    }

    //SAFE_DEBUG_QUAD("handling correctness for foreign call - trampoline",tramp);
    //SAFE_DEBUG_QUAD("handling correctness for foreign call - function",func);

    mc->correctness_foreign_calls++;


    // note that the following assumes that all fprs are caller-save,
    // as they are on x64.  Because of this assumption, we can demote
    // them all in place and then not restore any of them.
    //
    // If some fpregs are callee-save, this will generate a world of hurt
    // and we would want to carefully stash the callee-save registers
    // here and restore them from the stash in __fpvm_foreign_exit
    
    regs.mcontext = 0;                     // nothing should need this state

    regs.fprs = fpdata;
    regs.fpr_size = fpdata_byte_len;

    /* Done in assembly -KJH
    regs.fprs = fpregs.data;
    regs.fpr_size = fpregs.regsize_bytes;  // note, likely bogus
    */

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


    // stash the fpcsr we will enable on return
    mc->foreign_return_fpcsr = oldfpcsr;
    // stash the return address of the caller of the wrapper
    // we will ultimately want to return there
    mc->foreign_return_addr = *ret;
    // modify the current return address to return back to the
    // wrapper
    *ret = tramp;

    /* Done in assembly -KJH
    arch_set_fpregs_machine(&fpregs);
    */
    
    SAFE_DEBUG("foreign call begins\n");
    
    END_PERF(mc, foreign_call);
    
}

void NO_TOUCH_FLOAT  __fpvm_foreign_exit(void **ret)
{
  execution_context_t *mc = find_my_execution_context();

  START_PERF(mc, foreign_call);

  SAFE_DEBUG("foreign call ends\n");

  arch_set_machine_fp_csr(&mc->foreign_return_fpcsr);

  // now modify the return address to go back to
  // the original caller
  *ret = mc->foreign_return_addr;

  mc->foreign_return_addr=&fpvm_panic;

  SAFE_DEBUG("foreign exit\n");

  END_PERF(mc, foreign_call);

  TRAPALL_ON();
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

#if !CONFIG_DISABLE_GC
  START_PERF(mc, gc);
  fpvm_gc_run();
  END_PERF(mc, gc);
#endif


  if (!mc || mc->state != AWAIT_FPE) {
    arch_clear_fp_exceptions(uc);
    arch_mask_fp_traps(uc);           
    TRAPALL_OFF();
    arch_set_round_config(uc,orig_round_config);
    if (mc) {
      arch_reset_trap(uc,&mc->trap_state);
      abort_operation("Caught FP trap while not in AWAIT_FPE\n");
    } else {
      arch_reset_trap(uc,0);
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

    int inst_was_useful = 0;

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
#if CONFIG_FPTRAPALL
	// -KJH this used to be an "error" but with single stepping we can survive
	DEBUG("Cannot decode instruction %d (rip %p) of sequence: ",instindex,rip);
#if DEBUG_OUTPUT
	fpvm_decoder_decode_and_print_any_inst(rip,stderr," ");
#endif
#else
	ERROR("Cannot decode instruction %d (rip %p) of sequence:",instindex,rip);
	fpvm_decoder_decode_and_print_any_inst(rip,stderr," ");
	// ASSERT(0);
#endif
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
    regs.fpr_size = FPR_SIZE;

#if CONFIG_FPTRAPALL
#if DEBUG_OUTPUT
    fpvm_decoder_decode_and_print_any_inst(fi->addr,stderr,"about to bind: ");
#endif
#endif
    
    // bind operands
    START_PERF(mc, bind);
    if (fpvm_decoder_bind_operands(fi, &regs)) {
      if (instindex == 0) ERROR("Could not bind operands. instindex=%d\n", instindex);
      END_PERF(mc, bind);
      if (instindex==0) {
	ERROR("Cannot bind operands of first (rip %p) of sequence: ",rip);
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

    if (fpvm_emulator_emulate_inst(fi, &inst_promotions, &inst_demotions, &inst_clobbers, altmath_stat, &inst_was_useful)) {
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

    if(inst_was_useful) {
	mc->useful_emulated_insts++;
    } else {
	mc->extraneous_emulated_insts++;
    }
    mc->emulated_insts++;


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

  mc->fp_traps++;

  DEBUG("FPE succesfully done (emulated sequence of %d instructions)\n",instindex);

  arch_clear_fp_exceptions(uc); 

  return;

  // we should only get here if the first instruction
  // of a sequence could not be decoded, bound, or emulated
fail_do_trap:

  mc->single_step_traps++;

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

  TRAPALL_OFF();

  START_PERF(mc, single_step_inst);

  arch_clear_fp_exceptions(uc);
  arch_mask_fp_traps(uc);
  set_our_round_config(uc);
  arch_set_trap(uc,&mc->trap_state);

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

#if !CONFIG_DISABLE_GC
  // Let the garbage collector run
  fpvm_gc_run();
#endif
  
  // sanity check state and abort if needed
  if (!mc || mc->state != AWAIT_FPE) {
    arch_clear_fp_exceptions(uc);
    arch_mask_fp_traps(uc);
    TRAPALL_OFF();
    arch_set_round_config(uc, orig_round_config);
    if (mc) {
      arch_reset_trap(uc,&mc->trap_state);
      abort_operation("Caught FP trap while not in AWAIT_TRAP\n");
    } else {
       arch_reset_trap(uc,0);
       abort_operation("Cannot find execution context during sigfpvm_handler exec");
    }
    ASSERT(0);
    return;
  }

#if 0 && DEBUG_OUTPUT
#define DUMP_CUR_INSTR() fpvm_decoder_print_inst(fi, stderr);
#else
#define DUMP_CUR_INSTR()
#endif

  fpvm_inst_t *fi = 0;
  int do_insert = 0;
  fpvm_regs_t regs;

  regs.mcontext = &uc->uc_mcontext;

  // we get the registers early since
  // we will need to do a fake bind the first
  // time we see an instruction
  regs.fprs = MCTX_FPRS(&uc->uc_mcontext);
  regs.fpr_size = FPR_SIZE;

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

  mc->emulated_insts++;
  mc->useful_emulated_insts++;

  DEBUG("FPE succesfully done (emulated one instruction)\n");

  mc->fp_traps++;

  arch_clear_fp_exceptions(uc);        // exceptions cleared

  return;

  // we should only get here if the instruction
  // could not be handled
fail_do_trap:

  mc->single_step_traps++;

  START_PERF(mc, single_step_inst);

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
  arch_clear_fp_exceptions(uc);
  arch_mask_fp_traps(uc);
  TRAPALL_OFF();
  set_our_round_config(uc);
  arch_set_trap(uc,&mc->trap_state);



  // our next stop should be the instruction, and then, immediately afterwards,
  // the sigtrap handler

  return;
}


void fp_trap_handler(ucontext_t *uc)
{
#if CONFIG_USE_NVM
  return fp_trap_handler_nvm(uc);
#else
  return fp_trap_handler_emu(uc);
#endif
}



//
// Entry point for FP Trap when the SIGFPE (normal kernel delivery)
// mechanism is used
//
static void sigfpe_handler(int sig, siginfo_t *si, void *priv)
{
  arch_fp_csr_t oldfpcsr;
  arch_config_machine_fp_csr_for_local(&oldfpcsr);
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

  arch_set_machine_fp_csr(&oldfpcsr);

  execution_context_t *mc = find_my_execution_context();
  if (mc->state==AWAIT_TRAP) { 
    TRAPALL_OFF();
  }
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
    // PAD: this assumes x64...
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
  memset(&c->foreign_return_fpcsr,0,sizeof(c->foreign_return_fpcsr));
  c->foreign_return_addr=&fpvm_panic;
  c->aborting_in_trap = 0;
  c->fp_traps = 0;
  c->single_step_traps = 0;
  c->demotions = 0;
  c->promotions = 0;
  c->clobbers = 0;
  c->correctness_traps = 0;
  c->correctness_foreign_calls = 0;
  c->correctness_demotions = 0;
  c->emulated_insts = 0;
  c->useful_emulated_insts = 0;
  c->extraneous_emulated_insts = 0;
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

// PAD: Review lifetime management for arch process/thread init/deinit

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

static void init_arch_trap_mask(void)
{
    arch_clear_trap_mask();
#define SET_IF_NEED(E) if (!(exceptmask & E)) { arch_set_trap_mask(E); }
    SET_IF_NEED(FE_INVALID);
    SET_IF_NEED(FE_DIVBYZERO);
    SET_IF_NEED(FE_OVERFLOW);
    SET_IF_NEED(FE_UNDERFLOW);
    SET_IF_NEED(FE_INEXACT);
#ifdef FE_DENORM
    if (arch_have_special_fp_csr_exception(FE_DENORM)) { SET_IF_NEED(FE_DENORM);}
#endif
}

static int bringup() {

  if (arch_process_init()) {
    ERROR("Cannot initialize architecture support\n");
    return -1;
  }

  init_arch_trap_mask();

  // stash metadata about fp and gp regs on this machine
  memset(&fpregs_template,0,sizeof(fpregs_template));
  arch_get_fpregs_machine(&fpregs_template);
  arch_get_gpregs(0,&gpregs_template);

  if (fpvm_gc_init(fpvm_number_init, fpvm_number_deinit)) {
    ERROR("Cannot initialize garbage collector\n");
    return -1;
  }

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

  // try to set up our most powerful mechanisms first
#if CONFIG_TRAP_SHORT_CIRCUITING
  if (trap_sc) {
      if (arch_trap_short_circuiting_init()) {
	  DEBUG("failed to set up trap short-circuiting, trying next method\n");
	  trap_sc = 0;
      } else {
	  DEBUG("set up trap short-ciruiting successfully\n");
	  goto setup_signals;
      }
  }
#endif
#if CONFIG_KERNEL_SHORT_CIRCUITING
  if (kernel_sc) {
      if (arch_kernel_short_circuiting_init()) {
	  DEBUG("failed to set up kernel short-circuiting, trying next method\n");
	  kernel_sc = 0;
      } else {
	  DEBUG("set up kernel short-ciruiting successfully\n");
	  goto setup_signals;
      }
  }
#endif

  struct sigaction sa;

#if CONFIG_TRAP_SHORT_CIRCUITING || CONFIG_KERNEL_SHORT_CIRCUITING
 setup_signals:
#endif

  DEBUG("Setting up SIGFPE handler (default mechanism)\n");
  memset(&sa,0,sizeof(sa));
  sa.sa_sigaction = sigfpe_handler;
  sa.sa_flags |= SA_SIGINFO;
  sigemptyset(&sa.sa_mask);
  sigaddset(&sa.sa_mask, SIGINT);
  sigaddset(&sa.sa_mask, SIGTRAP);
  ORIG_IF_CAN(sigaction,SIGFPE,&sa,&oldsa_fpe);

  DEBUG("Setting up SIGTRAP handler (default mechanism)\n");
  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = sigtrap_handler;
  sa.sa_flags |= SA_SIGINFO;
  sigemptyset(&sa.sa_mask);
  sigaddset(&sa.sa_mask, SIGINT);
  sigaddset(&sa.sa_mask, SIGTRAP);
  sigaddset(&sa.sa_mask, SIGFPE);
  ORIG_IF_CAN(sigaction, SIGTRAP, &sa, &oldsa_trap);

  if(KICK_SIGNAL != SIGTRAP) {
      DEBUG("Setting up KICK_SIGNAL handler (default mechanism)\n");
      memset(&sa, 0, sizeof(sa));
      sa.sa_sigaction = sigtrap_handler;
      sa.sa_flags |= SA_SIGINFO;
      sigemptyset(&sa.sa_mask);
      sigaddset(&sa.sa_mask, SIGINT);
      sigaddset(&sa.sa_mask, KICK_SIGNAL);
      sigaddset(&sa.sa_mask, SIGFPE);
      ORIG_IF_CAN(sigaction, KICK_SIGNAL, &sa, &oldsa_trap);
  }

  DEBUG("Setting up SIGINT handler\n");
  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = sigint_handler;
  sa.sa_flags |= SA_SIGINFO;
  sigemptyset(&sa.sa_mask);
  sigaddset(&sa.sa_mask, SIGTRAP);
  ORIG_IF_CAN(sigaction, SIGINT, &sa, &oldsa_int);

  // DEBUG("Setting up SIGSEGV handler (for debugging purposes only)\n");
  // memset(&sa, 0, sizeof(sa));
  // sa.sa_sigaction = sigsegv_handler;
  // sa.sa_flags |= SA_SIGINFO;
  // sigemptyset(&sa.sa_mask);
  // sigaddset(&sa.sa_mask, SIGSEGV);
  // ORIG_IF_CAN(sigaction, SIGSEGV, &sa, &oldsa_segv);

  ORIG_IF_CAN(feenableexcept, exceptmask);

#if CONFIG_MAGIC_CORRECTNESS_TRAP
  // see if the binary has magic trap support
  DEBUG("attempting to set up magic correctness traps\n");
  fpvm_magic_trap_entry_t *f;

  f = dlsym(RTLD_NEXT, FPVM_MAGIC_TRAP_ENTRY_NAME_STR);

  if (f) {
    *f = (fpvm_magic_trap_entry_t)&fpvm_magic_trap_entry;
    DEBUG("airdropped magic trap location (%p) to target location (%p)\n",*f,f);
  } else {
    DEBUG("no airdrop of magic trap is possible, can't find %s\n",FPVM_MAGIC_TRAP_ENTRY_NAME_STR);
    DEBUG("trying to set up magic page instead\n");
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
      ERROR("magic traps in configuration but cannot be set up\n");
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

#if CONFIG_RUN_ALT_CALC
  TRAPALL_OFF();
  if (fpvm_number_alt_calc()) {
    INFO("early termination due to alt_calc\n");
    return -1;
  }
  TRAPALL_ON();
#endif

  // now kick ourselves to set the sse bits; we are currently in state INIT
  kick_self();

  inited = 1;
  DEBUG("Done with setup\n");

  return 0;
}

#if CONFIG_DEFER_BRINGUP_UNTIL_MAIN

// main() interception code influenced by 
// https://gist.github.com/apsun/1e144bf7639b22ff0097171fa0f8c6b1

static int main_shim(int argc, char **argv, char **envp)
{
  DEBUG("bringing up FPVM just before main\n");
  if (bringup()) {
    ERROR("cannot bring up framework\n");
  }
  return orig_main(argc, argv, envp);
}

// Wrapper for __libc_start_main() that replaces the real main
int __libc_start_main(int (*main)(int, char **, char **),
		      int argc,
		      char **argv,
		      int (*init)(int, char **, char **),
		      void (*fini)(void),
		      void (*rtld_fini)(void),
		      void *stack_end)
{
  orig_main = main;

  typeof(&__libc_start_main) orig_libc_start_main = dlsym(RTLD_NEXT, "__libc_start_main");
  
  return orig_libc_start_main(main_shim, argc, argv, init, fini, rtld_fini, stack_end);
}

#endif

// This should probably be specific to FPVM, but
// when we invoke
static void config_exceptions(char *buf) {
  exceptmask = 0;

  if (strcasestr(buf, "inv")) {
    DEBUG("tracking INVALID\n");
    exceptmask |= FE_INVALID;
  }
  if (strcasestr(buf, "den")) {
#ifdef FE_DENORM
    DEBUG("tracking DENORM\n");
    exceptmask |= FE_DENORM;
#else
    ERROR("cannot track DENORM on this architecture\n");
#endif
  }
  if (strcasestr(buf, "div")) {
    DEBUG("tracking DIVIDE_BY_ZERO\n");
    exceptmask |= FE_DIVBYZERO;
  }
  if (strcasestr(buf, "over")) {
    DEBUG("tracking OVERFLOW\n");
    exceptmask |= FE_OVERFLOW;
  }
  if (strcasestr(buf, "under")) {
    DEBUG("tracking UNDERFLOW\n");
    exceptmask |= FE_UNDERFLOW;
  }
  if (strcasestr(buf, "prec")) {
    DEBUG("tracking PRECISION\n");
    exceptmask |= FE_INEXACT;
  }
}

static void config_round_daz_ftz(char *buf)
{
    our_round_config = 0;

    if (strcasestr(buf, "pos")) {
	arch_set_round_mode(&our_round_config,FPVM_ARCH_ROUND_POSITIVE);
    } else if (strcasestr(buf, "neg")) {
	arch_set_round_mode(&our_round_config,FPVM_ARCH_ROUND_NEGATIVE);
    } else if (strcasestr(buf, "zer")) {
	arch_set_round_mode(&our_round_config,FPVM_ARCH_ROUND_ZERO);
    } else if (strcasestr(buf, "nea")) {
	arch_set_round_mode(&our_round_config,FPVM_ARCH_ROUND_NEAREST);
    } else {
	ERROR("Unknown rounding mode - avoiding rounding control\n");
	control_round_config = 0;
	return;
    }

    if (strcasestr(buf, "daz")) {
	if (strcasestr(buf,"ftz")) {
	    arch_set_dazftz_mode(&our_round_config,FPVM_ARCH_ROUND_DAZ_FTZ);
	} else {
	    arch_set_dazftz_mode(&our_round_config,FPVM_ARCH_ROUND_DAZ_NO_FTZ);
	}
    } else {
	if (strcasestr(buf,"ftz")) {
	  arch_set_dazftz_mode(&our_round_config,FPVM_ARCH_ROUND_NO_DAZ_FTZ);
	} else {
	    arch_set_dazftz_mode(&our_round_config,FPVM_ARCH_ROUND_NO_DAZ_NO_FTZ);
	}
    }

    control_round_config=1;

    DEBUG("Configuring rounding control to 0x%08x\n", our_round_config);
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
    fpvm_number_system_init();
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
    trap_sc = 0;
    if (getenv("FPVM_TRAP_SC") && tolower(getenv("FPVM_TRAP_SC")[0])=='y') {
	DEBUG("Attempting to use trap short-circuiting if hardware supports it\n");
	trap_sc = 1;
    }
    kernel_sc = 0;
    if (getenv("FPVM_KERNEL_SC") && tolower(getenv("FPVM_KERNEL_SC")[0])=='y') {
      DEBUG("Attempting to use kernel short-circuiting if kernel supports it\n");
      kernel_sc = 1;
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
#if !CONFIG_DEFER_BRINGUP_UNTIL_MAIN
    if (bringup()) {
      ERROR("cannot bring up framework\n");
      return;
    }
#else
    DEBUG("deferring FPVM bringup until just before main()\n");
#endif
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

  execution_context_t *mc = find_my_execution_context();

  // it is correct that we will not reenable it in this function
  TRAPALL_OFF();

  pulse_stop();
  DEBUG("deinit\n");
  arch_fp_csr_t old;

  arch_config_machine_fp_csr_for_local(&old);
  dump_execution_contexts_info();

  // If a different log file was chosen, close it.
  if (fpvm_log_file) fclose(fpvm_log_file);
#if CONFIG_KERNEL_SHORT_CIRCUITING
  if (kernel_sc) {
      arch_kernel_short_circuiting_deinit();
  }
#endif
#if CONFIG_TRAP_SHORT_CIRCUITING
  if (trap_sc) {
      arch_trap_short_circuiting_deinit();
  }
#endif
  arch_process_deinit();
  inited = 0;
  arch_set_machine_fp_csr(&old);
  DEBUG("done\n");
}




#if CONFIG_HAVE_MAIN

// x86 only at the moment

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

  fpvm_number_init(0);

#if CONFIG_RUN_ALT_CALC
  TRAPALL_OFF();
  if (fpvm_number_alt_calc()) {
    INFO("early termination due to alt_calc\n");
    return -1;
  }
  TRAPALL_ON();
#endif
  
  
  if (fpvm_decoder_init()) {
    ERROR("cannot initialize decoder\n");
    abort();
  }

  fpvm_inst_t *fi = fpvm_decoder_decode_inst(my_instruction);

  if (!fi) {
    ERROR("cannot decode instruction\n");
    abort();
  }

  // TESTING - Check for fi contents
  // op type should be 0 for fadd
  DEBUG("op_type: %d\n", fi->common->op_type);
  DEBUG("is_simple_mov: %d\n", fi->is_simple_mov);
  DEBUG("is_gpr_mov: %d\n", fi->is_gpr_mov);

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

  regs.fprs = MCTX_FPRS(&uc.uc_mcontext);
  regs.fpr_size = FPR_SIZE;

  // Doing fake bind here to capture operand sizes
  // If we do it this way, we will only bind the first time we see the instruction
  // and otherwise keep it in the decode cache
  if (fpvm_decoder_bind_operands(fi, &regs)) {
    ERROR("Cannot bind operands of instruction\n");
    abort();
  }


  if (fpvm_emulator_emulate_inst(fi, 0,0,0,0)) {
    ERROR("cannot emulate instruction\n");
    abort();
  }
  
  // // if (fpvm_vm_compile(fi)) {
  // //   ERROR("cannot compile instruction\n");
  // //   abort();
  // // }

  // INFO("successfully decoded and compiled instruction\n");

  // INFO("Now displaying generated code\n");
  // fpvm_builder_disas(stdout, (fpvm_builder_t*)fi->codegen);


  // INFO("Now trying to execute generated code\n");

  // INFO("Now testing with VM\n");


  // fpvm_vm_t vm;

  // struct xmm fpregs[16];

  // for (int i = 0; i < 16; i++) {
  //   fpregs[i].low = (double)i;
  //   fpregs[i].high = (double)i + 0.5;
  // }

  // regs.fprs = fpregs;
  // regs.fpr_size = FPR_SIZE;

  // INFO("Register initial state\n");
  // // print_fpregs_decimal(fpregs);
  // fpvm_dump_xmms_double(stderr, fpregs);

  // printf("\n");

  // // INFO("Register initial state (in hex)\n");
  // // print_fpregs_hex(fpregs);

  // printf("\n\n");

  // fpvm_vm_init(&vm, fi, &regs);

  // fpvm_vm_run(&vm);

  // INFO("Register final state\n");
  // // print_fpregs_decimal(fpregs);
  // fpvm_dump_xmms_double(stderr, fpregs);

  // printf("\n");

  // // INFO("Register final state (in hex)\n");
  // // print_fpregs_hex(fpregs);

  // printf("\n\n");

  // INFO("Testing ground truth\n");
  // for (int i = 0; i < 16; i++) {
  //   fpregs[i].low = (double)i;
  //   fpregs[i].high = (double)i + 0.5;
  // }
  // INFO("Register initial state\n");
  // // print_fpregs_decimal(fpregs);
  // fpvm_dump_xmms_double(stderr, fpregs);

  // fpvm_test_instr(fpregs);

  // printf("\n");

  // INFO("Register final state\n");
  // // print_fpregs_decimal(fpregs);
  // fpvm_dump_xmms_double(stderr, fpregs);

  // printf("\n");

  // INFO("Register final state (in hex)\n");
  // print_fpregs_hex(fpregs);

  return 0;
}
#endif

#if CONFIG_FPTRAPALL

#include <stdint.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/file.h>

#define FPTRAPALL_REGISTER_PATH "/sys/kernel/fptrapall/register"
#define FPTRAPALL_TS_PATH "/sys/kernel/fptrapall/ts"
#define FPTRAPALL_IN_SIGNAL_PATH "/sys/kernel/fptrapall/in_signal"

static int ts_fd = -1;
static int mark_sig_fd = -1;

static int ts_is_set = -1;

void
fptrapall_register(execution_context_t *mc)
{
	int fd = syscall(SYS_open, FPTRAPALL_REGISTER_PATH, O_WRONLY);
	if(fd < 0) {
		perror("open");
		syscall(SYS_exit, fd);
	}

	uint8_t val = '1';
	long written = syscall(SYS_write, fd, &val, sizeof(val));

        if (written < 0) {
            perror("write");
	    syscall(SYS_exit, (int)written);
        }

	syscall(SYS_close, fd);

	ts_fd = syscall(SYS_open, FPTRAPALL_TS_PATH, O_WRONLY);
	if(ts_fd < 0) {
		perror("open");
		syscall(SYS_exit, ts_fd);
	}

	mark_sig_fd = syscall(SYS_open, FPTRAPALL_IN_SIGNAL_PATH, O_WRONLY);
	if(mark_sig_fd < 0) {
		perror("open");
		syscall(SYS_exit, mark_sig_fd);
	}

	fptrapall_mark_in_signal();
	fptrapall_set_ts();
}

void
fptrapall_mark_in_signal(void)
{
    execution_context_t *mc = find_my_execution_context();
    if(mc == NULL) {return;} // We aren't registered yet
    START_PERF(mc, mark_in_signal);
    uint8_t val = '1';
    long written = syscall(SYS_write, mark_sig_fd, &val, sizeof(val));
    
    if (written < 0) {
        perror("write");
        syscall(SYS_exit, (int)written);
    }
    END_PERF(mc, mark_in_signal);
}

void
fptrapall_set_ts(void)
{
    execution_context_t *mc = find_my_execution_context();
    if(mc == NULL) {return;} // We aren't registered yet
    if(ts_is_set != 1) {
        START_PERF(mc, set_ts);
	uint8_t val = '1';
	long written = syscall(SYS_write, ts_fd, &val, sizeof(val));

        if (written < 0) {
            perror("write");
	    syscall(SYS_exit, (int)written);
        }
	
	ts_is_set = 1;
        END_PERF(mc, set_ts);
    }
}

void
fptrapall_clear_ts(void)
{
    execution_context_t *mc = find_my_execution_context();
    if(mc == NULL) {return;} // We aren't registered yet
    if(ts_is_set != 0) {
        START_PERF(mc, clear_ts);
	uint8_t val = '0';
	long written = syscall(SYS_write, ts_fd, &val, sizeof(val));

        if (written < 0) {
            perror("write");
	    syscall(SYS_exit, (int)written);
        }
	ts_is_set = 0;
        END_PERF(mc, clear_ts);
    }
}

#endif

