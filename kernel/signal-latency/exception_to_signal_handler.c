#define _GNU_SOURCE
#include <sys/ucontext.h>
#include <fenv.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>

#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include "fpvm_ioctl.h"

#include <assert.h>
#define N 100000

static inline uint64_t __attribute__((always_inline)) arch_cycle_count(void)
{
  uint64_t val;
  asm volatile("rdcycle %0" : "=r"(val));
  return val;
}

static volatile uint64_t hit_inst_time = 0;
static volatile uint64_t hit_handler_time = 0;
static volatile uint64_t hit_next_inst_time = 0;

struct result {
  uint64_t inst_to_handler;
  uint64_t handler_to_next_inst;
  uint64_t round_trip;
};
struct result results[N];

volatile uint64_t time[N];

static volatile uint64_t hit_handler_count = 0;
static void our_handler(int signum, siginfo_t *si, void *priv) {
  hit_handler_time = arch_cycle_count();
  hit_handler_count += 1;

  /* uepc += 4; */
  ucontext_t *uc = (ucontext_t*)priv;
  uc->uc_mcontext.__gregs[REG_PC] += 4;
  /* volatile uint64_t old_uepc = 0; */
  /* asm volatile( */
  /*     "csrr %0, 0x841\n\t" */
  /*     "addi %0, %0, 4\n\t" */
  /*     "csrw 0x841, %0\n\t" */
  /*     : "=r"(old_uepc) */
  /*     : */
  /*     : "memory"); */
  feclearexcept(FE_ALL_EXCEPT);
  return;
}

int main() {
  int pid;
  int file_desc;
  // memset(time, 1, N*sizeof(uint64_t));

#ifdef USE_SIGNALS
    struct sigaction sa;
    memset(&sa,0,sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = our_handler;
    sa.sa_flags |= SA_SIGINFO;
    sigaction(SIGFPE, &sa, NULL);
#else
  // Open
  file_desc = open("/dev/fpvm_dev", O_RDWR);

  // Try registering handler with fpvm_dev
  if (!(file_desc < 0)) {
    ioctl(file_desc, FPVM_IOCTL_REG, &_user_fpvm_entry);
  }
#endif
  feclearexcept(FE_ALL_EXCEPT);
  feenableexcept(FE_ALL_EXCEPT);

  for (int i = 0; i < N; i++) {
      time[i] = arch_cycle_count();
  }
  for (int i = 0; i < N; i++) {
      printf("%lu\n", time[i]);
  }

  volatile double in_a = 0.123;
  volatile double in_b = 0.456;
  volatile double z;

  for (int i = 0; i < N; i++) {
    hit_inst_time = arch_cycle_count();

    asm volatile(
        "movsd %1, %%xmm0\n\t"      // load a into xmm0
        "movsd %2, %%xmm1\n\t"      // load a into xmm1
        "mov $0xffEEff, %%r15\n\t"  // put a marker in r15
        "divsd %%xmm1, %%xmm0\n\t"  // the faulting instruction
        // here, r15 should be the time we got in the kernel
        "movq %%r15, %0\n\t"
        : "=m"(t_b)
        : "m"(in_a), "m"(in_b)
        : "xmm0", "xmm1", "r15");
    hit_next_inst_time = arch_cycle_count();

    struct result res;
    res.inst_to_handler = hit_handler_time - hit_inst_time;
    res.handler_to_next_inst = hit_next_inst_time - hit_handler_time;
    res.round_trip = arch_cycle_count() - hit_inst_time;
    results[i] = res;
  }

  assert(hit_handler_count == N);

  printf("Hit FP Handler %lu times\n", hit_handler_count);

  printf("trial,inst_to_handler,handler_to_next_inst,round_trip,slack\n");
  for (int i = 0; i < N; i++) {
    struct result r = results[i];
    printf("%d, %zu, %zu, %zu, %zu\n", i,
           r.inst_to_handler,
           r.handler_to_next_inst,
           r.round_trip,
           r.round_trip - (r.handler_to_next_inst + r.inst_to_handler));
  }

  return 0;
}
