#define _GNU_SOURCE
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

#define N 100000

static inline uint64_t my_rdtsc(void) {
  uint32_t lo, hi;
  asm volatile("rdtsc" : "=a"(lo), "=d"(hi));
  return lo | ((uint64_t)(hi) << 32);
}

void our_handler(void *test) {
  t_c = my_rdtsc();
  /* end = my_rdtsc(); */
  /* time[count++] = end; */
  /* if (count == N) { */
  /*   for (int i = 1; i < count; i++) { */
  /*     printf("%d\t%ld\n", i, time[i] - time[i - 1]); */
  /*   } */
  /*   exit(0); */
  /* } */
  return;
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

int main() {
  int pid;
  int file_desc;
  // memset(time, 1, N*sizeof(uint64_t));

#ifdef USE_SIGNALS
  signal(SIGFPE, our_handler);
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


  volatile double in_a = 0.123;
  volatile double in_b = 0.456;
  volatile double z;

  for (int i = 0; i < N; i++) {
    t_a = my_rdtsc();

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
