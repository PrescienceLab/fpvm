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

#include "exception_to_signal_handler.h"
extern void ppe_handler_entry(void);

#include <assert.h>
#define N 10000

// When did we hit the exceptional instruction?
static volatile uint64_t hit_inst_time = 0xDEADBEEFFEEDBEAD;
// When did we hit the handler's assembly landing pad?
static volatile uint64_t hit_handler_asm = 0;
// When did we hit the handler in C?
static volatile uint64_t hit_handler_time = 0xCAFEBEEFDEAD8080;
// When did we leave the handler in C?
static volatile uint64_t left_handler_time = 0;
// When did we leave the handler's assembly landing pad?
static volatile uint64_t left_handler_asm = 0;
// When did we hit the next instruction?
static volatile uint64_t hit_next_inst_time = 0x9278DEAD2929FE;

static volatile uint64_t hit_handler_count = 0;

#ifdef USE_SIGNALS
static void our_handler(int signum, siginfo_t *si, void *priv) {
  hit_handler_time = arch_cycle_count();
  hit_handler_count += 1;
  /* Skip the faulting instruction. */
  ucontext_t *uc = (ucontext_t*)priv;
  uc->uc_mcontext.__gregs[REG_PC] += 4;
  return;
}
#else
uintptr_t __attribute__((weak)) our_handler(uintptr_t cause, uintptr_t epc, uintptr_t gregs[31]) {
  hit_handler_time = arch_cycle_count();
  hit_handler_count += 1;

  /* printf("Made it into the handler!\n"); */
  /* printf("OLD UEPC: " REG_FMT "\n", epc); */

  uintptr_t new_uepc = epc + 4;

  /* printf("NEW UEPC: " REG_FMT "\n", new_uepc); */
  return new_uepc;
}
#endif

static void wrong_uepc_usage(void) {
    printf("We took UEPC at the wrong time!\n");
    exit(1);
}

void use (double f) {}

int main() {
  int pd_fd = open(PIPELINED_DELEGATE_FILE, O_RDWR | O_SYNC | O_DSYNC);
  if (pd_fd < 0) {
      printf("Could not open " PIPELINED_DELEGATE_FILE "\n");
  }

  int rc = 0;
  rc = ioctl(pd_fd, PIPELINED_DELEGATE_CSR_STATUS);

  unsigned long handler_vaddr = (unsigned long) wrong_uepc_usage;
#ifdef USE_SIGNALS
  struct sigaction sa;
  memset(&sa,0,sizeof(sa));
  sigemptyset(&sa.sa_mask);
  sa.sa_sigaction = our_handler;
  sa.sa_flags |= SA_SIGINFO;
  sigaction(SIGFPE, &sa, NULL);
  handler_vaddr = (unsigned long) wrong_uepc_usage;
#else
  struct delegate_config_t test_enable_mask = {
      .en_flag = 1,
      .trap_mask = 1 << EXC_FLOATING_POINT_FAULT,
  };
  rc = ioctl(pd_fd, PIPELINED_DELEGATE_DELEGATE_TRAPS, &test_enable_mask);
  rc = ioctl(pd_fd, PIPELINED_DELEGATE_CSR_STATUS);
  handler_vaddr = (unsigned long) ppe_handler_entry;
#endif

  rc = ioctl(pd_fd, PIPELINED_DELEGATE_INSTALL_HANDLER_TARGET, handler_vaddr);
  rc = ioctl(pd_fd, PIPELINED_DELEGATE_CSR_STATUS);

  use(rc);

  feclearexcept(FE_ALL_EXCEPT);
  asm volatile("csrwi 0x880, 0x1F" : : :);
  unsigned long uepc = 0xCAFE8080DAAEBEEFUL;
  asm volatile("csrw 0x841, %0\n\t"
               :
               : "r"(uepc)
               : "memory");

  volatile double in_a = 0.123;
  volatile double in_b = 0.456;
  volatile double z = 0.0;

  use(z);

  asm volatile(
      "fld f1, %0\n\t"
      "fld f2, %1\n\t"
      :
      : "m"(in_a), "m"(in_b)
      :);

  /* NOTE: We rely on the compiler not doing anything with f11/f12 in between
   * the load operations above and the FP-event causing instruction below. */

  printf("hit_inst_time,hit_handler_asm,hit_handler_time,left_handler_time,left_handler_asm,hit_next_inst_time\n");
  for (int i = 0; i < N; i++) {
    hit_inst_time = arch_cycle_count();

    // Generate a rounding event
    // Generate some kind of FP event
    asm volatile(
        "fdiv.d f3, f1, f2\n\t" // the faulting instruction
        :
        : "m"(in_a), "m"(in_b)
        : "f1", "f2", "f3", "memory");
    hit_next_inst_time = arch_cycle_count();

    left_handler_asm = read_uscratch();

    /* XXX: hit_handler_asm and left_handler_asm will be 0 in the case of
     * signals! You would need the kernel to populate those values for you!
     * TODO: Make Linux populate uscratch for hit/left_handler_asm upon
     * entry/exit to/from the kernel. */
    printf("%zu,%zu,%zu,%zu,%zu,%zu\n",
           hit_inst_time, hit_handler_asm, hit_handler_time,
           left_handler_time, left_handler_asm, hit_next_inst_time);

    feclearexcept(FE_ALL_EXCEPT);
  }

  fprintf(stderr, "Hit FP Handler %lu times\n", hit_handler_count);
  assert(hit_handler_count == N);

  close(pd_fd);
  return 0;
}
