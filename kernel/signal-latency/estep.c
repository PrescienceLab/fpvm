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

struct delegate_config_t {
        unsigned int en_flag;
        unsigned long trap_mask;
};

#include <assert.h>
#define N 1000000

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

uintptr_t __attribute__((weak)) our_handler(uintptr_t cause, uintptr_t epc, uintptr_t gregs[31]) {
  hit_handler_time = arch_cycle_count();
  hit_handler_count += 1;

  /* Read out the time we hit the ppe_handler_entry label from where we
   * stashed it in USCRATCH.
   * NOTE: We do this AFTER the hit_handler_time so that we get an accurate
   * measure of the time required to save the registers to the stack and
   * building the C function frame. */
  hit_handler_asm = read_uscratch();

  uintptr_t new_uepc = epc + 4;

  /* printf("NEW UEPC: " REG_FMT "\n", new_uepc); */
  left_handler_time = arch_cycle_count();
  return new_uepc;
}

void use(int x) {}

int main() {
  int pd_fd = open(PIPELINED_DELEGATE_FILE, O_RDWR | O_SYNC | O_DSYNC);
  if (pd_fd < 0) {
      printf("Could not open " PIPELINED_DELEGATE_FILE "\n");
  }

  int rc = 0;
  rc = ioctl(pd_fd, PIPELINED_DELEGATE_CSR_STATUS);

  struct delegate_config_t test_enable_mask = {
      .en_flag = 1,
      .trap_mask = 1 << EXC_INST_STEP,
  };
  rc = ioctl(pd_fd, PIPELINED_DELEGATE_DELEGATE_TRAPS, &test_enable_mask);
  rc = ioctl(pd_fd, PIPELINED_DELEGATE_CSR_STATUS);

  unsigned long handler_vaddr = (unsigned long) ppe_handler_entry;
  rc = ioctl(pd_fd, PIPELINED_DELEGATE_INSTALL_HANDLER_TARGET, handler_vaddr);
  rc = ioctl(pd_fd, PIPELINED_DELEGATE_CSR_STATUS);

  use(rc);

  printf("hit_inst_time,hit_handler_asm,hit_handler_time,left_handler_time,left_handler_asm,hit_next_inst_time\n");
  for (int i = 0; i < N; i++) {
    hit_inst_time = arch_cycle_count();

    asm volatile(
        ".insn 0x00300073\n\t"
        :
        :
        : "memory");
    hit_next_inst_time = arch_cycle_count();

    left_handler_asm = read_uscratch();

    /* XXX: hit_handler_asm and left_handler_asm will be 0 in the case of
     * signals! You would need the kernel to populate those values for you!
     * TODO: Make Linux populate uscratch for hit/left_handler_asm upon
     * entry/exit to/from the kernel. */
    printf("%zu,%zu,%zu,%zu,%zu,%zu\n",
           hit_inst_time, hit_handler_asm, hit_handler_time,
           left_handler_time, left_handler_asm, hit_next_inst_time);
  }

  fprintf(stderr, "Hit PPE handler %lu times\n", hit_handler_count);
  assert(hit_handler_count == N);

  close(pd_fd);
  return 0;
}
