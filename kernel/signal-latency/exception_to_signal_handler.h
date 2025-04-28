#pragma once

#include <stdint.h>

#include "csr.h"

#define PIPELINED_DELEGATE_HELLO_WORLD 0x4630
#define PIPELINED_DELEGATE_INSTALL_HANDLER_TARGET 0x80084631
#define PIPELINED_DELEGATE_DELEGATE_TRAPS 0x80084632
#define PIPELINED_DELEGATE_CSR_STATUS 0x4633

#define PIPELINED_DELEGATE_FILE "/dev/pipelined-delegate"
#define EXC_FLOATING_POINT_FAULT 0x18 // 24
#define EXC_INST_STEP 0x19 // 25

static inline uint64_t __attribute__((always_inline)) arch_cycle_count(void)
{
  uint64_t val;
  asm volatile("rdcycle %0" : "=r"(val));
  return val;
}

static inline uint64_t __attribute__((always_inline)) read_uscratch(void)
{
  uint64_t uscratch = 0;
  asm volatile("csrr %0, 0x840\n\t"
               : "=r"(uscratch)
               :
               : );
  return uscratch;
}
