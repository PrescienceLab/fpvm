#pragma once

#include <stdint.h>

static inline uint64_t __attribute__((always_inline)) arch_cycle_count(void)
{
  uint64_t val;
  asm volatile("rdcycle %0" : "=r"(val));
  return val;
}
