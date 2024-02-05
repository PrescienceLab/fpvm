#define _GNU_SOURCE

#ifndef _FPVM_COMMON_
#define _FPVM_COMMON_

#include "config.h"
#include <stdint.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

// // forward old configs
// #define DEBUG_OUTPUT CONFIG_DEBUG
// fix this : CONFIG_DEBUG not found config.h
#define DEBUG_OUTPUT CONFIG_DEBUG
#define NO_OUTPUT CONFIG_NO_OUTPUT

#define DEFAULT_DECODE_CACHE_SIZE 65537  // ideally a prime number
#define DEFAULT_TRACE_STORE_SIZE  (DEFAULT_DECODE_CACHE_SIZE*13)

#ifndef gettid
#define gettid() syscall(SYS_gettid)
#endif

#if DEBUG_OUTPUT
#define DEBUG(S, ...) fprintf(stderr, "fpvm debug(%8ld): " S, gettid(), ##__VA_ARGS__)
#else
#define DEBUG(S, ...)
#endif

#if NO_OUTPUT
#define INFO(S, ...)
#define ERROR(S, ...)
#else
#define INFO(S, ...) fprintf(stderr, "fpvm info(%8ld): " S, gettid(), ##__VA_ARGS__)
#define ERROR(S, ...) fprintf(stderr, "fpvm ERROR(%8ld): " S, gettid(), ##__VA_ARGS__)
#endif

// eventually make this a menuconfig option
#define CONFIG_ASSERTIONS 1

#if CONFIG_ASSERTIONS
#include <assert.h>
#define ASSERT(E) assert(E)
#else
#define ASSERT(E)
#endif

static inline uint64_t __attribute__((always_inline)) rdtsc(void) {
  uint32_t lo, hi;
  asm volatile("rdtsc" : "=a"(lo), "=d"(hi));
  return lo | ((uint64_t)(hi) << 32);
}

#endif
