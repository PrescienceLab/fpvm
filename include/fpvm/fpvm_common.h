#ifndef _FPVM_COMMON_
#define _FPVM_COMMON_

#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "config.h"


// // forward old configs
// #define DEBUG_OUTPUT CONFIG_DEBUG
//fix this : CONFIG_DEBUG not found config.h
#define DEBUG_OUTPUT CONFIG_DEBUG
#define NO_OUTPUT CONFIG_NO_OUTPUT


#define DEFAULT_DECODE_CACHE_SIZE 65537   // ideally a prime number



#if DEBUG_OUTPUT
#define DEBUG(S, ...) fprintf(stderr, "fpvm debug(%8d): " S, gettid(), ##__VA_ARGS__)
#else 
#define DEBUG(S, ...) 
#endif

#if NO_OUTPUT
#define INFO(S, ...) 
#define ERROR(S, ...)
#else
#define INFO(S, ...) fprintf(stderr,  "fpvm info(%8d): " S, gettid(), ##__VA_ARGS__)
#define ERROR(S, ...) fprintf(stderr, "fpvm ERROR(%8d): " S, gettid(), ##__VA_ARGS__)
#endif



// eventually make this a menuconfig option
#define CONFIG_ASSERTIONS 1

#if CONFIG_ASSERTIONS
#include <assert.h>
#define ASSERT(E) assert(E)
#else
#define ASSERT(E)
#endif

static inline uint64_t __attribute__((always_inline)) rdtsc(void)
{
  uint32_t lo, hi;
  asm volatile("rdtsc" : "=a"(lo), "=d"(hi));
  return lo | ((uint64_t)(hi) << 32);
}
#if 1
static inline int gettid()
{
  return syscall(SYS_gettid);
}
#endif


#endif
