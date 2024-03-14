
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

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


// Private output formatting routines since we
// do not want to reply on printf being functional
#define DB(x)  { char _buf=x;  syscall(SYS_write,2,&_buf,1); }
#define DHN(x) DB((((x & 0xF) >= 10) ? (((x & 0xF) - 10) + 'a') : ((x & 0xF) + '0')))
#define DHB(x) DHN(x >> 4) ; DHN(x);
#define DHW(x) DHB(x >> 8) ; DHB(x);
#define DHL(x) DHW(x >> 16) ; DHW(x);
#define DHQ(x) DHL(x >> 32) ; DHL(x);
#define DSTR(x) { char *__curr = x; while(*__curr) { DB(*__curr); __curr++; } }

#define _SAFE_DEBUG(s) DSTR("fpvm safe debug: "); DSTR(s)
#define _SAFE_DEBUG_QUAD(s,x) DSTR("fpvm safe debug: "); DSTR(s); DSTR(": "); DHQ(((uint64_t)x)); DB('\n')


#if DEBUG_OUTPUT
#define DEBUG(S, ...) fprintf(stderr, "fpvm debug(%8ld): " S, gettid(), ##__VA_ARGS__)
#define SAFE_DEBUG(S) _SAFE_DEBUG(S)
#define SAFE_DEBUG_QUAD(S,X) _SAFE_DEBUG_QUAD(S,X)
#else
#define DEBUG(S, ...)
#define SAFE_DEBUG(S)
#define SAFE_DEBUG_QUAD(S,X)
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

#define NO_TOUCH_FLOAT __attribute__((__target__("no-avx,no-avx2,no-sse,no-sse2,no-sse3,no-sse4,no-sse4.1,no-sse4.2,no-sse4a,no-ssse3")))


// interface to assembly stub
int fpvm_memaddr_probe_readable_long(void *addr);



#endif
