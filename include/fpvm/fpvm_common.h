
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
// and we need to be able to intercept printf/fprintf/etc
#define DB(fd,x)  { char _buf=x;  syscall(SYS_write,fd,&_buf,1); }
#define DHN(fd,x) DB(fd,(((x & 0xF) >= 10) ? (((x & 0xF) - 10) + 'a') : ((x & 0xF) + '0')))
#define DHB(fd,x) DHN(fd,x >> 4) ; DHN(fd,x);
#define DHW(fd,x) DHB(fd,x >> 8) ; DHB(fd,x);
#define DHL(fd,x) DHW(fd,x >> 16) ; DHW(fd,x);
#define DHQ(fd,x) DHL(fd,x >> 32) ; DHL(fd,x);
#define DSTR(fd,x) { char *__curr = x; uint64_t __count=0; while(*__curr++) { __count++; } syscall(SYS_write,fd,x,__count); }

#define _SAFE_DEBUG(s) DSTR(2,"fpvm safe debug: "); DSTR(2,s)
#define _SAFE_DEBUG_QUAD(s,x) DSTR(2,"fpvm safe debug: "); DSTR(2,s); DSTR(2,": "); DHQ(2,((uint64_t)x)); DB(2,'\n')

// if enabled, try to limit output to "safe" functions as
// much as possible
#define TRY_RESTRICT_TO_SAFE 1


#if DEBUG_OUTPUT
#if TRY_RESTRICT_TO_SAFE
#define DEBUG(S, ...) { char __buf[512]; snprintf(__buf,512, "fpvm debug(%8ld): " S, gettid(), ##__VA_ARGS__); DSTR(2,__buf) }
#else
#define DEBUG(S, ...) fprintf(stderr, "fpvm debug(%8ld): " S, gettid(), ##__VA_ARGS__)
#endif
#define SAFE_DEBUG(S) _SAFE_DEBUG(S)
#define SAFE_DEBUG_QUAD(S,X) _SAFE_DEBUG_QUAD(S,X)
#else
#define DEBUG(S, ...)
#define SAFE_DEBUG(S)
#define SAFE_DEBUG_QUAD(S,X)
#endif

#if NO_OUTPUT
#if DEBUG_OUTPUT
#undef DEBUG
#undef SAFE_DEBUG
#undef SAFE_DEBUG_QUAD
#endif
#define DEBUG(S, ...)
#define SAFE_DEBUG(S)
#define SAFE_DEBUG_QUAD(S,X)
#define INFO(S, ...)
#define ERROR(S, ...)
#else
#if TRY_RESTRICT_TO_SAFE
#define INFO(S, ...) { char __buf[512]; snprintf(__buf,512, "fpvm info(%8ld): " S, gettid(), ##__VA_ARGS__); DSTR(2,__buf) } 
#define ERROR(S, ...) { char __buf[512]; snprintf(__buf,512, "fpvm ERROR(%8ld): " S, gettid(), ##__VA_ARGS__); DSTR(2,__buf) }
#else
#define INFO(S, ...) fprintf(stderr, "fpvm info(%8ld): " S, gettid(), ##__VA_ARGS__)
#define ERROR(S, ...) fprintf(stderr, "fpvm ERROR(%8ld): " S, gettid(), ##__VA_ARGS__)
#endif
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
