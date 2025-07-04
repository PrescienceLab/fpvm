
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

#if __x86_64__
// somehow this also causes stack alignment to be screwed up...
#define NO_TOUCH_FLOAT __attribute__((target ("general-regs-only")))
#define FXSAVE_ALIGN __attribute__((aligned (16)));
#define XMM_ALIGN __attribute__((aligned (16)));
#else
#define NO_TOUCH_FLOAT
#define FXSAVE_ALIGN
#define XMM_ALIGN
#endif


// somehow incomplete... 
//#define NO_TOUCH_FLOAT __attribute__((target ("no-avx,no-avx2,no-sse,no-sse2,no-sse3,no-sse4,no-sse4.1,no-sse4.2,no-sse4a,no-ssse3,no-3dnow,no-3dnowa,no-abm,no-adx,no-aes,no-mmx,no")))


// --------------- x86 -----------------
#if defined(__x86_64__)

typedef struct _libc_fpstate fpvm_fpstate_t;
#define FPSTATE_FPRS(fpstate) (&(fpstate)->_xmm[0])

// these functions take an fpvm_regs_t struct, and return the address of various
// fields according to the given architecture
// HACK: this is not a good way to do this, but it works just to get FPVM compiling
//       on arm64
#define FPVM_REGS_GPRS(regs) (uint8_t*)((regs)->mcontext->gregs)
#define FPVM_REGS_FPRS(regs) (uint8_t*)((regs)->fprs)

// Grab important registers from the mcontext struct (it's layout is different on different archs)
#define MCTX_PC(mc) ((mc)->gregs[REG_RIP])
#define MCTX_SP(mc) ((mc)->gregs[REG_RSP])
// A pointer to the start of the floating point register state
#define MCTX_FPRS(mc) ((mc)->fpregs->_xmm)


#endif

// -------------- RISCV ----------------
#if defined(__riscv)
#error "RISC-V not supported yet"

#endif

// -------------- ARM64 ----------------
#if defined(__aarch64__)

typedef struct { double data[32]; } fpvm_fpstate_t; // TODO: INCORRECT
#define FPSTATE_FPRS(fpstate) (&(fpstate)->data)

#define FPVM_REGS_GPRS(regs) (uint8_t*)((regs)->mcontext->regs)
#define FPVM_REGS_FPRS(regs) (uint8_t*)((regs)->fprs)


#define MCTX_PC(mc) ((mc)->pc)
#define MCTX_SP(mc) ((mc)->sp)
#define MCTX_FPRS(mc) ((void*)NULL) // TODO:

#endif





// attempts at comprehensive list from https://gcc.gnu.org/onlinedocs/gcc/x86-Function-Attributes.html
// generated from script
//#define NO_TOUCH_FLOAT __attribute__((target ("no-3dnow,no-3dnowa,no-abm,no-adx,no-aes,no-avx,no-avx2,no-avx5124fmaps,no-avx5124vnniw,no-avx512bitalg,no-avx512bw,no-avx512cd,no-avx512dq,no-avx512er,no-avx512f,no-avx512ifma,no-avx512pf,no-avx512vbmi,no-avx512vbmi2,no-avx512vl,no-avx512vnni,no-avx512vpopcntdq,no-bmi,no-bmi2,no-cldemote,no-clflushopt,no-clwb,no-clzero,no-crc32,no-cx16,no-f16c,no-fma,no-fma4,no-fsgsbase,no-fxsr,no-gfni,no-hle,no-lwp,no-lzcnt,no-mmx,no-movbe,no-movdir64b,no-movdiri,no-mwait,no-mwaitx,no-pclmul,no-pconfig,no-pku,no-popcnt,no-prefetchwt1,no-prfchw,no-ptwrite,no-rdpid,no-rdrnd,no-rdseed,no-rtm,no-sahf,no-sgx,no-sha,no-shstk,no-sse,no-sse2,no-sse3,no-sse4,no-sse4.1,no-sse4.2,no-sse4a,no-ssse3,no-tbm,no-vaes,no-vpclmulqdq,no-waitpkg,no-wbnoinvd,no-xop,no-xsave,no-xsavec,no-xsaveopt,no-xsaves,no-amx-tile,no-amx-int8,no-amx-bf16,no-uintr,no-hreset,no-kl,no-widekl,no-avxvnni,no-avxifma,no-avxvnniint8,no-avxneconvert,no-cmpccxadd,no-amx-fp16,no-prefetchi,no-raoint,no-amx-complex,no-avxvnniint16,no-sm3,no-sha512,no-sm4,no-usermsr,no-apxf,no-avx10.1,no-avx10.1-256,no-avx10.1-512,no-cld,no-fancy-math-387,no-ieee-fp,no-inline-all-stringops,no-inline-stringops-dynamically,no-align-stringops,no-recip")))
// Generated from script and reduced to that accepted by ubuntu 22 default compiler
//#define NO_TOUCH_FLOAT __attribute__((target ("no-3dnow,no-3dnowa,no-abm,no-adx,no-aes,no-avx,no-avx2,no-avx5124fmaps,no-avx5124vnniw,no-avx512bitalg,no-avx512bw,no-avx512cd,no-avx512dq,no-avx512er,no-avx512f,no-avx512ifma,no-avx512pf,no-avx512vbmi,no-avx512vbmi2,no-avx512vl,no-avx512vnni,no-avx512vpopcntdq,no-bmi,no-bmi2,no-cldemote,no-clflushopt,no-clwb,no-clzero,no-crc32,no-cx16,no-f16c,no-fma,no-fma4,no-fsgsbase,no-fxsr,no-gfni,no-hle,no-lwp,no-lzcnt,no-mmx,no-movbe,no-movdir64b,no-movdiri,no-mwait,no-mwaitx,no-pclmul,no-pconfig,no-pku,no-popcnt,no-prefetchwt1,no-prfchw,no-ptwrite,no-rdpid,no-rdrnd,no-rdseed,no-rtm,no-sahf,no-sgx,no-sha,no-shstk,no-sse,no-sse2,no-sse3,no-sse4,no-sse4.1,no-sse4.2,no-sse4a,no-ssse3,no-tbm,no-vaes,no-vpclmulqdq,no-waitpkg,no-wbnoinvd,no-xop,no-xsave,no-xsavec,no-xsaveopt,no-xsaves,no-amx-tile,no-amx-int8,no-amx-bf16,no-uintr,no-hreset,no-kl,no-widekl,no-avxvnni,no-cld,no-fancy-math-387,no-ieee-fp,no-inline-all-stringops,no-inline-stringops-dynamically,no-align-stringops,no-recip")))

static inline uint64_t NO_TOUCH_FLOAT __attribute__((always_inline)) rdtsc(void) {
  uint32_t lo, hi;
  __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
  return lo | ((uint64_t)(hi) << 32);
}


#define DIVU(x,y) ((y)==0 ? 0 : (x)/(y))
#define DIVF(x,y) ((y)==0.0 ? 0.0 : (x)/(y))


static inline void NO_TOUCH_FLOAT fpvm_safe_memset(void *p, uint8_t c,uint64_t len)
{
  for (uint8_t *up=(uint8_t*)p; len ; len--, up++) { *up=c; }
}

// interface to assembly stub
int fpvm_memaddr_probe_readable_long(void *addr);



#endif
