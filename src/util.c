#include <stdint.h>
#include <stdio.h>

#define _GNU_SOURCE
#define __USE_GNU
#include <sys/ucontext.h>

#include <fpvm/fpvm_common.h>
#include <fpvm/util.h>

void fpvm_dump_xmms_double(FILE *out, void *xmm) {
  int i;

  uint64_t *x = xmm;
  double *d = xmm;

  for (i = 0; i < 32; i += 2) {
    fprintf(out, " xmm[%2d] = (%lf, %lf) [%016lx, %016lx] (addr %p)\n", i / 2,
            d[i], d[i + 1], x[i], x[i + 1], &x[i]);
  }
}

void fpvm_dump_xmms_float(FILE *out, void *xmm) {
  int i;

  uint32_t *x = xmm;
  float *f = xmm;

  for (i = 0; i < 64; i += 4) {
    fprintf(out,
            " xmm[%2d] = (%f, %f, %f, %f) [%08x, %08x, %08x, %08x] (addr %p)\n",
            i / 4, f[i], f[i + 1], f[i + 2], f[i + 3], x[i], x[i + 1], x[i + 2],
            x[i + 3], &x[i]);
  }
}

static uint32_t get_mxcsr() {
  uint32_t val = 0;
  __asm__ __volatile__("stmxcsr %0" : "=m"(val) : : "memory");
  return val;
}

void fpvm_dump_float_control(FILE *out, ucontext_t *uc) {
  fpregset_t f = uc->uc_mcontext.fpregs;

  fprintf(out, " mxcsr=%08x  real_mxcsr=%08x mxcr_mask=%08x\n", f->mxcsr,
          get_mxcsr(), f->mxcr_mask);
}

void fpvm_dump_gprs(FILE *out, ucontext_t *uc) {
  greg_t *r = uc->uc_mcontext.gregs;

  fprintf(out, " rip=%016lx rfl=%016lx cgf=%016lx cr2=%016lx\n",
          (uint64_t)r[REG_RIP], (uint64_t)r[REG_EFL], (uint64_t)r[REG_CSGSFS],
          (uint64_t)r[REG_CR2]);
  fprintf(out, " rax=%016lx rbx=%016lx rcx=%016lx rdx=%016lx\n",
          (uint64_t)r[REG_RAX], (uint64_t)r[REG_RBX], (uint64_t)r[REG_RCX],
          (uint64_t)r[REG_RDX]);
  fprintf(out, " rsp=%016lx rbp=%016lx rsi=%016lx rdi=%016lx\n",
          (uint64_t)r[REG_RSP], (uint64_t)r[REG_RBP], (uint64_t)r[REG_RSI],
          (uint64_t)r[REG_RDI]);
  fprintf(out, "  r8=%016lx  r9=%016lx r10=%016lx r11=%016lx\n",
          (uint64_t)r[REG_R8], (uint64_t)r[REG_R9], (uint64_t)r[REG_R10],
          (uint64_t)r[REG_R11]);
  fprintf(out, " r12=%016lx r13=%016lx r14=%016lx r15=%016lx\n",
          (uint64_t)r[REG_R12], (uint64_t)r[REG_R13], (uint64_t)r[REG_R14],
          (uint64_t)r[REG_R15]);
}
