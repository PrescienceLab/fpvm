#define _GNU_SOURCE
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <ucontext.h>
#include <fenv.h>
#include <string.h>
#include <fcntl.h>

#include <fpvm/fpvm.h>
#include <fpvm/arch.h>
#include <fpvm/fpvm_arch.h>

// support for kernel module
#if CONFIG_KERNEL_SHORT_CIRCUITING
#include <sys/ioctl.h>
#include <fpvm/fpvm_ioctl.h>
#endif


static int mxcsrmask_base = 0x3f;  // which sse exceptions to handle, default all (using base zero)

#define MXCSR_FLAG_MASK (mxcsrmask_base << 0)
#define MXCSR_MASK_MASK (mxcsrmask_base << 7)

void arch_clear_trap_mask(void) { mxcsrmask_base = 0; }

void arch_set_trap_mask(int which) {
  switch (which) {
    case FE_INVALID:
      mxcsrmask_base |= 0x1;
      break;
    case FE_DENORM:
      mxcsrmask_base |= 0x2;
      break;
    case FE_DIVBYZERO:
      mxcsrmask_base |= 0x4;
      break;
    case FE_OVERFLOW:
      mxcsrmask_base |= 0x8;
      break;
    case FE_UNDERFLOW:
      mxcsrmask_base |= 0x10;
      break;
    case FE_INEXACT:
      mxcsrmask_base |= 0x20;
      break;
  }
}

void arch_reset_trap_mask(int which) {
  switch (which) {
    case FE_INVALID:
      mxcsrmask_base &= ~0x1;
      break;
    case FE_DENORM:
      mxcsrmask_base &= ~0x2;
      break;
    case FE_DIVBYZERO:
      mxcsrmask_base &= ~0x4;
      break;
    case FE_OVERFLOW:
      mxcsrmask_base &= ~0x8;
      break;
    case FE_UNDERFLOW:
      mxcsrmask_base &= ~0x10;
      break;
    case FE_INEXACT:
      mxcsrmask_base &= ~0x20;
      break;
  }
}



// MXCSR used when *we* are executing floating point code
// All masked, flags zeroed, round nearest, special features off
#define MXCSR_OURS 0x1f80


static uint32_t NO_TOUCH_FLOAT get_mxcsr() {
  uint32_t val = 0;
  __asm__ __volatile__("stmxcsr %0" : "=m"(val) : : "memory");
  return val;
}

static void NO_TOUCH_FLOAT set_mxcsr(uint32_t val) {
    __asm__ __volatile__("ldmxcsr %0" : : "m"(val) : "memory");
}

void arch_get_machine_fp_csr(arch_fp_csr_t *f) { f->val = get_mxcsr(); }

void arch_set_machine_fp_csr(const arch_fp_csr_t *f) { set_mxcsr(f->val); }

int arch_machine_supports_fp_traps(void) { return 1; }

void arch_config_machine_fp_csr_for_local(arch_fp_csr_t *old) {
  arch_get_machine_fp_csr(old);
  set_mxcsr(MXCSR_OURS);
}

int arch_have_special_fp_csr_exception(int which) {
  if (which == FE_DENORM) {
    return !!(get_mxcsr() & 0x2);
  } else {
    return 0;
  }
}

void arch_dump_gp_csr(const char *prefix, const ucontext_t *uc) {
  char buf[256];

  rflags_t *r = (rflags_t *)&(uc->uc_mcontext.gregs[REG_EFL]);

  sprintf(buf, "rflags = %016lx", r->val);

#define EF(x, y)         \
  if (r->x) {            \
    strcat(buf, " " #y); \
  }

  EF(zf, zero);
  EF(sf, neg);
  EF(cf, carry);
  EF(of, over);
  EF(pf, parity);
  EF(af, adjust);
  EF(tf, TRAP);
  EF(intf, interrupt);
  EF(ac, alignment);
  EF(df, down);

  DEBUG("%s: %s\n", prefix, buf);
}

void arch_dump_fp_csr(const char *pre, const ucontext_t *uc) {
  char buf[256];

  mxcsr_t *m = (mxcsr_t *)&uc->uc_mcontext.fpregs->mxcsr;

  sprintf(buf, "mxcsr = %08x flags:", m->val);

#define MF(x, y)         \
  if (m->x) {            \
    strcat(buf, " " #y); \
  }

  MF(ie, NAN);
  MF(de, DENORM);
  MF(ze, ZERO);
  MF(oe, OVER);
  MF(ue, UNDER);
  MF(pe, PRECISION);

  strcat(buf, " masking:");

  MF(im, nan);
  MF(dm, denorm);
  MF(zm, zero);
  MF(om, over);
  MF(um, under);
  MF(pm, precision);

  DEBUG("%s: %s rounding: %s %s %s\n", pre, buf,
      m->rounding == 0   ? "nearest"
      : m->rounding == 1 ? "negative"
      : m->rounding == 2 ? "positive"
                         : "zero",
      m->daz ? "DAZ" : "", m->fz ? "FTZ" : "");
}

void arch_set_trap(ucontext_t *uc, uint64_t *state) {
  uc->uc_mcontext.gregs[REG_EFL] |= 0x100UL;
  if (state) {
    *state = 2;
  }
}

void arch_reset_trap(ucontext_t *uc, uint64_t *state) {
  uc->uc_mcontext.gregs[REG_EFL] &= ~0x100UL;
  if (state) {
    *state = 1;
  }
}


void arch_clear_fp_exceptions(ucontext_t *uc) { uc->uc_mcontext.fpregs->mxcsr &= ~MXCSR_FLAG_MASK; }

void arch_mask_fp_traps(ucontext_t *uc) { uc->uc_mcontext.fpregs->mxcsr |= MXCSR_MASK_MASK; }

void arch_unmask_fp_traps(ucontext_t *uc) { uc->uc_mcontext.fpregs->mxcsr &= ~MXCSR_MASK_MASK; }


#define MXCSR_ROUND_DAZ_FTZ_MASK 0xe040UL

fpvm_arch_round_config_t arch_get_machine_round_config(void) {
  uint32_t mxcsr = get_mxcsr();
  uint32_t mxcsr_round = mxcsr & MXCSR_ROUND_DAZ_FTZ_MASK;
  return mxcsr_round;
}

fpvm_arch_round_config_t arch_get_round_config(ucontext_t *uc) {
  uint32_t mxcsr = uc->uc_mcontext.fpregs->mxcsr;
  uint32_t mxcsr_round = mxcsr & MXCSR_ROUND_DAZ_FTZ_MASK;
  DEBUG("mxcsr (0x%08x) round faz dtz at 0x%08x\n", mxcsr, mxcsr_round);
  arch_dump_fp_csr("arch_get_round_config", uc);
  return mxcsr_round;
}

void arch_set_round_config(ucontext_t *uc, fpvm_arch_round_config_t config) {
  uc->uc_mcontext.fpregs->mxcsr &= ~MXCSR_ROUND_DAZ_FTZ_MASK;
  uc->uc_mcontext.fpregs->mxcsr |= config;
  DEBUG("mxcsr masked to 0x%08x after round daz ftz update (0x%08x)\n",
      uc->uc_mcontext.fpregs->mxcsr, config);
  arch_dump_fp_csr("arch_set_round_config", uc);
}

fpvm_arch_round_mode_t arch_get_round_mode(fpvm_arch_round_config_t config) { return (config >> 13) & 0x3; }

void arch_set_round_mode(fpvm_arch_round_config_t *config, fpvm_arch_round_mode_t mode) {
  *config &= (~0x6000);
  *config |= (mode & 0x3) << 13;
}

fpvm_arch_dazftz_mode_t arch_get_dazftz_mode(fpvm_arch_round_config_t *config) {
  switch (*config & 0x8040) {
    case 0x8040:
      return FPVM_ARCH_ROUND_DAZ_FTZ;
      break;
    case 0x8000:
      return FPVM_ARCH_ROUND_NO_DAZ_FTZ;
      break;
    case 0x0040:
      return FPVM_ARCH_ROUND_DAZ_NO_FTZ;
      break;
    case 0x0000:
    default:
      return FPVM_ARCH_ROUND_NO_DAZ_NO_FTZ;
      break;
  }
}

void arch_set_dazftz_mode(fpvm_arch_round_config_t *config, fpvm_arch_dazftz_mode_t mode) {
  *config &= ~0x8040;
  mode &= 0x3;
  switch (mode) {
    case FPVM_ARCH_ROUND_DAZ_FTZ:
      *config |= 0x8040;
      break;
    case FPVM_ARCH_ROUND_NO_DAZ_FTZ:
      *config |= 0x8000;
      break;
    case FPVM_ARCH_ROUND_DAZ_NO_FTZ:
      *config |= 0x0040;
      break;
    case FPVM_ARCH_ROUND_NO_DAZ_NO_FTZ:
    default:
      // leave at 0x0000
      break;
  }
}


uint64_t arch_get_ip(const ucontext_t *uc) { return uc->uc_mcontext.gregs[REG_RIP]; }

uint64_t arch_get_sp(const ucontext_t *uc) { return uc->uc_mcontext.gregs[REG_RSP]; }

uint64_t arch_get_gp_csr(const ucontext_t *uc) { return uc->uc_mcontext.gregs[REG_EFL]; }

uint64_t arch_get_fp_csr(const ucontext_t *uc) { return uc->uc_mcontext.fpregs->mxcsr; }


int arch_get_instr_bytes(const ucontext_t *uc, uint8_t *dest, int size) {
  int len = size > 15 ? 15 : size;

  if (size < 0) {
    return -1;
  } else {
    memcpy(dest, (const void *)uc->uc_mcontext.gregs[REG_RIP], len);
    return len;
  }
}


int arch_process_init(void) {
  DEBUG("x64 process init\n");
  return 0;
}

void arch_process_deinit(void) { DEBUG("x64 process deinit\n"); }

int arch_thread_init(ucontext_t *uc) {
  DEBUG("x64 thread init\n");
  return 0;
}

void arch_thread_deinit(void) { DEBUG("x64 thread deinit\n"); }


static uint64_t NO_TOUCH_FLOAT get_xmm0() {
  uint64_t val = 0;
  #ifdef __x86_64__
  // TODO: move to a central "machine state save/restore" function
  __asm__ __volatile__("movq %%xmm0, %0" : "=r"(val) : : "memory");
  #endif
  return val;
}



static void mxcsr_disable_save(uint32_t* old) {
  uint32_t tmp = get_mxcsr();
  *old = tmp;
  tmp |= MXCSR_MASK_MASK;
  set_mxcsr(tmp);
}

static void mxcsr_restore(uint32_t old) {
  set_mxcsr(old);
}

static inline void NO_TOUCH_FLOAT fxsave(fpvm_fpstate_t *fpvm_fpregs)
{
  #ifdef __x86_64__
  __asm__ __volatile__("fxsave64 (%0)" :: "r"(fpvm_fpregs));
  #endif
}

static inline void NO_TOUCH_FLOAT fxrstor(const fpvm_fpstate_t *fpvm_fpregs)
{
  #ifdef __x86_64__
  __asm__ __volatile__("fxrstor64 (%0)" :: "r"(fpvm_fpregs));
  #endif
}


//
// Entry point for FP Trap for trap short circuiting (kernel module)
// is used
//
#if CONFIG_KERNEL_SHORT_CIRCUITING
void fpvm_short_circuit_handler(void *priv)
{
  // Build up a sufficiently detailed ucontext_t and
  // call the shared handler.  Copy in/out the FP and GP
  // state

  siginfo_t fake_siginfo;
  fpvm_fpstate_t fpvm_fpregs;
  ucontext_t fake_ucontext;
  uint32_t old;

  // capture FP state (note that this eventually needs to do xsave)
  fxsave(&fpvm_fpregs);

  // disable FP traps during our handler execution
  mxcsr_disable_save(&old);


  uint32_t err = ~(old >> 7) & old;
  if (err & 0x001) {	/* Invalid op*/
    fake_siginfo.si_code = FPE_FLTINV;
  } else if (err & 0x004) { /* Divide by Zero */
    fake_siginfo.si_code = FPE_FLTDIV;
  } else if (err & 0x008) { /* Overflow */
    fake_siginfo.si_code = FPE_FLTOVF;
  } else if (err & 0x012) { /* Denormal, Underflow */
    fake_siginfo.si_code = FPE_FLTUND;
  } else if (err & 0x020) { /* Precision */
    fake_siginfo.si_code = FPE_FLTRES;
  } else {
    // quell warning
    fake_siginfo.si_code = -1;
  }

  siginfo_t * si = (siginfo_t *)&fake_siginfo;

  fake_ucontext.uc_mcontext.fpregs = &fpvm_fpregs;

  // consider memcpy
  for (int i = 0; i < 18; i++) {
    fake_ucontext.uc_mcontext.gregs[i] = *((greg_t*)priv + i);
  }

  ucontext_t *uc = (ucontext_t *)&fake_ucontext;

  uint8_t *rip = (uint8_t*) MCTX_PC(&uc->uc_mcontext);

  DEBUG(
	"SCFPE code 0x%x rip %p %02x %02x %02x %02x %02x "
	"%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
	si->si_code, rip, rip[0], rip[1], rip[2], rip[3], rip[4],
	rip[5], rip[6], rip[7], rip[8], rip[9], rip[10], rip[11], rip[12], rip[13], rip[14], rip[15]);
  DEBUG("SCFPE RIP=%p RSP=%p\n", rip, MCTX_SP(&uc->uc_mcontext));

#if DEBUG_OUTPUT
  char buf[80];
#define CASE(X)      \
  case X:            \
    strcpy(buf, #X); \
    break;
  switch (si->si_code) {
    CASE(FPE_FLTDIV);
    CASE(FPE_FLTINV);
    CASE(FPE_FLTOVF);
    CASE(FPE_FLTUND);
    CASE(FPE_FLTRES);
    CASE(FPE_FLTSUB);
    CASE(FPE_INTDIV);
    CASE(FPE_INTOVF);
  default:
    sprintf(buf, "UNKNOWN(0x%x)\n", si->si_code);
    break;
  }
  DEBUG("FPE exceptions: %s\n", buf);
#endif

  fp_trap_handler(uc);

  DEBUG("SCFPE  done\n");

  // restore GP state
  // consider memcpy
  for (int i = 0; i < 18; i++) {
    *((greg_t*)priv + i) = fake_ucontext.uc_mcontext.gregs[i];
  }

  // restore FP state (note that this eventually needs to do xsave)
  // note that this is also doing the mxcsr restore for however
  // fp_trap_handler modified it
  fxrstor(&fpvm_fpregs);

  return;
}

// trampoline entry stub - from the assembly code
extern void * _user_fpvm_entry;

static int kernel_short_circuit_fd = -1;

int arch_kernel_short_circuiting_init(void)
{
    kernel_short_circuit_fd = open("/dev/fpvm_dev", O_RDWR);

    if (kernel_short_circuit_fd < 0) {
	ERROR("failed to open FPVM kernel support (/dev/fpvm_dev)\n");
	return -1;
    } else {
	if (ioctl(kernel_short_circuit_fd, FPVM_IOCTL_REG, &_user_fpvm_entry)) {
	    ERROR("failed to ioctl FPVM kernel support (/dev/fpvm_dev)\n");
	    close(kernel_short_circuit_fd);
	    return -1;
	} else {
	    DEBUG(":) FPVM kerenl support setup successful\n");
	    return 0;
	}
    }
}

void arch_kernel_short_circuiting_deinit(void)
{
    if (kernel_short_circuit_fd>0) {
	DEBUG("unregistering from FPVM kernel support (/dev/fpvm_dev)\n");
	close(kernel_short_circuit_fd);
    } else {
	DEBUG("skipping unregistering from FPVM kernel support (/dev/fpvm_dev) since fd=%d\n",kernel_short_circuit_fd);
    }
}

#endif
