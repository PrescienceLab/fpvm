#ifndef __ARCH
#define __ARCH


/*
  This is the architectural interface for fpvm

  Note that this is not about instructions, but
  rather to support traps, etc
 */

typedef uint32_t fpvm_arch_round_config_t;

typedef enum {
  FPVM_ARCH_ROUND_NEAREST = 0,
  FPVM_ARCH_ROUND_NEGATIVE = 1,
  FPVM_ARCH_ROUND_POSITIVE = 2,
  FPVM_ARCH_ROUND_ZERO = 3,
  FPVM_ARCH_ROUND_NEAREST_MAXMAG = 4,
  FPVM_ARCH_ROUND_DYNAMIC = 5
} fpvm_arch_round_mode_t;

typedef enum {
  FPVM_ARCH_ROUND_NO_DAZ_NO_FTZ = 0,
  FPVM_ARCH_ROUND_NO_DAZ_FTZ = 1,
  FPVM_ARCH_ROUND_DAZ_NO_FTZ = 2,
  FPVM_ARCH_ROUND_DAZ_FTZ = 3
} fpvm_arch_dazftz_mode_t;

typedef struct {
    uint32_t numregs;
    uint32_t regsize_bytes;
    uint32_t regalign_bytes;
    void    *data; 
} fpvm_arch_gpregs_t;

typedef struct {
    uint32_t numregs;
    uint32_t regsize_bytes;
    uint32_t regalign_bytes;
    uint32_t regsize_entries; // number of doubles per register
    void    *data; 
} fpvm_arch_fpregs_t;


// arch-specific structures and inline functions
// see else for what is expected
//
//

#if defined(x64)
#include "arch/x64/x64.h"
#elif defined(arm64)
#include "arch/arm64/arm64.h"
#elif defined(riscv64)
#include "arch/riscv64/riscv64.h"
#else

//
// This is the "abstract" interface
//

// Implementation must let us define the set of exceptions that
// we want to have trap.   "which" is indicated using the regular
// fenv values (e.g., FE_DIVZERO, FE_INVALID, ..) plus others
// that might be supported, like FE_DENORM
//
// The idea is that these functions will be used at startup time
// to build an except/trap mask that then will be applied when we
// invoke arch_(un)mask_fp_traps() (see below)
#define FE_DENORM 0x1000
void arch_clear_trap_mask(void);
void arch_set_trap_mask(int which);
void arch_reset_trap_mask(int which);


// Implementation needs to define a type for the FP control/status reg
typedef union arch_fp_csr {
} arch_fp_csr_t;

// Implementation must let us get at raw machine state (opaque is fine)
uint64_t arch_cycle_count(void);
void arch_get_machine_fp_csr(arch_fp_csr_t *f);
void arch_set_machine_fp_csr(const arch_fp_csr_t *f);

// Implementation must tell us if it supports FP traps or not
int arch_machine_supports_fp_traps(void);

// Implementation must let us disable all traps, etc, and set FP defaults
// so that we can perform FP ourselves within Fpvm when absolutely needed
void arch_config_fp_csr_for_local(arch_fp_csr_t *old);

// Implementation should be able to tell us if any special exception
// (other than the fenv ones) has been noted.  For example FE_DENORM
int arch_have_special_fp_csr_exception(int which);

// Implementation must let us dump FP and GP control/status regs
// and should dump them using the DEBUG() macro
void arch_dump_gp_csr(const char *pre, const ucontext_t *uc);
void arch_dump_fp_csr(const char *pre, const ucontext_t *uc);

// Implementation must let us trap on the *next* instruction after the
// current one in the ucontext.
// state points to a location where the implementation can
// stash state on a "set_trap" and then see it again on "reset_trap".
// If state==NULL, then the implementation should do the best it can
// If this happens, it is because of a surprise abort in Fpvm in which
// we cannot find the monitoring context of the thread.
void arch_set_trap(ucontext_t *uc, uint64_t *state);
// disable the trap for the *current* instruction
void arch_reset_trap(ucontext_t *uc, uint64_t *state);

// Implementation must allow us to clear all FP exceptions in the ucontext
void arch_clear_fp_exceptions(ucontext_t *uc);

// Implementation must allow us to mask and unmask FP traps in the ucontext
// The traps to use are set previously (see "trap_mask" above)
void arch_mask_fp_traps(ucontext_t *uc);
void arch_unmask_fp_traps(ucontext_t *uc);

// Implementation must allow us to get the FP rounding configuration from the
// hardware. This is opaque
fpvm_arch_round_config_t arch_get_machine_round_config(void);

// Implementation must allow us to get/set the FP rounding configuration
// of the ucontext.  This is opaque
fpvm_arch_round_config_t arch_get_round_config(ucontext_t *uc);
void arch_set_round_config(ucontext_t *uc, fpvm_arch_round_config_t config);

// Implementation must allow us to interogate the opaque rounding config
// to get at the IEEE rounding mode.
fpvm_arch_round_mode_t arch_get_round_mode(fpvm_arch_round_config_t config);
void arch_set_round_mode(fpvm_arch_round_config_t *config, fpvm_arch_round_mode_t mode);

// Implementation must allow us to interogate the opaque rounding config
// to get at the DAZ and FTZ features of the hardware, if they are supported
fpvm_arch_dazftz_mode_t arch_get_dazftz_mode(fpvm_arch_round_config_t *config);
void arch_set_dazftz_mode(fpvm_arch_round_config_t *config, fpvm_arch_dazftz_mode_t mode);

// Implementation must allow us to get at the raw FP and FP CSRs of the ucontext
// as well as the instruction pointer and stack pointer
void     arch_get_fp_csr(const ucontext_t *uc, arch_fp_csr_t *fpcsr);
void     arch_get_fp_csr_machine(arch_fp_csr_t *fpcsr);
void     arch_set_fp_csr(ucontext_t *uc, const arch_fp_csr_t *fpcsr);
void     arch_set_fp_csr_machine(const arch_fp_csr_t *fpcsr);
uint64_t arch_get_gp_csr(const ucontext_t *uc);
uint64_t arch_get_ip(const ucontext_t *uc);
void     arch_set_ip(ucontext_t *uc, const uint64_t ip);
uint64_t arch_get_sp(const ucontext_t *uc);


// fill in dest with up to min(size,instruction size) instruction bytes
// then return the number of number of bytes read, or negative on error
int arch_get_instr_bytes(const ucontext_t *uc, uint8_t *dest, int size);

// zero out all fpregs
void arch_zero_fpregs(const ucontext_t *uc);

// fpregs comes back with metadata filled out and data pointing to
// relevant part of ucontext
void arch_get_fpregs(const ucontext_t *uc, fpvm_arch_fpregs_t *fpregs);
void arch_set_fpregs(ucontext_t *uc, const fpvm_arch_fpregs_t *fpregs);

// similar, but if data is null, it only fills out the metadata
// if data is not null, it fills out both metadata and copies the data
void arch_get_fpregs_machine(fpvm_arch_fpregs_t *fpregs);
void arch_set_fpregs_machine(const fpvm_arch_fpregs_t *fpregs);

// gpregs comes back with metadata filled out and data pointing to
// relevant part of ucontext; if uc is null, then only metadata is returned
void arch_get_gpregs(const ucontext_t *uc, fpvm_arch_gpregs_t *gpregs);
void arch_set_gpregs(ucontext_t *uc, const fpvm_arch_gpregs_t *gpregs);

// Implementation is initialized at start of process.  It can
// veto by returning non-zero.   Implementation is also
// initialized/deinitialized on each thread.
int arch_process_init(void);
void arch_process_deinit(void);

int arch_thread_init(ucontext_t *uc);  // uc can be null (for aggregate mode)
void arch_thread_deinit(void);

// mcontext_t-access-specific stuff
#define MCTX_PC(mc) -1
#define MCTX_SP(mc) -1
#define MCTX_FPRS(mc) -1
#define MCTX_GPRS(mc) -1

// should be defined as the appropriate attributes
// for a function that will not touch floating point state
#define NO_TOUCH_FLOAT

#endif

#endif
