#ifndef __RISCV64
#define __RISCV64

#define EXC_FLOATING_POINT 0x18
#define EXC_INSTRUCTION_STEP 0x19

typedef union {
  uint64_t val;
  struct {
    uint8_t nx : 1;  // detected rounding
    uint8_t uf : 1;  // detected underflow
    uint8_t of : 1;  // detected overflow (infinity)
    uint8_t dz : 1;  // detected divide by zero
    uint8_t nv : 1;  // detected invalid (nan)
    uint8_t rm : 3;  // rounding mode
    // 000 = RNE round to nearest, ties to even
    // 001 = RTZ round toward zero
    // 010 = RDN round down (towards -inf)
    // 011 = RUP round up (towards +inf)
    // 100 = RMM round to nearest, ties to maximum magnitude
    // 101 = reserved
    // 110 = reserved
    // 111 = DYN dynamic (chosen by instructions rm field?)
    uint32_t res1 : 24;  // reserved, zero

    // our CURRENTLY BOGUS magical additional controls
    // these only work on a risc-v that has our trap extensions
    uint8_t nxe : 1;  // enable rounding traps  BOGUS
    uint8_t ufe : 1;  // enable underflow traps BOGUS
    uint8_t ofe : 1;  // enable overflow traps  BOGUS
    uint8_t dze : 1;  // enable divide by zero traps BOGUS
    uint8_t nve : 1;  // enable nan traps BOGUS
    uint32_t res2 : 27;
  } __attribute__((packed));
} __attribute__((packed)) arch_fp_csr_t;


#pragma GCC diagnostic ignored "-Wpacked-bitfield-compat"
#pragma GCC diagnostic pop

// actually does not exist on riscv
typedef uint64_t arch_gp_csr_t;


static inline uint64_t __attribute__((always_inline)) arch_cycle_count(void) {
#if 1
  uint64_t val;
  asm volatile("rdcycle %0" : "=r"(val));
  return val;
#else
  // fake it
#define FREQ_MHZ (2000UL)
  struct timeval t;

  if (gettimeofday(&t, 0) < 0) {
    return -1;
  } else {
    return ((((uint64_t)(t.tv_sec)) * 1000000UL) + ((uint64_t)(t.tv_usec))) / FREQ_MHZ;
  }
#endif
}

// the DENORM trap is NOT available on riscv, though we could add it...
// it's included here so that the user can ask about it via
// the special exception query interface
#define FE_DENORM 0x1000
void arch_clear_trap_mask(void);
void arch_set_trap_mask(int which);
void arch_reset_trap_mask(int which);


uint64_t arch_cycle_count(void);
void arch_get_machine_fp_csr(arch_fp_csr_t *f);
void arch_set_machine_fp_csr(const arch_fp_csr_t *f);

int arch_machine_supports_fp_traps(void);

void arch_config_machine_fp_csr_for_local(arch_fp_csr_t *old);

// detects only FE_DENORM (within the HW state)
int arch_have_special_fp_csr_exception(int which);

void arch_dump_gp_csr(const char *pre, const ucontext_t *uc);
void arch_dump_fp_csr(const char *pre, const ucontext_t *uc);

void arch_set_trap(ucontext_t *uc, uint64_t *state);
void arch_reset_trap(ucontext_t *uc, uint64_t *state);

void arch_clear_fp_exceptions(ucontext_t *uc);

void arch_mask_fp_traps(ucontext_t *uc);
void arch_unmask_fp_traps(ucontext_t *uc);

fpvm_arch_round_config_t arch_get_machine_round_config(void);

fpvm_arch_round_config_t arch_get_round_config(ucontext_t *uc);
void arch_set_round_config(ucontext_t *uc, fpvm_arch_round_config_t config);

fpvm_arch_round_mode_t arch_get_round_mode(fpvm_arch_round_config_t config);
void arch_set_round_mode(fpvm_arch_round_config_t *config, fpvm_arch_round_mode_t mode);

fpvm_arch_dazftz_mode_t arch_get_dazftz_mode(fpvm_arch_round_config_t *config);
void arch_set_dazftz_mode(fpvm_arch_round_config_t *config, fpvm_arch_dazftz_mode_t mode);


void     arch_get_fp_csr(const ucontext_t *uc, arch_fp_csr_t *fpcsr);
void     arch_get_fp_csr_machine(arch_fp_csr_t *fpcsr);
void     arch_set_fp_csr(ucontext_t *uc, const arch_fp_csr_t *fpcsr);
void     arch_set_fp_csr_machine(const arch_fp_csr_t *fpcsr);
uint64_t arch_get_gp_csr(const ucontext_t *uc);
uint64_t arch_get_ip(const ucontext_t *uc);
void     arch_set_ip(ucontext_t *uc, const uint64_t ip);
uint64_t arch_get_sp(const ucontext_t *uc);

int arch_get_instr_bytes(const ucontext_t *uc, uint8_t *dest, int size);

void arch_zero_fpregs(const ucontext_t *uc);

void arch_get_fpregs(const ucontext_t *uc, fpvm_arch_fpregs_t *fpregs);
void arch_set_fpregs(ucontext_t *uc, const fpvm_arch_fpregs_t *fpregs);

void arch_get_fpregs_machine(fpvm_arch_fpregs_t *fpregs);
void arch_set_fpregs_machine(const fpvm_arch_fpregs_t *fpregs);

void arch_get_gpregs(const ucontext_t *uc, fpvm_arch_gpregs_t *gpregs);
void arch_set_gpregs(ucontext_t *uc, const fpvm_arch_gpregs_t *gpregs);

int arch_process_init(void);
void arch_process_deinit(void);

int arch_thread_init(ucontext_t *uc);
void arch_thread_deinit(void);

#define MCTX_PC(mc) ((mc)->__gregs[REG_PC])
#define MCTX_SP(mc) ((mc)->__gregs[REG_SP])
#define MCTX_FPRS(mc) ((mc)->__fpregs.__d.__f)
#define MCTX_GPRS(mc) ((mc)->__gregs)

// intentionally empty
#define NO_TOUCH_FLOAT


#if CONFIG_TRAP_SHORT_CIRCUITING
int  arch_trap_short_circuiting_init(void);
void arch_trap_short_circuiting_deinit(void);

static inline void __attribute__((always_inline)) arch_trap_short_circuiting_kick_self(void) {
    // estep instruction
  __asm__ __volatile__(".insn 0x00300073\n\t");
}
#endif

#endif
