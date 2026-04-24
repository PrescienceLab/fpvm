#ifdef __aarch64__

#include <fpvm/fpvm_common.h>
#include <fpvm/vm.h>
#include <fpvm/decoder.h>
#include <fpvm/emulator.h>
#include <fpvm/fpvm_common.h>

#include <fpvm/fp_ops.h>
#include <fpvm/number_system.h>
#include <fpvm/nan_boxing.h>
#include <fpvm/gc.h>

#include <capstone/capstone.h>

// 128-bit SIMD/FP — "V" view
#define IS_V(r)  ((r) >= ARM64_REG_V0 && (r) <= ARM64_REG_V31)
// element-width views (all alias V0..V31)
#define IS_Q(r)  ((r) >= ARM64_REG_Q0 && (r) <= ARM64_REG_Q31) // 128b
#define IS_D(r)  ((r) >= ARM64_REG_D0 && (r) <= ARM64_REG_D31) //  64b
#define IS_S(r)  ((r) >= ARM64_REG_S0 && (r) <= ARM64_REG_S31) //  32b
#define IS_H(r)  ((r) >= ARM64_REG_H0 && (r) <= ARM64_REG_H31) //  16b
#define IS_B(r)  ((r) >= ARM64_REG_B0 && (r) <= ARM64_REG_B31) //   8b

#define IS_FPR(r) (IS_V(r) || IS_Q(r) || IS_D(r) || IS_S(r) || IS_H(r) || IS_B(r))

FPVM_NUMBER_SYSTEM_INIT();

typedef int reg_map_entry_t[3]; // {greg_index, byte_off, size}

#define REG_ZERO -1
#define REG_NONE -2

// Linux arm64 mcontext_t:
//   unsigned long long fault_address;
//   unsigned long long regs[31];  // X0..X30
//   unsigned long long sp;
//   unsigned long long pc;
//   unsigned long long pstate;    // holds NZCV + rest
// We'll pretend gregs[0..30]=X0..X30, gregs[31]=SP, gregs[32]=PC, gregs[33]=PSTATE.
#define MC_X(n)    (n)
#define MC_SP      31
#define MC_PC      32
#define MC_PSTATE  33

static reg_map_entry_t capstone_to_mcontext[ARM64_REG_ENDING] = {
    [0 ... ARM64_REG_ENDING - 1] = {REG_NONE, 0, 0},

#define ARM_GPR(n)                                                 \
    [ARM64_REG_X##n] = {MC_X(n), 0, 8},                            \
    [ARM64_REG_W##n] = {MC_X(n), 0, 4}

    ARM_GPR(0),  ARM_GPR(1),  ARM_GPR(2),  ARM_GPR(3),
    ARM_GPR(4),  ARM_GPR(5),  ARM_GPR(6),  ARM_GPR(7),
    ARM_GPR(8),  ARM_GPR(9),  ARM_GPR(10), ARM_GPR(11),
    ARM_GPR(12), ARM_GPR(13), ARM_GPR(14), ARM_GPR(15),
    ARM_GPR(16), ARM_GPR(17), ARM_GPR(18), ARM_GPR(19),
    ARM_GPR(20), ARM_GPR(21), ARM_GPR(22), ARM_GPR(23),
    ARM_GPR(24), ARM_GPR(25), ARM_GPR(26), ARM_GPR(27),
    ARM_GPR(28), ARM_GPR(29), ARM_GPR(30),

    [ARM64_REG_SP]   = {MC_SP,    0, 8},
    [ARM64_REG_WSP]  = {MC_SP,    0, 4},
    [ARM64_REG_XZR]  = {REG_ZERO, 0, 8},
    [ARM64_REG_WZR]  = {REG_ZERO, 0, 4},

    // condition flags live inside PSTATE; we expose the whole word.
    [ARM64_REG_NZCV] = {MC_PSTATE, 0, 8},
};

// Consider fp_ptr_offset instruction
static void compile_fp_ptr(fpvm_builder_t *b, cs_arm64_op *o, unsigned vector_offset) {
  const int fpr_size = 16;

  int idx = -1;
  if      (IS_V(o->reg)) idx = o->reg - ARM64_REG_V0;
  else if (IS_Q(o->reg)) idx = o->reg - ARM64_REG_Q0;
  else if (IS_D(o->reg)) idx = o->reg - ARM64_REG_D0;
  else if (IS_S(o->reg)) idx = o->reg - ARM64_REG_S0;
  else if (IS_H(o->reg)) idx = o->reg - ARM64_REG_H0;
  else if (IS_B(o->reg)) idx = o->reg - ARM64_REG_B0;
  else abort();

  fpvm_build_fpptr(b, fpr_size * idx + vector_offset);
}


static void compile_gpr_ptr(fpvm_builder_t *b, arm64_reg r) {
    reg_map_entry_t *m = CAPSTONE_TO_MCONTEXT(r);
    if (MCREG(m) == REG_NONE || MCREG(m) == REG_ZERO) abort();
    // MCOFF is always 0 on ARM64 but we keep the formula to match x86 layout.
    uint16_t off = MCREG(m) * 8 + MCOFF(m);
    fpvm_build_mcptr(b, off);
}


static void compile_mem_operand(fpvm_builder_t *b, fpvm_inst_t *fi,
                                cs_arm64_op *o, long vector_offset) {
    arm64_op_mem *mo = &o->mem;

    // --- BASE ---
    if (mo->base != ARM64_REG_INVALID) {
        compile_gpr_ptr(b, mo->base);
        fpvm_build_ld64(b);
        // Unlike x86, there's no PC-relative addressing via the base reg.
        // PC-relative on ARM64 uses ADR/ADRP which decode as IMM operands,
        // not memory operands — so no rip-relative fixup needed here.
    } else {
        fpvm_build_imm64(b, 0);
    }

    // --- INDEX (with optional shift, not a multiplier!) ---
    if (mo->index != ARM64_REG_INVALID) {
        compile_gpr_ptr(b, mo->index);
        fpvm_build_ld64(b);

        // Capstone sets o->shift.type (ARM64_SFT_LSL/UXTW/SXTW/SXTX) and
        // o->shift.value. For plain LSL, shift.value is the log2 scale.
        if (o->ext == ARM64_EXT_SXTW || o->ext == ARM64_EXT_UXTW) {
            // index is the low 32 bits; sign/zero-extend it.
            fpvm_build_ext32(b, /*sign=*/o->ext == ARM64_EXT_SXTW);
        }
        if (o->shift.type == ARM64_SFT_LSL && o->shift.value != 0) {
            fpvm_build_imm64(b, o->shift.value);
            fpvm_build_ishl(b);     // shift-left, not multiply
        }
        fpvm_build_iadd(b);
    }

    // --- DISPLACEMENT ---
    if (mo->disp != 0) {
        fpvm_build_imm64(b, mo->disp);
        fpvm_build_iadd(b);
    }

    if (vector_offset != 0) {
        fpvm_build_imm64(b, vector_offset);
        fpvm_build_iadd(b);
    }

    // NOTE: pre/post-increment writeback (`[x0, #8]!` and `[x0], #8`)
    // needs to ALSO update the base register. You'd emit an extra
    // store-back sequence here, keyed on cs_arm64->writeback.
}


static void compile_operand(fpvm_builder_t *b, fpvm_inst_t *fi,
                            cs_arm64_op *o, unsigned vector_offset) {
    switch (o->type) {
      case ARM64_OP_REG:
        if (IS_FPR(o->reg))  compile_fp_ptr(b, o, vector_offset);
        else                 compile_gpr_ptr(b, o->reg);
        break;
      case ARM64_OP_IMM:
      case ARM64_OP_FP:     // e.g. fmov d0, #1.0 — encoded as FP immediate
        fpvm_build_todo(b); // materialize as a constant pointer
        break;
      case ARM64_OP_MEM:
        compile_mem_operand(b, fi, o, vector_offset);
        break;
      case ARM64_OP_CIMM:     // condition code immediate
      case ARM64_OP_REG_MRS:  // system register reads
      case ARM64_OP_REG_MSR:
      case ARM64_OP_PSTATE:
      case ARM64_OP_SYS:
      case ARM64_OP_PREFETCH:
      case ARM64_OP_BARRIER:
      default:
        fpvm_build_todo(b);
        break;
    }
}


int fpvm_vm_arm64_compile(fpvm_inst_t *fi) {
    cs_insn *inst = (cs_insn *)fi->internal;
    cs_detail *det = inst->detail;
    cs_arm64 *a64 = &det->arm64;

    fpvm_builder_t *bp = malloc(sizeof(fpvm_builder_t));
    if (!bp) return -1;
    fpvm_builder_init(bp);

    int op_count = a64->op_count;
    op_t func = NULL;

    if      (fi->common->op_size == 4) func = vanilla_op_map[fi->common->op_type][0];
    else if (fi->common->op_size == 8) func = op_map[fi->common->op_type][1];
    else { ASSERT(0); return -1; }

    int count = fi->common->is_vector
        ? fi->operand_sizes[0] / fi->common->op_size : 1;
    int step  = fi->common->op_size;

    for (int vl = 0; vl < count; vl++) {
        switch (fi->common->op_type) {
          case FPVM_OP_ADD: case FPVM_OP_SUB:
          case FPVM_OP_MUL: case FPVM_OP_DIV:
          case FPVM_OP_MIN: case FPVM_OP_MAX:
            // ARM64 FP arithmetic is almost always 3-operand (Fd, Fn, Fm).
            // 2-operand forms don't exist for FADD/FSUB/FMUL/FDIV.
            compile_operand(bp, fi, &a64->operands[2], vl * step); // src2
            compile_operand(bp, fi, &a64->operands[1], vl * step); // src1
            compile_operand(bp, fi, &a64->operands[0], vl * step); // dest
            fpvm_build_call2s1d(bp, func);
            break;

          case FPVM_OP_SQRT:
            // FSQRT Fd, Fn — always 2 operands
            compile_operand(bp, fi, &a64->operands[1], vl * step);
            compile_operand(bp, fi, &a64->operands[0], vl * step);
            fpvm_build_call1s1d(bp, func);
            break;

          case FPVM_OP_MADD:
            // FMADD Fd, Fn, Fm, Fa — 4 operands always
            compile_operand(bp, fi, &a64->operands[3], vl * step); // Fa
            compile_operand(bp, fi, &a64->operands[2], vl * step); // Fm
            compile_operand(bp, fi, &a64->operands[1], vl * step); // Fn
            compile_operand(bp, fi, &a64->operands[0], vl * step); // Fd
            fpvm_build_call3s1d(bp, func);
            break;

          case FPVM_OP_CMPXX:
            // FCMEQ/FCMGT/etc. — writes an FP register with all-1s mask
            fpvm_build_clspecial(bp);
            fpvm_build_setcti(bp, fi->compare);
            compile_operand(bp, fi, &a64->operands[2], vl * step); // src2
            compile_operand(bp, fi, &a64->operands[1], vl * step); // src1
            compile_operand(bp, fi, &a64->operands[0], vl * step); // dest (FP reg)
            fpvm_build_call2s1d(bp, func);
            break;

          case FPVM_OP_CMP:
          case FPVM_OP_UCMP:
            // FCMP / FCMPE — writes NZCV in PSTATE, no FP destination.
            fpvm_build_clspecial(bp);
            compile_operand(bp, fi, &a64->operands[1], 0);     // src2
            compile_operand(bp, fi, &a64->operands[0], 0);     // src1
            // Destination is NZCV — pointer to PSTATE slot.
            fpvm_build_mcptr(bp, MC_PSTATE * 8);
            fpvm_build_dup(bp);
            fpvm_build_setnzcv(bp);                            // was setrflags
            fpvm_build_call2s1d(bp, func);
            break;

          default: break;
        }
    }

    fpvm_build_done(bp);
    fi->codegen = bp;
    return 0;
}

#endif  // __aarch64__