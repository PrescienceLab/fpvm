#ifdef __riscv

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

#define IS_FPR(r)  ((r) >= RISCV_REG_F0_32 && (r) <= RISCV_REG_F31_64)
// If your Capstone uses the unified naming:
// #define IS_FPR(r) ((r) >= RISCV_REG_F0 && (r) <= RISCV_REG_F31)

// If the V extension is on, vector regs are their own file:
#define IS_VREG(r) ((r) >= RISCV_REG_V0 && (r) <= RISCV_REG_V31)


// Linux riscv64 mcontext uses __gregs[32]: [0]=pc, [1..31]=x1..x31.
// We'll publish a flat 32-entry view where index n maps to xn,
// and PC goes to index 32 (or wherever your mcontext wrapper puts it).
#define MC_X(n) (n)    // x0..x31 → gregs[0..31] (after hiding the pc slot)
#define MC_PC   32

typedef int reg_map_entry_t[3]; // {greg_index, byte_off, size}

static reg_map_entry_t capstone_to_mcontext[RISCV_REG_ENDING] = {
    [0 ... RISCV_REG_ENDING - 1] = {REG_NONE, 0, 0},

    [RISCV_REG_X0]  = {REG_ZERO, 0, 8},     // hardwired zero
#define RV_GPR(n) [RISCV_REG_X##n] = {MC_X(n), 0, 8}
    RV_GPR(1),  RV_GPR(2),  RV_GPR(3),  RV_GPR(4),  RV_GPR(5),
    RV_GPR(6),  RV_GPR(7),  RV_GPR(8),  RV_GPR(9),  RV_GPR(10),
    RV_GPR(11), RV_GPR(12), RV_GPR(13), RV_GPR(14), RV_GPR(15),
    RV_GPR(16), RV_GPR(17), RV_GPR(18), RV_GPR(19), RV_GPR(20),
    RV_GPR(21), RV_GPR(22), RV_GPR(23), RV_GPR(24), RV_GPR(25),
    RV_GPR(26), RV_GPR(27), RV_GPR(28), RV_GPR(29), RV_GPR(30),
    RV_GPR(31),

    // PC is addressable as a register on RV (pseudo in most contexts)
    [RISCV_REG_PC] = {MC_PC, 0, 8},

    // no eflags, no NZCV — deliberately absent
};


static void compile_fp_ptr(fpvm_builder_t *b, cs_riscv_op *o, unsigned vector_offset) {
    // In the D extension, each F register is 64 bits — adjust if you're on Q (128b).
    const int fpr_size = 8;

    if (IS_FPR(o->reg)) {
        // Be tolerant of Capstone's F*_32 / F*_64 split:
        int idx;
        if (o->reg >= RISCV_REG_F0_64)      idx = o->reg - RISCV_REG_F0_64;
        else /* F*_32 */                    idx = o->reg - RISCV_REG_F0_32;
        fpvm_build_fpptr(b, fpr_size * idx + vector_offset);
    } else if (IS_VREG(o->reg)) {
        // RVV: vector stride depends on VLEN at runtime. You'll need a
        // vlen-aware stride rather than a compile-time constant.
        int idx = o->reg - RISCV_REG_V0;
        fpvm_build_fpptr(b, runtime_vlen_bytes() * idx + vector_offset);
    } else {
        abort();
    }
}


static void compile_gpr_ptr(fpvm_builder_t *b, riscv_reg r) {
    reg_map_entry_t *m = CAPSTONE_TO_MCONTEXT(r);
    if (MCREG(m) == REG_NONE) abort();

    if (MCREG(m) == REG_ZERO) {
        // x0 reads as zero. Push an immediate 0 address... but callers
        // expect a POINTER. Better: point at a read-only zero slot your
        // runtime maintains.
        fpvm_build_zero_ptr(b);    // add this helper if not present
        return;
    }
    uint16_t off = MCREG(m) * 8 + MCOFF(m);  // MCOFF always 0
    fpvm_build_mcptr(b, off);
}


static void compile_mem_operand(fpvm_builder_t *b, fpvm_inst_t *fi,
                                cs_riscv_op *o, long vector_offset) {
    riscv_op_mem *mo = &o->mem;

    // base is always present in a well-formed RV mem operand
    compile_gpr_ptr(b, mo->base);
    fpvm_build_ld64(b);

    if (mo->disp != 0) {
        fpvm_build_imm64(b, mo->disp);
        fpvm_build_iadd(b);
    }
    if (vector_offset != 0) {
        fpvm_build_imm64(b, vector_offset);
        fpvm_build_iadd(b);
    }
}


static void compile_operand(fpvm_builder_t *b, fpvm_inst_t *fi,
                            cs_riscv_op *o, unsigned vector_offset) {
    switch (o->type) {
      case RISCV_OP_REG:
        if (IS_FPR(o->reg) || IS_VREG(o->reg))
            compile_fp_ptr(b, o, vector_offset);
        else
            compile_gpr_ptr(b, o->reg);
        break;
      case RISCV_OP_IMM:
        fpvm_build_todo(b);
        break;
      case RISCV_OP_MEM:
        compile_mem_operand(b, fi, o, vector_offset);
        break;
      case RISCV_OP_INVALID:
      default:
        fpvm_build_todo(b);
        break;
    }
}


int fpvm_vm_riscv64_compile(fpvm_inst_t *fi) {
    cs_insn *inst = (cs_insn *)fi->internal;
    cs_detail *det = inst->detail;
    cs_riscv *rv = &det->riscv;

    fpvm_builder_t *bp = malloc(sizeof(fpvm_builder_t));
    if (!bp) return -1;
    fpvm_builder_init(bp);

    int op_count = rv->op_count;
    op_t func = NULL;
    if      (fi->common->op_size == 4) func = vanilla_op_map[fi->common->op_type][0];
    else if (fi->common->op_size == 8) func = op_map[fi->common->op_type][1];
    else { ASSERT(0); return -1; }

    // RVV length is runtime — for scalar F/D, count is always 1.
    int count = 1;
    int step  = fi->common->op_size;

    for (int vl = 0; vl < count; vl++) {
        switch (fi->common->op_type) {
          case FPVM_OP_ADD: case FPVM_OP_SUB:
          case FPVM_OP_MUL: case FPVM_OP_DIV:
          case FPVM_OP_MIN: case FPVM_OP_MAX:
            // All F/D scalar arith is 3-operand: fadd.d fd, fs1, fs2
            compile_operand(bp, fi, &rv->operands[2], vl * step); // fs2
            compile_operand(bp, fi, &rv->operands[1], vl * step); // fs1
            compile_operand(bp, fi, &rv->operands[0], vl * step); // fd
            fpvm_build_call2s1d(bp, func);
            break;

          case FPVM_OP_SQRT:
            // fsqrt.d fd, fs1 — 2 operands
            compile_operand(bp, fi, &rv->operands[1], vl * step);
            compile_operand(bp, fi, &rv->operands[0], vl * step);
            fpvm_build_call1s1d(bp, func);
            break;

          case FPVM_OP_MADD:
            // fmadd.d fd, fs1, fs2, fs3 — always 4 operands
            compile_operand(bp, fi, &rv->operands[3], vl * step);
            compile_operand(bp, fi, &rv->operands[2], vl * step);
            compile_operand(bp, fi, &rv->operands[1], vl * step);
            compile_operand(bp, fi, &rv->operands[0], vl * step);
            fpvm_build_call3s1d(bp, func);
            break;

          case FPVM_OP_CMP:
          case FPVM_OP_UCMP:
            // feq.d / flt.d / fle.d — writes a GPR, NOT flags.
            // operands[0] = xd (GPR), operands[1] = fs1, operands[2] = fs2
            fpvm_build_clspecial(bp);
            compile_operand(bp, fi, &rv->operands[2], 0);  // fs2
            compile_operand(bp, fi, &rv->operands[1], 0);  // fs1
            compile_operand(bp, fi, &rv->operands[0], 0);  // xd — GPR ptr
            fpvm_build_call2s1d(bp, func);
            // NOTE: the helper you pick here should write 0/1 to the
            // destination, not flag bits. You'll want a separate entry
            // in op_map for RISC-V semantics.
            break;

          case FPVM_OP_CMPXX:
            // RISC-V has no "compare to FP mask" instruction in scalar F/D.
            // This case only fires for RVV mask-producing compares
            // (vmfeq.vv, vmflt.vv, etc.), which target a v-register.
            fpvm_build_clspecial(bp);
            fpvm_build_setcti(bp, fi->compare);
            compile_operand(bp, fi, &rv->operands[2], vl * step);
            compile_operand(bp, fi, &rv->operands[1], vl * step);
            compile_operand(bp, fi, &rv->operands[0], vl * step);
            fpvm_build_call2s1d(bp, func);
            break;

          default: break;
        }
    }

    fpvm_build_done(bp);
    fi->codegen = bp;
    return 0;
}

#endif  // __riscv