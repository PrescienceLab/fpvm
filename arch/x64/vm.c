#ifdef __amd64__


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

// original FP
#define IS_X87(r) ((r) >= X86_REG_ST0 && (r) <= X86_REG_ST7)
// internal 80 bit x87 register access
#define IS_X87_80(r) ((r) >= X86_REG_FP0 && (r) <= X86_REG_FP7)
// first vector featureset, overloading x87
#define IS_MMX(r) ((r) >= X86_REG_MM0 && (r) <= X86_REG_MM7)
// second vector featureset (SSE+)
#define IS_XMM(r) ((r) >= X86_REG_XMM0 && (r) <= X86_REG_XMM31)
#define IS_YMM(r) ((r) >= X86_REG_YMM0 && (r) <= X86_REG_YMM31)
#define IS_ZMM(r) ((r) >= X86_REG_ZMM0 && (r) <= X86_REG_ZMM31)
// these registers allow masking of individual vector elements
// in AVX512 instructions
#define IS_AVX512_MASK(r) ((r) >= X86_REG_K0 && (r) <= X86_REG_K7)

#define IS_NORMAL_FPR(r) (IS_XMM(r) || IS_YMM(r) || IS_ZMM(r))

#define IS_FPR(r) (IS_NORMAL_FPR(r) || IS_AVX512_MASK(r) || IS_X87(r) || IS_X87_80(r) || IS_MMX(r))



// HACK
FPVM_NUMBER_SYSTEM_INIT();

// the map is from capstone regnum to mcontext gpr, offset (assuming
// little endian), size
typedef int reg_map_entry_t[3];


// TODO: unify this into one place
static reg_map_entry_t capstone_to_mcontext[X86_REG_ENDING] = {

#define REG_ZERO -1
#define REG_NONE -2

    // base (undefined)
    [0 ... X86_REG_ENDING - 1] = {REG_NONE, 0, 0},

    [X86_REG_AH] = {REG_RAX, 1, 1},
    [X86_REG_AL] = {REG_RAX, 0, 1},
    [X86_REG_AX] = {REG_RAX, 0, 2},
    [X86_REG_EAX] = {REG_RAX, 0, 4},
    [X86_REG_RAX] = {REG_RAX, 0, 8},

    [X86_REG_BH] = {REG_RBX, 1, 1},
    [X86_REG_BL] = {REG_RBX, 0, 1},
    [X86_REG_BX] = {REG_RBX, 0, 2},
    [X86_REG_EBX] = {REG_RBX, 0, 4},
    [X86_REG_RBX] = {REG_RBX, 0, 8},

    [X86_REG_CH] = {REG_RCX, 1, 1},
    [X86_REG_CL] = {REG_RCX, 0, 1},
    [X86_REG_CX] = {REG_RCX, 0, 2},
    [X86_REG_ECX] = {REG_RCX, 0, 4},
    [X86_REG_RCX] = {REG_RCX, 0, 8},

    [X86_REG_DH] = {REG_RDX, 1, 1},
    [X86_REG_DL] = {REG_RDX, 0, 1},
    [X86_REG_DX] = {REG_RDX, 0, 2},
    [X86_REG_EDX] = {REG_RDX, 0, 4},
    [X86_REG_RDX] = {REG_RDX, 0, 8},

    [X86_REG_SIL] = {REG_RSI, 0, 1},
    [X86_REG_SI] = {REG_RSI, 0, 2},
    [X86_REG_ESI] = {REG_RSI, 0, 4},
    [X86_REG_RSI] = {REG_RSI, 0, 8},

    [X86_REG_DIL] = {REG_RDI, 0, 1},
    [X86_REG_DI] = {REG_RDI, 0, 2},
    [X86_REG_EDI] = {REG_RDI, 0, 4},
    [X86_REG_RDI] = {REG_RDI, 0, 8},

    [X86_REG_SPL] = {REG_RSP, 0, 1},
    [X86_REG_SP] = {REG_RSP, 0, 2},
    [X86_REG_ESP] = {REG_RSP, 0, 4},
    [X86_REG_RSP] = {REG_RSP, 0, 8},

    [X86_REG_BPL] = {REG_RBP, 0, 1},
    [X86_REG_BP] = {REG_RBP, 0, 2},
    [X86_REG_EBP] = {REG_RBP, 0, 4},
    [X86_REG_RBP] = {REG_RBP, 0, 8},

#define SANE_GPR(x)                                                       \
  [X86_REG_##x##B] = {REG_##x, 0, 1}, [X86_REG_##x##W] = {REG_##x, 0, 2}, \
  [X86_REG_##x##D] = {REG_##x, 0, 4}, [X86_REG_##x] = {REG_##x, 0, 8}

    SANE_GPR(R8),
    SANE_GPR(R9),
    SANE_GPR(R10),
    SANE_GPR(R11),
    SANE_GPR(R12),
    SANE_GPR(R13),
    SANE_GPR(R14),
    SANE_GPR(R15),

    [X86_REG_IP] = {REG_RIP, 0, 2},
    [X86_REG_EIP] = {REG_RIP, 0, 4},
    [X86_REG_RIP] = {REG_RIP, 0, 8},

    [X86_REG_FS] = {REG_CSGSFS, 4, 2},
    [X86_REG_GS] = {REG_CSGSFS, 2, 2},

    [X86_REG_EFLAGS] = {REG_EFL, 0, 4},

    // pseudo reg that is zero
    [X86_REG_EIZ] = {REG_ZERO, 0, 4},
    [X86_REG_RIZ] = {REG_ZERO, 0, 8},

};

#define CAPSTONE_TO_MCONTEXT(r) (&(capstone_to_mcontext[r]))
#define MCREG(m) ((*m)[0])
#define MCOFF(m) ((*m)[1])
#define MCSIZE(m) ((*m)[2])


// Consider fp_ptr_offset instruction
static void compile_fp_ptr(fpvm_builder_t *b, cs_x86_op *o, unsigned vector_offset) {
  // TODO: figure this out.
  const int fpr_size = 16;

  if (IS_NORMAL_FPR(o->reg)) {
    if (IS_XMM(o->reg)) {
      fpvm_build_fpptr(b, fpr_size * (o->reg - X86_REG_XMM0) + vector_offset);
    } else if (IS_YMM(o->reg)) {
      //
      fpvm_build_fpptr(b, fpr_size * (o->reg - X86_REG_YMM0) + vector_offset);
    } else if (IS_ZMM(o->reg)) {
      //
      fpvm_build_fpptr(b, fpr_size * (o->reg - X86_REG_ZMM0) + vector_offset);
    }
  } else {
    abort();
  }
}


static void compile_gpr_ptr(fpvm_builder_t *b, x86_reg r) {
  reg_map_entry_t *m = CAPSTONE_TO_MCONTEXT(r);

  if (MCREG(m) == REG_NONE || MCREG(m) == REG_ZERO) {
    // ERROR("No mapping of %s!\n", reg_name(o->reg));
    abort();
  }

  uint16_t off = MCREG(m) * 8 + MCOFF(m);
  fpvm_build_mcptr(b, off);

}


static void compile_mem_operand(fpvm_builder_t *b, fpvm_inst_t *fi, cs_x86_op *o, long vector_offset) {
  // push the base GPR, load it to get the address, then augment that value appropriately
  // steps:
  x86_op_mem *mo = &o->mem;

  // x86_reg segment; ///< segment register (or X86_REG_INVALID if irrelevant)
  // x86_reg base;	///< base register (or X86_REG_INVALID if irrelevant)
  // x86_reg index;	///< index register (or X86_REG_INVALID if irrelevant)
  // int scale;	///< scale for index register
  // int64_t disp;	///< displacement value

  if (mo->base != X86_REG_INVALID) {
    //
    // PAD: again these mappings into the mcontext must be correct
    // for this to work.
    // and capstone better not use some out of range psuedoregister
    compile_gpr_ptr(b, mo->base);
    fpvm_build_ld64(b);

    if (mo->base == X86_REG_RIP) {
      // for PC relative, it is the address of the next instruction that matters
      // so we need to add the instruction length to it
      fpvm_build_imm8(b,fi->length);
      fpvm_build_iadd(b);
    }

    /* reg_map_entry_t *m = CAPSTONE_TO_MCONTEXT(mo->base); */
    /* addr += fr->mcontext->gregs[MCREG(m)]; */
    /* // in rip-relative mode, rip is the address of the next instruction */
    /* // rip can only used for the base register, which is why this code */
    /* // does not exist elsewhere */
    /* if (MCREG(m) == REG_RIP) { */
    /*   addr += fi->length; */
    /* } */
  } else {
    // PAD: this is probably OK, it just means there is no base register
  }

  if (mo->index != X86_REG_INVALID) {
    // reg_map_entry_t *m = CAPSTONE_TO_MCONTEXT(mo->index);
    // addr += fr->mcontext->gregs[MCREG(m)] * mo->scale;  // assuming scale is not shift amount
  } else {
    // PAD: this is probably OK, it just means there is no index regiser
  }

  // if the displacement is nonzero, add it
  if (mo->disp != 0) {
    fpvm_build_imm64(b, mo->disp);
    fpvm_build_iadd(b);
  }

  if (vector_offset != 0) {
    fpvm_build_imm64(b, vector_offset);
    fpvm_build_iadd(b);
  }
}


// given an x86 operand, create the bytecode that leaves a pointer to the intended data on TOS
static void compile_operand(
    fpvm_builder_t *b, fpvm_inst_t *fi, cs_x86_op *o, unsigned vector_offset) {
  switch (o->type) {
    case X86_OP_REG: {
      if (IS_FPR(o->reg)) {
        compile_fp_ptr(b, o, vector_offset);
      } else {
        // TODO: assert vector_offset is zero
        compile_gpr_ptr(b, o->reg);
      }
      break;
    }

    case X86_OP_IMM:
      fpvm_build_todo(b);
      break;

    case X86_OP_MEM:
      compile_mem_operand(b, fi, o, vector_offset);
      break;

    case X86_OP_INVALID:
      fpvm_build_todo(b);
      break;
  }
}

int fpvm_vm_x86_compile(fpvm_inst_t *fi) {
  DEBUG("x86 vm test: %p\n", fi);
  fpvm_decoder_decode_and_print_any_inst(fi->addr, stderr, "vm: ");


  cs_insn *inst = (cs_insn *)fi->internal;
  cs_detail *det = inst->detail;
  cs_x86 *x86 = &det->x86;


  fpvm_builder_t *bp = malloc(sizeof(fpvm_builder_t));

  if (!bp) {
    ERROR("failed to allocate builder\n");
    return -1;
  }

  
  fpvm_builder_init(bp);

  int op_count = x86->op_count;

  int lanes = 1;
  op_t func = NULL;
  if (fi->common->op_size == 4) {
    ERROR("Using vanilla op map for float binop %d\n",fi->common->op_type);
    func = vanilla_op_map[fi->common->op_type][0];
  } else if (fi->common->op_size == 8) {
    // TODO: this is for testing. Use op_map to enable NAN boxing
    //func = vanilla_op_map[fi->common->op_type][1];

    // op_map[FPVM_OP_CMP][1] → fp_ordered_compare_set_flags
    func = op_map[fi->common->op_type][1];
  } else {
    ERROR("Cannot handle binary instruction with op_size = %d for float binop %d\n", fi->common->op_size,fi->common->op_type);
    ASSERT(0);
    return -1;
  }

  int count = 1;
  int dest_step = 0, src_step = 0;

  if (fi->common->is_vector) {
    count = fi->operand_sizes[0] / fi->common->op_size;
    dest_step = fi->common->op_size;
    src_step = fi->common->op_size;  // PAD: these can technically be different - FIX FIX FIX
    DEBUG("Doing vector instruction - this might break (dest operand size=%lu common operand size=%lu computed count=%lu dest_step=%lu src_step=%lu)\n",fi->operand_sizes[0],fi->common->op_size,count,dest_step,src_step);
  } else {
    dest_step = fi->common->op_size;
    src_step = fi->common->op_size;
    DEBUG("Doing scalar instruction - (common operand size=%lu)\n",fi->common->op_size);
  }

  for (int vl = 0; vl < count; vl++) {
    switch (fi->common->op_type) {
      case FPVM_OP_ADD:
      case FPVM_OP_SUB:
      case FPVM_OP_MUL:
      case FPVM_OP_DIV:
      case FPVM_OP_MIN:
      case FPVM_OP_MAX:
        if (op_count == 2) {
          compile_operand(bp, fi, &x86->operands[1], vl * src_step);  // src2
          compile_operand(bp, fi, &x86->operands[0], vl * src_step);  // src1
          fpvm_build_dup(bp);                              // dest
          fpvm_build_call2s1d(bp, func);
        } else if (op_count == 3) {
          // 3 operand (dest != src1)
          compile_operand(bp, fi, &x86->operands[2], vl * src_step);  // src2
          compile_operand(bp, fi, &x86->operands[1], vl * src_step);  // src1
          compile_operand(bp, fi, &x86->operands[0], vl * dest_step);  // dest
          fpvm_build_call2s1d(bp, func);
        }
        break;
      case FPVM_OP_SQRT:
        compile_operand(bp, fi, &x86->operands[1], vl * src_step);  // src1
        compile_operand(bp, fi, &x86->operands[0], vl * dest_step);  // dest
        fpvm_build_call1s1d(bp, func);
        break;
      case FPVM_OP_MADD:
        compile_operand(bp, fi, &x86->operands[3], vl * src_step);  // src3
        compile_operand(bp, fi, &x86->operands[2], vl * src_step);  // src2
        compile_operand(bp, fi, &x86->operands[1], vl * src_step);  // src1
        compile_operand(bp, fi, &x86->operands[0], vl * dest_step);  // dest
        fpvm_build_call3s1d(bp, func);
        break;
      case FPVM_OP_CMPXX:
        fpvm_build_clspecial(bp);
        fpvm_build_setcti(bp, fi->compare);
        compile_operand(bp, fi, &x86->operands[1], vl * src_step);  // src2
        compile_operand(bp, fi, &x86->operands[0], vl * src_step);  // src1
        fpvm_build_dup(bp);                              // dest
        fpvm_build_call2s1d(bp, func);
        break;
      case FPVM_OP_CMP:
      case FPVM_OP_UCMP:
        fpvm_build_clspecial(bp);                    // clear vm.special

        compile_operand(bp, fi, &x86->operands[1], 0);   // src2  (bottom)
        compile_operand(bp, fi, &x86->operands[0], 0);   // src1
        fpvm_build_mcptr(bp, REG_EFL * 8);               // dest = &EFLAGS
        fpvm_build_dup(bp);                              // duplicate dest
        fpvm_build_setrflags(bp);                        // pop copy -> special.rflags

        fpvm_build_call2s1d(bp, func);                  // cmp_double / cmp_float
        break;
      default:
        break;
    }
  }

  /* for (int i = x86->op_count - 1; i >= 0; i--) { */
  /*   cs_x86_op *o = &x86->operands[i]; */
  /*   compile_operand(bp, fi, o, 0); */
  /* } */
  /* fpvm_build_dup(bp); */

  // if (fi->common->op_type == FPVM_OP_CMP || fi->common->op_type == FPVM_OP_UCMP) {
  //   DEBUG("Handling comparison instruction\n");


  //   fpvm_build_mcptr(bp, REG_EFL * 8);        // push &EFLAGS

  //   // (riscv) cmp - type of comparison (eg <, >, ==) - writes result in int register
  //   // (x86/arm) generic cmp - set rflag bits - also compare type of comparison (cmpxx) - writes float register
  //   compile_operand(bp, fi, &x86->operands[1], 0); // src2 pointer
  //   compile_operand(bp, fi, &x86->operands[0], 0); // src1 pointer

  //   // TODO: Use cmp_double instead of helper functions
  //   // op_map and call2s1d should be sitting in vm->special
  //   op_t func = op_map[fi->common->op_type][1];     // double version
  //   fpvm_build_call2s1d(bp, func);
  // } 

  fpvm_build_done(bp);  // Insert the 'done' instruction

  fi->codegen = bp;
  
  return 0;
}




#endif  // __amd64__
