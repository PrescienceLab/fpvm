#define _GNU_SOURCE
#include <signal.h>
#include <ucontext.h>

#include <sys/syscall.h>
#include <unistd.h>

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include <fpvm/decoder.h>
#include <fpvm/fpvm_common.h>
#include <fpvm/vm.h>

#include <capstone/capstone.h>

static csh handle;

// SHOULD MOVE THIS SOMEWHERE BETTER
//
#define IS_FPR(r) \
  (((r) >= RISCV_REG_F0_32 && (r) <= RISCV_REG_F31_64))

// In capstone, the enum for the 64bit version of the register
// immediately follows the enum for the 32bit version.
// For example RISCV_REG_F4_32, then RISCV_REG_F4_64
// The following convoluted macros for finding the
// register index encode this, and compute the same index for both
// plus the relevant size.  In the example, "4" will get
// computed in both cases.
#define GET_FPR_INDEX(r) \
  (((r) - RISCV_REG_F0_32) / 2)

#define GET_FPR_SIZE(r) \
  (((r) - RISCV_REG_F0_32) % 2 == 0 ? 4 : 8)

#define GPR_SIZE 8

#define GET_GPR_INDEX(r) \
  ((r) - RISCV_REG_X0)

//
// This contains the mapping to our high-level
// interface
//
// fpvm_inst_common_t {
//   fpvm_op_t op_type;
//   int is_vector;     // is this a vector FP?
//   int has_mask;      // mask vector?
//   unsigned op_size;  // size of operands
//
//   dest_size is currently only meaningful for conversion (F2* or I2* or U2* or movsx/etc)
//   unsigned dest_size;  // size of destination operands in conversion
// }
fpvm_inst_common_t capstone_to_common[RISCV_INS_ENDING] = {
    [0 ... RISCV_INS_ENDING - 1] = {FPVM_OP_UNKNOWN, 0, 0, 0},

    // Computational Instructions
    [RISCV_INS_FADD_D] = {FPVM_OP_ADD, 0, 0, 8, 0},
    [RISCV_INS_FSUB_D] = {FPVM_OP_SUB, 0, 0, 8, 0},
    [RISCV_INS_FMUL_D] = {FPVM_OP_MUL, 0, 0, 8, 0},
    [RISCV_INS_FDIV_D] = {FPVM_OP_DIV, 0, 0, 8, 0},
    [RISCV_INS_FSQRT_D] = {FPVM_OP_SQRT, 0, 0, 8, 0},
    [RISCV_INS_FMIN_D] = {FPVM_OP_MIN, 0, 0, 8, 0},
    [RISCV_INS_FMAX_D] = {FPVM_OP_MAX, 0, 0, 8, 0},


    //Compare instructions
    [RISCV_INS_FEQ_D] = {FPVM_OP_CMPXX, 0, 0, 8, 0},
    [RISCV_INS_FLE_D] = {FPVM_OP_CMPXX, 0, 0, 8, 0},
    [RISCV_INS_FLT_D] = {FPVM_OP_CMPXX, 0, 0, 8, 0},

    
    // Fused Instructions 
    // (Matching x86 implementation of fused, so they might map to a different fused op)
    [RISCV_INS_FMADD_D] = {FPVM_OP_MADD, 0, 0, 8, 0},
    [RISCV_INS_FMSUB_D] = {FPVM_OP_MSUB, 0, 0, 8, 0},
    [RISCV_INS_FNMADD_D] = {FPVM_OP_NMSUB, 0, 0, 8, 0},
    [RISCV_INS_FNMSUB_D] = {FPVM_OP_NMADD, 0, 0, 8, 0},
};

static char* reg_name(riscv_reg reg) {
#define DO_REG(x) \
  case x:         \
    return #x;    \
    break;
  switch (reg) {
    DO_REG(RISCV_REG_X0);
    DO_REG(RISCV_REG_X1);
    DO_REG(RISCV_REG_X2);
    DO_REG(RISCV_REG_X3);
    DO_REG(RISCV_REG_X4);
    DO_REG(RISCV_REG_X5);
    DO_REG(RISCV_REG_X6);
    DO_REG(RISCV_REG_X7);
    DO_REG(RISCV_REG_X8);
    DO_REG(RISCV_REG_X9);
    DO_REG(RISCV_REG_X10);
    DO_REG(RISCV_REG_X11);
    DO_REG(RISCV_REG_X12);
    DO_REG(RISCV_REG_X13);
    DO_REG(RISCV_REG_X14);
    DO_REG(RISCV_REG_X15);
    DO_REG(RISCV_REG_X16);
    DO_REG(RISCV_REG_X17);
    DO_REG(RISCV_REG_X18);
    DO_REG(RISCV_REG_X19);
    DO_REG(RISCV_REG_X20);
    DO_REG(RISCV_REG_X21);
    DO_REG(RISCV_REG_X22);
    DO_REG(RISCV_REG_X23);
    DO_REG(RISCV_REG_X24);
    DO_REG(RISCV_REG_X25);
    DO_REG(RISCV_REG_X26);
    DO_REG(RISCV_REG_X27);
    DO_REG(RISCV_REG_X28);
    DO_REG(RISCV_REG_X29);
    DO_REG(RISCV_REG_X30);
    DO_REG(RISCV_REG_X31);
    DO_REG(RISCV_REG_F0_32);
    DO_REG(RISCV_REG_F0_64);
    DO_REG(RISCV_REG_F1_32);
    DO_REG(RISCV_REG_F1_64);
    DO_REG(RISCV_REG_F2_32);
    DO_REG(RISCV_REG_F2_64);
    DO_REG(RISCV_REG_F3_32);
    DO_REG(RISCV_REG_F3_64);
    DO_REG(RISCV_REG_F4_32);
    DO_REG(RISCV_REG_F4_64);
    DO_REG(RISCV_REG_F5_32);
    DO_REG(RISCV_REG_F5_64);
    DO_REG(RISCV_REG_F6_32);
    DO_REG(RISCV_REG_F6_64);
    DO_REG(RISCV_REG_F7_32);
    DO_REG(RISCV_REG_F7_64);
    DO_REG(RISCV_REG_F8_32);
    DO_REG(RISCV_REG_F8_64);
    DO_REG(RISCV_REG_F9_32);
    DO_REG(RISCV_REG_F9_64);
    DO_REG(RISCV_REG_F10_32);
    DO_REG(RISCV_REG_F10_64);
    DO_REG(RISCV_REG_F11_32);
    DO_REG(RISCV_REG_F11_64);
    DO_REG(RISCV_REG_F12_32);
    DO_REG(RISCV_REG_F12_64);
    DO_REG(RISCV_REG_F13_32);
    DO_REG(RISCV_REG_F13_64);
    DO_REG(RISCV_REG_F14_32);
    DO_REG(RISCV_REG_F14_64);
    DO_REG(RISCV_REG_F15_32);
    DO_REG(RISCV_REG_F15_64);
    DO_REG(RISCV_REG_F16_32);
    DO_REG(RISCV_REG_F16_64);
    DO_REG(RISCV_REG_F17_32);
    DO_REG(RISCV_REG_F17_64);
    DO_REG(RISCV_REG_F18_32);
    DO_REG(RISCV_REG_F18_64);
    DO_REG(RISCV_REG_F19_32);
    DO_REG(RISCV_REG_F19_64);
    DO_REG(RISCV_REG_F20_32);
    DO_REG(RISCV_REG_F20_64);
    DO_REG(RISCV_REG_F21_32);
    DO_REG(RISCV_REG_F21_64);
    DO_REG(RISCV_REG_F22_32);
    DO_REG(RISCV_REG_F22_64);
    DO_REG(RISCV_REG_F23_32);
    DO_REG(RISCV_REG_F23_64);
    DO_REG(RISCV_REG_F24_32);
    DO_REG(RISCV_REG_F24_64);
    DO_REG(RISCV_REG_F25_32);
    DO_REG(RISCV_REG_F25_64);
    DO_REG(RISCV_REG_F26_32);
    DO_REG(RISCV_REG_F26_64);
    DO_REG(RISCV_REG_F27_32);
    DO_REG(RISCV_REG_F27_64);
    DO_REG(RISCV_REG_F28_32);
    DO_REG(RISCV_REG_F28_64);
    DO_REG(RISCV_REG_F29_32);
    DO_REG(RISCV_REG_F29_64);
    DO_REG(RISCV_REG_F30_32);
    DO_REG(RISCV_REG_F30_64);
    DO_REG(RISCV_REG_F31_32);
    DO_REG(RISCV_REG_F31_64);
    default:
      return "UNKNOWN";
      break;
  }
}

static int decode_to_common(fpvm_inst_t *fi)
{
  cs_insn* inst = (cs_insn*)fi->internal;

  fi->length = inst->size;

  fi->common = &capstone_to_common[inst->id];

  if (fi->common->op_type == FPVM_OP_UNKNOWN) {
    // not an error, since this could be a sequence-ending instruction
    DEBUG("instruction decodes to unknown common op type\n");
    return -1;
  }

  return 0;
}

static int decode_move(fpvm_inst_t *fi)
{
  fi->is_simple_mov = 0;
  fi->is_gpr_mov = 0;
  fi->extend = FPVM_INST_ZERO_EXTEND;
  return 0;
}

static int decode_comparison(fpvm_inst_t *fi)
{
  if (fi->common->op_type != FPVM_OP_CMPXX) {
    return 0;
  }

  cs_insn *inst = (cs_insn *)fi->internal;

  switch(inst->id){
    case RISCV_INS_FEQ_D:
    case RISCV_INS_FEQ_S:
      fi->compare = FPVM_INST_COMPARE_EQ;
      break;
    case RISCV_INS_FLE_D:
    case RISCV_INS_FLE_S:
      fi->compare = FPVM_INST_COMPARE_LE;
      break;
    case RISCV_INS_FLT_D:
    case RISCV_INS_FLT_S:
      fi->compare = FPVM_INST_COMPARE_LT;
      break;
    default:
      ERROR("cmpxx operation but has no valid comparison type\n");
      return -1;
  }
  return -1;
}

int fpvm_decoder_init(void)
{
  if (cs_open(CS_ARCH_RISCV, CS_MODE_RISCV64, &handle) != CS_ERR_OK) {
    ERROR("Failed to open decoder\n");
    return -1;
  }
  if (cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK) {
    ERROR("Cannot enable detailed decode\n");
    return -1;
  }
  DEBUG("decoder initialized\n");
  return 0;
}

void fpvm_decoder_deinit(void)
{
  cs_close(&handle);
  DEBUG("decoder deinit\n");
}

void fpvm_decoder_free_inst(fpvm_inst_t *fi)
{
  DEBUG("decoder free inst at %p\n", fi);
  free(fi);
}



fpvm_inst_t *fpvm_decoder_decode_inst(void *addr)
{
  DEBUG("Decoding instruction at %p\n", addr);

  cs_insn *inst;

  size_t count = cs_disasm(handle, addr, 4, (uint64_t)addr, 1, &inst);
  if (count != 1) {
    ERROR("Failed to decode instruction (return=%lu, errno=%d)\n", count, cs_errno(handle));
    return 0;
  }

  fpvm_inst_t *fi = malloc(sizeof(*fi));
  if (!fi) {
    ERROR("Can't allocate instruction\n");
    return 0;
  }
  memset(fi, 0, sizeof(*fi));
  fi->addr = addr;
  fi->internal = inst; // stash a copy of the whole instruction

  if (decode_to_common(fi)) {
    DEBUG("Can't decode to common representation\n");
    fpvm_decoder_free_inst(fi);
    return 0;
  }

  if (decode_move(fi)) {
    DEBUG("Can't decode move info\n");
    fpvm_decoder_free_inst(fi);
    return 0;
  }

  if (decode_comparison(fi)) {
    DEBUG("Can't decode comparison info\n");
    fpvm_decoder_free_inst(fi);
    return 0;
  }

  return fi;
}

int  fpvm_decoder_decode_and_print_any_inst(void *addr, FILE *out, char *prefix)
{
  cs_insn *inst;
  int len;

  //  DEBUG("Decoding instruction for print at %p\n", addr);

  size_t count = cs_disasm(handle, addr, 16, (uint64_t)addr, 1, &inst);

  if (count != 1) {
    ERROR("Failed to decode instruction for print (return=%lu, errno=%d)\n", count, cs_errno(handle));
    return -1;
  }

  fprintf(out, "%s%s\t\t%s (%u bytes)\n", prefix, inst->mnemonic, inst->op_str, inst->size);

  len = inst->size;

  cs_free(inst, 1);

  return len;

}

void fpvm_decoder_get_inst_str(fpvm_inst_t *fi, char *buf, int len) {
  cs_insn *inst = (cs_insn *)fi->internal;

  snprintf(buf, len, "%s %s", inst->mnemonic, inst->op_str);
}

// after this function is complete, every operand pointer in
// fi will be pointing to the relavent memory location or a
// a field (register snapshot) in fr.
int fpvm_decoder_bind_operands(fpvm_inst_t *fi, fpvm_regs_t *fr) {
  cs_insn *inst = (cs_insn *)fi->internal;
  cs_detail *det = inst->detail;
  // 
  // typedef struct cs_riscv {
  // 	// Does this instruction need effective address or not. <====== What does this mean????
  // 	bool need_effective_addr;
  // 	uint8_t op_count;
  // 	cs_riscv_op operands[NUM_RISCV_OPS];
  // } cs_riscv;
  //
  cs_riscv *riscv = &det->riscv;

  // operand sizes for memory operands cannot be determined
  // trivially, so the idea here is to make memory operands
  // correspond to the largest operand size we encounter
  // in the instruction.   This is done in two passes
  uint8_t max_operand_size=0;
#define UPDATE_MAX_OPERAND_SIZE(s) max_operand_size = ((s)>max_operand_size) ? (s) : max_operand_size;

  int i;

  DEBUG("binding instruction to mcontext=%p fprs=%p fpr_size=%u\n", fr->mcontext, fr->fprs,
      fr->fpr_size);

  if (fi->common->op_type == FPVM_OP_CMP || fi->common->op_type == FPVM_OP_UCMP) {
    // fi->side_effect_addrs[0] = (void *)(uint64_t *)&fr->mcontext->__gregs[REG_EFL];
    // PAD: DO WE HANDLE SIDE EFFECTS IN COMPARES CORRECTLY?
    // CMP/UCMP put their result in the rflags register
    // WHAT ABOUT OTEHR SIDE EFFECTING INSTRUCTIONS?
    //
    // PAD: WE DO NOT CURRENTLY HAVE THE EMULATED INSTRUCTION
    // TOUCH THE MXCSR register (these are the condition codes for floating
    // point We must eventually emulate these, but note that we must mask out
    // any manipulation of the control bits since we use those to invoke FPVM
    // handle MXCSR LATER FIX FIX FIX
    //   fi->side_effect_addrs[1] = &fr->mcontext->gregs[REG_MXCSR];
  }

  fi->operand_count = 0;

  for (i=0; i < riscv->op_count; i++) {
    DEBUG("Binding operand #%d\n", i);
    cs_riscv_op *o = &riscv->operands[i];

    switch (o->type) {

      case RISCV_OP_REG:
        if (IS_FPR(o->reg)) {
          fi->operand_addrs[fi->operand_count] = fr->fprs + (fr->fpr_size * GET_FPR_INDEX(o->reg)); // x2 because Capstone stores 32/64 registers side by side in enum
          fi->operand_sizes[fi->operand_count] = GET_FPR_SIZE(o->reg);

          UPDATE_MAX_OPERAND_SIZE(fi->operand_sizes[fi->operand_count]);
          DEBUG("Mapped FPR %s of value %lf to %p (size: %d bytes)\n", reg_name(o->reg), *((double*)fi->operand_addrs[fi->operand_count]),
              fi->operand_addrs[fi->operand_count], fi->operand_sizes[fi->operand_count]);
        }
        else {
          // Are we assuming RISCV64???
          fi->operand_addrs[fi->operand_count] = fr->mcontext->__gregs + (64 * GET_GPR_INDEX(o->reg));
          fi->operand_sizes[fi->operand_count] = GPR_SIZE;

          UPDATE_MAX_OPERAND_SIZE(fi->operand_sizes[fi->operand_count]);
          DEBUG("Mapped GPR %s to %p (size: %d bytes)\n", reg_name(o->reg),
              fi->operand_addrs[fi->operand_count], fi->operand_sizes[fi->operand_count]);
        }
        fi->operand_count++;

      break;

      case RISCV_OP_IMM:
        fi->operand_addrs[fi->operand_count] = &o->imm;
        fi->operand_sizes[fi->operand_count] = 0;
        // Capstone doesn't expose size in RISC-V it seems, set to 0 for now and it will be updated
        // to max_operand_size
	      UPDATE_MAX_OPERAND_SIZE(fi->operand_sizes[fi->operand_count]);
        fi->operand_count++;
      break;

      case RISCV_OP_MEM:
      // riscv seems to only have base + offset memory addressing available 
        riscv_op_mem *mo = &o->mem;

        //Calculate address using offset/displacement + base
        uint64_t addr = mo->disp;
         if (mo->base != RISCV_REG_INVALID) {
          addr += fr->mcontext->__gregs[GET_GPR_INDEX(mo->base)];
        }

        fi->operand_addrs[fi->operand_count] = (void *)addr;


        // Need to double check if this is the correct way to get the size for riscv. Just copied arm
        fi->operand_sizes[fi->operand_count] = 0;
        UPDATE_MAX_OPERAND_SIZE(fi->operand_sizes[fi->operand_count]);
        fi->operand_count++;
      break;

      default:
        DEBUG("Operand type is invalid\n");
    }

  }

  return 0;
}

// TODO:
int fpvm_memaddr_probe_readable_long(void *addr) {
  return 0;
}
