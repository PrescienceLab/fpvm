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

    ///Computational instructions
    [RISCV_INS_FADD_D] = {FPVM_OP_ADD, 0, 0, 8, 0},
    [RISCV_INS_FSUB_D] = {FPVM_OP_SUB, 0, 0, 8, 0},

    //Compare instructions
    [RISCV_INS_FEQ_D] = {FPVM_OP_ADD, 0, 0, 8, 0},
    [RISCV_INS_FLE_D] = {FPVM_OP_SUB, 0, 0, 8, 0},
    [RISCV_INS_FLT_D] = {FPVM_OP_ADD, 0, 0, 8, 0},

};

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
  //Just changed everything to 1 from 0. Not sure whether we have to do anything else. Can look into this later
  fi->is_simple_mov = 1;
  fi->is_gpr_mov = 1;
  fi->extend = FPVM_INST_ZERO_EXTEND;
  return 0;
}

static int decode_comparison(fpvm_inst_t *fi)
{
  //Haresh: I implemented this
  if (fi->common->op_type != FPVM_OP_CMPXX) {
    return 0;
  }

  cs_insn *inst = (cs_insn *)fi->internal;

  switch(inst->id){
    case RISCV_INS_FEQ_D:
      fi->compare = FPVM_INST_COMPARE_EQ;
      break;
    case RISCV_INS_FLE_D:
      fi->compare = FPVM_INST_COMPARE_LE;
      break;
    case RISCV_INS_FLT_D:
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
  cs_x86 *x86 = &det->x86;

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

  return 0;
}

// TODO:
int fpvm_memaddr_probe_readable_long(void *addr) {
  return 0;
}
