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
// This contains the mapping to our high-level interface
//
// TODO:
//    Size of 1 for now, but expand to ARM64_INS_ENDING
//    once we are ready...
fpvm_op_t capstone_to_common[ARM64_INS_ENDING] = {
  [ARM64_INS_FADD] = FPVM_OP_ADD,
  [ARM64_INS_FSUB] = FPVM_OP_SUB,
  [ARM64_INS_FMUL] = FPVM_OP_MUL,
  [ARM64_INS_FDIV] = FPVM_OP_DIV,
  [ARM64_INS_FSQRT] = FPVM_OP_SQRT,
  [ARM64_INS_FMOV] = FPVM_OP_MOVE,

  // comparison instructions
  [ARM64_INS_FCMP] = FPVM_OP_CMP,
  [ARM64_INS_FCMPE] = FPVM_OP_CMP,

  // neon comparison instructions
  [ARM64_INS_CMEQ] = FPVM_OP_CMPXX,
  [ARM64_INS_FCMEQ] = FPVM_OP_CMPXX,
  [ARM64_INS_CMGE] = FPVM_OP_CMPXX,
  [ARM64_INS_FCMGE] = FPVM_OP_CMPXX,
  [ARM64_INS_CMGT] = FPVM_OP_CMPXX,
  [ARM64_INS_FCMGT] = FPVM_OP_CMPXX,
  [ARM64_INS_CMLE] = FPVM_OP_CMPXX,
  [ARM64_INS_FCMLE] = FPVM_OP_CMPXX,
  [ARM64_INS_CMLT] = FPVM_OP_CMPXX,
  [ARM64_INS_FCMLT] = FPVM_OP_CMPXX,
  //[ARM64_INS_FCMNE] = FPVM_OP_CMPXX,
  //[ARM64_INS_FACGE] = FPVM_OP_CMPXX,
  //[ARM64_INS_FACGT] = FPVM_OP_CMPXX,

  // conversion instructions
  // side note: may be need more instruction specific 
  // conversion operations (e.g. rounding, saturation)?

  // float to float conversion
  [ARM64_INS_FCVT] = FPVM_OP_F2F,
  [ARM64_INS_FCVTL] = FPVM_OP_F2F, // lower half
  [ARM64_INS_FCVTL2] = FPVM_OP_F2F, // upper half
  [ARM64_INS_FCVTN] = FPVM_OP_F2F,
  [ARM64_INS_FCVTN2] = FPVM_OP_F2F,
  [ARM64_INS_FCVTXN] = FPVM_OP_F2F,
  [ARM64_INS_FCVTXN2] = FPVM_OP_F2F,
  //[ARM64_INS_FCVTX] = FPVM_OP_F2F,

  // float to integer conversion
  [ARM64_INS_FCVTAS] = FPVM_OP_F2I,
  [ARM64_INS_FCVTAU] = FPVM_OP_F2U,
  [ARM64_INS_FCVTMS] = FPVM_OP_F2I,
  [ARM64_INS_FCVTMU] = FPVM_OP_F2U,
  [ARM64_INS_FCVTNS] = FPVM_OP_F2I,
  [ARM64_INS_FCVTNU] = FPVM_OP_F2U,
  [ARM64_INS_FCVTPS] = FPVM_OP_F2I,
  [ARM64_INS_FCVTPU] = FPVM_OP_F2U,
  [ARM64_INS_FCVTZS] = FPVM_OP_F2I,
  [ARM64_INS_FCVTZU] = FPVM_OP_F2U,

  // integer to float conversion
  [ARM64_INS_SCVTF] = FPVM_OP_I2F,
  [ARM64_INS_UCVTF] = FPVM_OP_U2F,

};

// Checks the sizes of dest and op sizes, uses the string
// to check each operand, don't know a better way of doing it
static int check_dest_and_op_sizes(fpvm_inst_t *fi, cs_insn *inst) {
  char delimiter[] = ", ";
  char* token;

  token = strtok(inst->op_str, delimiter);
  bool dest = true;

  // iterate through each operand
  while(token != NULL){
    if (strstr(token, ".16b")){
      if(dest) fi->common->dest_size = 1;
      else fi->common->op_size = 1;
    } 
    else if (strstr(token, ".8h")){
      if(dest) fi->common->dest_size = 2;
      else fi->common->op_size = 2;
    } 
    else if (strstr(token, ".4s")){
      if(dest) fi->common->dest_size = 4;
      else fi->common->op_size = 4;
    } 
    else if (strstr(token, ".2d")){
      if(dest) fi->common->dest_size = 8;
      else fi->common->op_size = 8;
    }
    else if (strstr(token, " s")) {
      if(dest) fi->common->dest_size = 4;
      else fi->common->op_size = 4;
    }
    else if (strstr(token, " d")){
      if(dest) fi->common->dest_size = 8;
      else fi->common->op_size = 8;
    }
    else {
      ERROR("invalid operand\n");
      return -1;
    }
    token = strtok(NULL, delimiter);
    dest = false;
  }

  return 0;
}

// Set rounding mode for f2i conversion 
static int check_round_mode(fpvm_inst_t *fi ,cs_insn *inst) {
  switch(inst->id){
    case ARM64_INS_FCVTAS:
    case ARM64_INS_FCVTAU:
      fi->round_mode = FPVM_ROUND_NEAREST;
      break;
    case ARM64_INS_FCVTMS:
    case ARM64_INS_FCVTMU:
      fi->round_mode = FPVM_ROUND_NEGATIVE;
      break;
    case ARM64_INS_FCVTNS:
    case ARM64_INS_FCVTNU:
      // ??? not sure what mode this would be
      break;
    case ARM64_INS_FCVTPS:
    case ARM64_INS_FCVTPU:
      fi->round_mode = FPVM_ROUND_POSITIVE;
      break;
    case ARM64_INS_FCVTZS:
    case ARM64_INS_FCVTZU:
      fi->round_mode = FPVM_ROUND_ZERO;
      break;
    default:
      return 0;
  }

  return 0;
}

static int decode_to_common(fpvm_inst_t *fi) {
  cs_insn *inst = (cs_insn *)fi->internal;

  fi->addr = (void *)inst->address;
  fi->length = inst->size;

  fpvm_inst_common_t* common = (fpvm_inst_common_t*)malloc(sizeof(fpvm_inst_common_t));
  fi->common = common; 
  memset(fi->common, 0, sizeof(*fi->common));
  fi->common->op_type = capstone_to_common[inst->id];

  cs_detail *detail = inst->detail;
  cs_arm64 *arm64 = &detail->arm64;

  // determine whether it's vector or scalar
  cs_arm64_op *op = &arm64->operands[1];
  if (op->reg >= ARM64_REG_S0 && op->reg <= ARM64_REG_S31) {
      DEBUG("Operand is scalar float (32-bit)\n");
  } else if (op->reg >= ARM64_REG_D0 && op->reg <= ARM64_REG_D31) {
      DEBUG("Operand is scalar double (64-bit)\n");
  } else if (op->reg >= ARM64_REG_V0 && op->reg <= ARM64_REG_V31) {
      fi->common->is_vector = 1;
      DEBUG("Operand is vector\n");
  }

  if(check_dest_and_op_sizes(fi, inst)){
    return -1;
  }

  check_dest_and_op_sizes(fi, inst);

  if (fi->common->op_type == FPVM_OP_UNKNOWN) {
    // not an error, since this could be a sequence-ending instruction
    DEBUG("instruction decodes to unknown common op type\n");
    return -1;
  }

  return 0;
}

static int decode_move(fpvm_inst_t* fi) {
  cs_insn *inst = (cs_insn*)fi->internal;
  fi->is_simple_mov = 1;
  fi->is_gpr_mov = 1;
  // on ARM, we always clear the top half
  fi->zero_top_half_of_dest_gpr_suffering = 1;

  if (inst->id == ARM64_INS_MOV) {
    // TODO:
  }

  return 0;
}

static int decode_comparison(fpvm_inst_t* fi) {
  if (fi->common->op_type != FPVM_OP_CMPXX) {
    return 0;
  }

  cs_insn *inst = (cs_insn *)fi->internal;

  // arm neon instructions separates different cmp operations
  switch(inst->id){
    case ARM64_INS_CMEQ:
    case ARM64_INS_FCMEQ:
      fi->compare = FPVM_INST_COMPARE_EQ;
      break;
    case ARM64_INS_CMGE:
    case ARM64_INS_FCMGE:
      fi->compare = FPVM_INST_COMPARE_GE;
      break;
    case ARM64_INS_CMGT:
    case ARM64_INS_FCMGT:
      fi->compare = FPVM_INST_COMPARE_GT;
      break;
    case ARM64_INS_CMLE:
    case ARM64_INS_FCMLE:
      fi->compare = FPVM_INST_COMPARE_LE;
      break;
    case ARM64_INS_CMLT:
    case ARM64_INS_FCMLT:
      fi->compare = FPVM_INST_COMPARE_LT;
      break;
    // case ARM64_INS_FCMNE:
    //   fi->compare = FPVM_INST_COMPARE_NEQ;
    //   break;
    // case ARM64_INS_FACGE:
    // case ARM64_INS_FACGT:
    // since x86 doesn't have absolute comparisons, will leave these
    // commented out for now, don't know how to decode it
    default:
      ERROR("cmpxx operation but has no valid comparison type\n");
      return -1;
  }  

  return 0;
}


// TODO:
int fpvm_memaddr_probe_readable_long(void *addr) {
  return 0;
}


int fpvm_decoder_init(void)
{
  if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) != CS_ERR_OK) {
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

void fpvm_decoder_deinit(void) {
  DEBUG("decoder deinit\n");
  cs_close(&handle);
}


fpvm_inst_t *fpvm_decoder_decode_inst(void *addr) {

  cs_insn *inst;

  DEBUG("Decoding instruction at %p\n", addr);

  // ARM instructions are 4 bytes long
  size_t count = cs_disasm(handle, addr, 4, (uint64_t)addr, 1, &inst);
  if (count != 1) {
    ERROR("Failed to decode instruction (return=%lu, errno=%d)\n", count, cs_errno(handle));
    return 0;
  }

  fpvm_inst_t *fi = malloc(sizeof(fpvm_inst_t));
  if (!fi) {
    ERROR("Can't allocate instruction\n");
    return 0;
  }
  memset(fi, 0, sizeof(*fi));
  fi->addr = addr;
  fi->internal = inst;

  if (decode_to_common(fi)) {
    INFO("Can't decode to common representation\n");
    fpvm_decoder_free_inst(fi);
    return 0;
  }

  if (decode_move(fi)) {
    INFO("Can't decode move info\n");
    fpvm_decoder_free_inst(fi);
    return 0;
  }

  if (decode_comparison(fi)) {
    INFO("Can't decode comparison info\n");
    fpvm_decoder_free_inst(fi);
    return 0;
  }

  return fi;
}


void fpvm_decoder_free_inst(fpvm_inst_t *fi)
{
  DEBUG("decoder free inst at %p\n", fi);
  cs_free(fi->internal, 1);
  free(fi);
}

// TODO:
int fpvm_decoder_bind_operands(fpvm_inst_t *fi, fpvm_regs_t *fr) {
  DEBUG("decoder bind operands at %p\n", fi);
  return -1;
}

int fpvm_decoder_decode_and_print_any_inst(void *addr, FILE *out, char *prefix) {
  cs_insn *inst;
  int len;

  //  DEBUG("Decoding instruction for print at %p\n", addr);

  size_t count = cs_disasm(handle, addr, 4, (uint64_t)addr, 1, &inst);

  if (count != 1) {
    ERROR("Failed to decode instruction for print (return=%lu, errno=%d)\n", count, cs_errno(handle));
    return -1;
  }

  fprintf(out, "%s%s\t\t%s (%u bytes)\n", prefix, inst->mnemonic, inst->op_str, inst->size);

  len = inst->size;

  cs_free(inst, 1);

  return len;
}

// TODO:
void fpvm_dump_xmms_double(FILE *out, void *xmm) {
}

// TODO:
void fpvm_dump_xmms_float(FILE *out, void *xmm) {
}
