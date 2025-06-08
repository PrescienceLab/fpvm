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
// Find the register ID index of a capstone reg
#define REG_IDX(r) \
  ((r) >= ARM64_REG_X0 && (r) <= ARM64_REG_X30 ? (r) - ARM64_REG_X0 : \
   (r) >= ARM64_REG_W0 && (r) <= ARM64_REG_W30 ? (r) - ARM64_REG_W0 : -1)

#define IS_FPR(r) \
  (((r) >= ARM64_REG_S0 && (r) <= ARM64_REG_S31) || \
   ((r) >= ARM64_REG_D0 && (r) <= ARM64_REG_D31) || \
   ((r) >= ARM64_REG_V0 && (r) <= ARM64_REG_V31))

#define GET_FPR_INDEX(r) \
  (((r) >= ARM64_REG_S0 && (r) <= ARM64_REG_S31) ? ((r) - ARM64_REG_S0) : \
   ((r) >= ARM64_REG_D0 && (r) <= ARM64_REG_D31) ? ((r) - ARM64_REG_D0) : \
   ((r) - ARM64_REG_V0))

#define GET_FPR_SIZE(r) \
  (((r) >= ARM64_REG_S0 && (r) <= ARM64_REG_S31) ? 4 : \
   ((r) >= ARM64_REG_D0 && (r) <= ARM64_REG_D31) ? 8 : \
   16) // 16 bytes for Vector

//
// This contains the mapping to our high-level interface
//
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
  // [ARM64_INS_FCVTX] = FPVM_OP_F2F,

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

static char* reg_name(arm64_reg reg) {
#define DO_REG(x) \
  case x:         \
    return #x;    \
    break;
  switch (reg) {
    DO_REG(ARM64_REG_X29);
    DO_REG(ARM64_REG_X30);
    DO_REG(ARM64_REG_NZCV);
    DO_REG(ARM64_REG_SP);
    DO_REG(ARM64_REG_WSP);
    DO_REG(ARM64_REG_WZR);
    DO_REG(ARM64_REG_XZR);
    DO_REG(ARM64_REG_B0);
    DO_REG(ARM64_REG_B1);
    DO_REG(ARM64_REG_B2);
    DO_REG(ARM64_REG_B3);
    DO_REG(ARM64_REG_B4);
    DO_REG(ARM64_REG_B5);
    DO_REG(ARM64_REG_B6);
    DO_REG(ARM64_REG_B7);
    DO_REG(ARM64_REG_B8);
    DO_REG(ARM64_REG_B9);
    DO_REG(ARM64_REG_B10);
    DO_REG(ARM64_REG_B11);
    DO_REG(ARM64_REG_B12);
    DO_REG(ARM64_REG_B13);
    DO_REG(ARM64_REG_B14);
    DO_REG(ARM64_REG_B15);
    DO_REG(ARM64_REG_B16);
    DO_REG(ARM64_REG_B17);
    DO_REG(ARM64_REG_B18);
    DO_REG(ARM64_REG_B19);
    DO_REG(ARM64_REG_B20);
    DO_REG(ARM64_REG_B21);
    DO_REG(ARM64_REG_B22);
    DO_REG(ARM64_REG_B23);
    DO_REG(ARM64_REG_B24);
    DO_REG(ARM64_REG_B25);
    DO_REG(ARM64_REG_B26);
    DO_REG(ARM64_REG_B27);
    DO_REG(ARM64_REG_B28);
    DO_REG(ARM64_REG_B29);
    DO_REG(ARM64_REG_B30);
    DO_REG(ARM64_REG_B31);
    DO_REG(ARM64_REG_D0);
    DO_REG(ARM64_REG_D1);
    DO_REG(ARM64_REG_D2);
    DO_REG(ARM64_REG_D3);
    DO_REG(ARM64_REG_D4);
    DO_REG(ARM64_REG_D5);
    DO_REG(ARM64_REG_D6);
    DO_REG(ARM64_REG_D7);
    DO_REG(ARM64_REG_D8);
    DO_REG(ARM64_REG_D9);
    DO_REG(ARM64_REG_D10);
    DO_REG(ARM64_REG_D11);
    DO_REG(ARM64_REG_D12);
    DO_REG(ARM64_REG_D13);
    DO_REG(ARM64_REG_D14);
    DO_REG(ARM64_REG_D15);
    DO_REG(ARM64_REG_D16);
    DO_REG(ARM64_REG_D17);
    DO_REG(ARM64_REG_D18);
    DO_REG(ARM64_REG_D19);
    DO_REG(ARM64_REG_D20);
    DO_REG(ARM64_REG_D21);
    DO_REG(ARM64_REG_D22);
    DO_REG(ARM64_REG_D23);
    DO_REG(ARM64_REG_D24);
    DO_REG(ARM64_REG_D25);
    DO_REG(ARM64_REG_D26);
    DO_REG(ARM64_REG_D27);
    DO_REG(ARM64_REG_D28);
    DO_REG(ARM64_REG_D29);
    DO_REG(ARM64_REG_D30);
    DO_REG(ARM64_REG_D31);
    DO_REG(ARM64_REG_H0);
    DO_REG(ARM64_REG_H1);
    DO_REG(ARM64_REG_H2);
    DO_REG(ARM64_REG_H3);
    DO_REG(ARM64_REG_H4);
    DO_REG(ARM64_REG_H5);
    DO_REG(ARM64_REG_H6);
    DO_REG(ARM64_REG_H7);
    DO_REG(ARM64_REG_H8);
    DO_REG(ARM64_REG_H9);
    DO_REG(ARM64_REG_H10);
    DO_REG(ARM64_REG_H11);
    DO_REG(ARM64_REG_H12);
    DO_REG(ARM64_REG_H13);
    DO_REG(ARM64_REG_H14);
    DO_REG(ARM64_REG_H15);
    DO_REG(ARM64_REG_H16);
    DO_REG(ARM64_REG_H17);
    DO_REG(ARM64_REG_H18);
    DO_REG(ARM64_REG_H19);
    DO_REG(ARM64_REG_H20);
    DO_REG(ARM64_REG_H21);
    DO_REG(ARM64_REG_H22);
    DO_REG(ARM64_REG_H23);
    DO_REG(ARM64_REG_H24);
    DO_REG(ARM64_REG_H25);
    DO_REG(ARM64_REG_H26);
    DO_REG(ARM64_REG_H27);
    DO_REG(ARM64_REG_H28);
    DO_REG(ARM64_REG_H29);
    DO_REG(ARM64_REG_H30);
    DO_REG(ARM64_REG_H31);
    DO_REG(ARM64_REG_Q0);
    DO_REG(ARM64_REG_Q1);
    DO_REG(ARM64_REG_Q2);
    DO_REG(ARM64_REG_Q3);
    DO_REG(ARM64_REG_Q4);
    DO_REG(ARM64_REG_Q5);
    DO_REG(ARM64_REG_Q6);
    DO_REG(ARM64_REG_Q7);
    DO_REG(ARM64_REG_Q8);
    DO_REG(ARM64_REG_Q9);
    DO_REG(ARM64_REG_Q10);
    DO_REG(ARM64_REG_Q11);
    DO_REG(ARM64_REG_Q12);
    DO_REG(ARM64_REG_Q13);
    DO_REG(ARM64_REG_Q14);
    DO_REG(ARM64_REG_Q15);
    DO_REG(ARM64_REG_Q16);
    DO_REG(ARM64_REG_Q17);
    DO_REG(ARM64_REG_Q18);
    DO_REG(ARM64_REG_Q19);
    DO_REG(ARM64_REG_Q20);
    DO_REG(ARM64_REG_Q21);
    DO_REG(ARM64_REG_Q22);
    DO_REG(ARM64_REG_Q23);
    DO_REG(ARM64_REG_Q24);
    DO_REG(ARM64_REG_Q25);
    DO_REG(ARM64_REG_Q26);
    DO_REG(ARM64_REG_Q27);
    DO_REG(ARM64_REG_Q28);
    DO_REG(ARM64_REG_Q29);
    DO_REG(ARM64_REG_Q30);
    DO_REG(ARM64_REG_Q31);
    DO_REG(ARM64_REG_S0);
    DO_REG(ARM64_REG_S1);
    DO_REG(ARM64_REG_S2);
    DO_REG(ARM64_REG_S3);
    DO_REG(ARM64_REG_S4);
    DO_REG(ARM64_REG_S5);
    DO_REG(ARM64_REG_S6);
    DO_REG(ARM64_REG_S7);
    DO_REG(ARM64_REG_S8);
    DO_REG(ARM64_REG_S9);
    DO_REG(ARM64_REG_S10);
    DO_REG(ARM64_REG_S11);
    DO_REG(ARM64_REG_S12);
    DO_REG(ARM64_REG_S13);
    DO_REG(ARM64_REG_S14);
    DO_REG(ARM64_REG_S15);
    DO_REG(ARM64_REG_S16);
    DO_REG(ARM64_REG_S17);
    DO_REG(ARM64_REG_S18);
    DO_REG(ARM64_REG_S19);
    DO_REG(ARM64_REG_S20);
    DO_REG(ARM64_REG_S21);
    DO_REG(ARM64_REG_S22);
    DO_REG(ARM64_REG_S23);
    DO_REG(ARM64_REG_S24);
    DO_REG(ARM64_REG_S25);
    DO_REG(ARM64_REG_S26);
    DO_REG(ARM64_REG_S27);
    DO_REG(ARM64_REG_S28);
    DO_REG(ARM64_REG_S29);
    DO_REG(ARM64_REG_S30);
    DO_REG(ARM64_REG_S31);
    DO_REG(ARM64_REG_W0);
    DO_REG(ARM64_REG_W1);
    DO_REG(ARM64_REG_W2);
    DO_REG(ARM64_REG_W3);
    DO_REG(ARM64_REG_W4);
    DO_REG(ARM64_REG_W5);
    DO_REG(ARM64_REG_W6);
    DO_REG(ARM64_REG_W7);
    DO_REG(ARM64_REG_W8);
    DO_REG(ARM64_REG_W9);
    DO_REG(ARM64_REG_W10);
    DO_REG(ARM64_REG_W11);
    DO_REG(ARM64_REG_W12);
    DO_REG(ARM64_REG_W13);
    DO_REG(ARM64_REG_W14);
    DO_REG(ARM64_REG_W15);
    DO_REG(ARM64_REG_W16);
    DO_REG(ARM64_REG_W17);
    DO_REG(ARM64_REG_W18);
    DO_REG(ARM64_REG_W19);
    DO_REG(ARM64_REG_W20);
    DO_REG(ARM64_REG_W21);
    DO_REG(ARM64_REG_W22);
    DO_REG(ARM64_REG_W23);
    DO_REG(ARM64_REG_W24);
    DO_REG(ARM64_REG_W25);
    DO_REG(ARM64_REG_W26);
    DO_REG(ARM64_REG_W27);
    DO_REG(ARM64_REG_W28);
    DO_REG(ARM64_REG_W29);
    DO_REG(ARM64_REG_W30);
    DO_REG(ARM64_REG_X0);
    DO_REG(ARM64_REG_X1);
    DO_REG(ARM64_REG_X2);
    DO_REG(ARM64_REG_X3);
    DO_REG(ARM64_REG_X4);
    DO_REG(ARM64_REG_X5);
    DO_REG(ARM64_REG_X6);
    DO_REG(ARM64_REG_X7);
    DO_REG(ARM64_REG_X8);
    DO_REG(ARM64_REG_X9);
    DO_REG(ARM64_REG_X10);
    DO_REG(ARM64_REG_X11);
    DO_REG(ARM64_REG_X12);
    DO_REG(ARM64_REG_X13);
    DO_REG(ARM64_REG_X14);
    DO_REG(ARM64_REG_X15);
    DO_REG(ARM64_REG_X16);
    DO_REG(ARM64_REG_X17);
    DO_REG(ARM64_REG_X18);
    DO_REG(ARM64_REG_X19);
    DO_REG(ARM64_REG_X20);
    DO_REG(ARM64_REG_X21);
    DO_REG(ARM64_REG_X22);
    DO_REG(ARM64_REG_X23);
    DO_REG(ARM64_REG_X24);
    DO_REG(ARM64_REG_X25);
    DO_REG(ARM64_REG_X26);
    DO_REG(ARM64_REG_X27);
    DO_REG(ARM64_REG_X28);
    DO_REG(ARM64_REG_V0);
    DO_REG(ARM64_REG_V1);
    DO_REG(ARM64_REG_V2);
    DO_REG(ARM64_REG_V3);
    DO_REG(ARM64_REG_V4);
    DO_REG(ARM64_REG_V5);
    DO_REG(ARM64_REG_V6);
    DO_REG(ARM64_REG_V7);
    DO_REG(ARM64_REG_V8);
    DO_REG(ARM64_REG_V9);
    DO_REG(ARM64_REG_V10);
    DO_REG(ARM64_REG_V11);
    DO_REG(ARM64_REG_V12);
    DO_REG(ARM64_REG_V13);
    DO_REG(ARM64_REG_V14);
    DO_REG(ARM64_REG_V15);
    DO_REG(ARM64_REG_V16);
    DO_REG(ARM64_REG_V17);
    DO_REG(ARM64_REG_V18);
    DO_REG(ARM64_REG_V19);
    DO_REG(ARM64_REG_V20);
    DO_REG(ARM64_REG_V21);
    DO_REG(ARM64_REG_V22);
    DO_REG(ARM64_REG_V23);
    DO_REG(ARM64_REG_V24);
    DO_REG(ARM64_REG_V25);
    DO_REG(ARM64_REG_V26);
    DO_REG(ARM64_REG_V27);
    DO_REG(ARM64_REG_V28);
    DO_REG(ARM64_REG_V29);
    DO_REG(ARM64_REG_V30);
    DO_REG(ARM64_REG_V31);
    default:
      return "UNKNOWN";
      break;
  }
}

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
    else if (strstr(token, "s")) {
      if(dest) fi->common->dest_size = 4;
      else fi->common->op_size = 4;
    }
    else if (strstr(token, "d")){
      if(dest) fi->common->dest_size = 8;
      else fi->common->op_size = 8;
    }
    else if (strstr(token, "#")) {
      // skip if immediate
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
  fi->zero_top_half_of_dest_gpr_suffering = 0;

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

int fpvm_decoder_bind_operands(fpvm_inst_t *fi, fpvm_regs_t *fr) {
  cs_insn *inst = (cs_insn *)fi->internal;
  cs_detail *det = inst->detail;
  cs_arm64 *arm64 = &det->arm64;

  uint8_t max_operand_size=0;
#define UPDATE_MAX_OPERAND_SIZE(s) max_operand_size = ((s)>max_operand_size) ? (s) : max_operand_size;

  int i;

  DEBUG("binding instruction to mcontext=%p fprs=%p fpr_size=%u\n", fr->mcontext, fr->fprs,
    fr->fpr_size);
  
  // If operation is comparison, save side effects
  if (fi->common->op_type == FPVM_OP_CMP || fi->common->op_type == FPVM_OP_UCMP) {
    // On x86, we save EFLAGS which is generic side effects. We can try to follow this by storing the pstate, which holds
    // NZCV flags.
    fi->side_effect_addrs[0] = (void*)fr->mcontext->pstate;
    // Store FPSR as 2nd side effect.
    fi->side_effect_addrs[1] = MCTX_FPSRP(fr->mcontext);
  }

  fi->operand_count = 0;

  for (i = 0; i < arm64->op_count; i++) {
    DEBUG("Binding operand #%d\n", i);
    cs_arm64_op *o = &arm64->operands[i];
    switch (o->type) {
      case ARM64_OP_REG:

        if (IS_FPR(o->reg)) {
          fi->operand_addrs[fi->operand_count] = fr->fprs + fr->fpr_size * GET_FPR_INDEX(o->reg);
          fi->operand_sizes[fi->operand_count] = GET_FPR_SIZE(o->reg);
          UPDATE_MAX_OPERAND_SIZE(fi->operand_sizes[fi->operand_count]);
          DEBUG("Mapped FPR %s to %p (size: %d bytes)\n", reg_name(o->reg),
              fi->operand_addrs[fi->operand_count], fi->operand_sizes[fi->operand_count]);
        }
        else {
          // This is a GPR
          //
          // You can not use a GPR directly for fops, but they CAN be used as an
          // intermediate register (I think)
          DEBUG("Not handling GPR registers for now");
          return -1;
        }
        fi->operand_count++;
        break;
      
      case ARM64_OP_MEM:
        arm64_op_mem *mo = &o->mem;

        // On ARM, we process using base + index registers, and displacement (immediate)
        // (ex. [base, displacement] => base + displacement
        //      [base, index] => base + index
        //      [base, index, LSL #n] => base + index << n)
        //
        // Start with displacement
        uint64_t addr = mo->disp;

        if (mo->base != ARM64_REG_INVALID) {
          addr += fr->mcontext->regs[REG_IDX(mo->base)];
        }

        if (mo->index != ARM64_REG_INVALID) {
          uint64_t val = fr->mcontext->regs[REG_IDX(mo->index)];
          if (o->shift.type != ARM64_SFT_INVALID) {
            val <<= o->shift.value; // We assume left shifting here (LSL)
          }
          addr += val;
        }

        fi->operand_addrs[fi->operand_count] = (void *)addr;
        
        // For the size of the operand, we are not sure if we can rely on Capstone to
        // populate o->size correctly. Consider implementing it with a second pass like in x86.
        // fi->operand_sizes[fi->operand_count] = o->size;
        fi->operand_sizes[fi->operand_count] = 0;

        UPDATE_MAX_OPERAND_SIZE(fi->operand_sizes[fi->operand_count]);
        fi->operand_count++;
        break;

      case ARM64_OP_FP:
        fi->operand_addrs[fi->operand_count] = &o->fp;
        // fi->operand_sizes[fi->operand_count] = o->size;
        fi->operand_sizes[fi->operand_count] = 0;
        UPDATE_MAX_OPERAND_SIZE(fi->operand_sizes[fi->operand_count]);

        DEBUG("Mapped immediate %lf at %p (size: %d bytes)\n", 
          o->fp, fi->operand_addrs[fi->operand_count], fi->operand_sizes[fi->operand_count]);
        fi->operand_count++;
        break;

      default:
        ERROR("Operand type not covered! \n");
        return -1;
    }

  }

  DEBUG("Max operand size: %d\n", max_operand_size);
  
  // update memory operand sizes
  for (i = 0; i < fi->operand_count; i++) {
    
  }

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
