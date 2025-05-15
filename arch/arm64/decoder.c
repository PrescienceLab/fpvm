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

#include <capstone/capstone.h>
static csh handle;

//
// This contains the mapping to our high-level interface
//
// TODO:
//    Size of 1 for now, but expand to ARM64_INS_ENDING
//    once we are ready...
fpvm_inst_common_t capstone_to_common[ARM64_INS_ENDING] = {
  [ARM64_INS_FADD] = {FPVM_OP_ADD, 1, 0, 8, 0}
};

// TODO:
// - For testing, just do fadd
static int decode_to_common(fpvm_inst_t *fi) {
  cs_insn *inst = (cs_insn*)fi->internal;

  fi->addr = (void*)inst->address;
  fi->length = inst->size;
  // Only fadd is being set up for now
  fi->common = &capstone_to_common[inst->id];

  if (fi->common->op_type == FPVM_OP_UNKNOWN) {
    DEBUG("instruction decodes to unknown common op type\n");
    return -1;
  }
  
  return 0;
}

static int decode_move(fpvm_inst_t* fi) {
  cs_insn *inst = (cs_insn*)fi->internal;
  fi->is_simple_mov = 0;
  fi->is_gpr_mov = 0;
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

  //TODO:
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

static int decode_to_common(fpvm_inst_t *fi) {
  cs_insn *inst = (cs_insn *)fi->internal;

  fi->addr = (void *)inst->address;
  fi->length = inst->size;

  //fi->common = &capstone_to_common[inst->id];

  // testing out only fadd instruction
  memset(&fi->common, 0, sizeof(fi->common));
  fi->common.op_type = FPVM_OP_ADD;

  cs_detail *detail = inst->detail;
  cs_arm64 *arm64 = &detail->arm64;

  // determine whether it's vector or scalar
  cs_arm64_op *op = &arm64->operands[0];
  if (op->reg >= ARM64_REG_S0 && op->reg <= ARM64_REG_S31) {
      DEBUG("Operand is scalar float (32-bit)\n");
  } else if (op->reg >= ARM64_REG_D0 && op->reg <= ARM64_REG_D31) {
      DEBUG("Operand is scalar double (64-bit)\n");
  } else if (op->reg >= ARM64_REG_V0 && op->reg <= ARM64_REG_V31) {
      fi->common.is_vector = 1;
      DEBUG("Operand is vector\n");
  }

  // check 32 or 64 bit
  if (strstr(inst->op_str, ".4s")) fi->common.op_size = 4;
  if (strstr(inst->op_str, ".2d")) fi->common.op_size = 8;
  if (strstr(inst->op_str, " s")) fi->common.op_size = 4;
  if (strstr(inst->op_str, " d")) fi->common.op_size = 8;


  if (fi->common->op_type == FPVM_OP_UNKNOWN) {
    // not an error, since this could be a sequence-ending instruction
    DEBUG("instruction decodes to unknown common op type\n");
    return -1;
  }

  return 0;
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

  // print out instruction decoded
  DEBUG("instr: %s\nop_str: %s\n", inst->mnemonic, inst->op_str);
  DEBUG("opid: %d\n", inst->id);

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

// TODO:
int fpvm_decoder_decode_and_print_any_inst(void *addr, FILE *out, char *prefix) {
  DEBUG("decoder decode and print any inst at %p\n", addr);
  return -1;
}

// TODO:
void fpvm_dump_xmms_double(FILE *out, void *xmm) {
}

// TODO:
void fpvm_dump_xmms_float(FILE *out, void *xmm) {
}
