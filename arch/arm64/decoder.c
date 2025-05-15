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


int fpvm_memaddr_probe_readable_long(void *addr) {
  return 0;
}


int fpvm_decoder_init(void)
{
  if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
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
}

fpvm_inst_t *fpvm_decoder_decode_inst(void *addr)
{
  // TODO:

  cs_insn *inst;
  
  DEBUG("Decoding instruction at %p\n", addr);

  cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
  size_t count = cs_disasm(handle, addr, 16, (uint64_t)addr, 1, &inst);

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
    DEBUG("Can't decode to common representation\n");
    fpvm_decoder_free_inst(fi);
    return 0;
  }

  return NULL;
}

void fpvm_decoder_free_inst(fpvm_inst_t *fi)
{
  DEBUG("decoder free inst at %p\n", fi);
  free(fi);
}


int fpvm_decoder_bind_operands(fpvm_inst_t *fi, fpvm_regs_t *fr) {
  DEBUG("decoder bind operands at %p\n", fi);
  return -1;
}


int fpvm_decoder_decode_and_print_any_inst(void *addr, FILE *out, char *prefix) {
  DEBUG("decoder decode and print any inst at %p\n", addr);
  return -1;
}


void fpvm_dump_xmms_double(FILE *out, void *xmm) {
}

void fpvm_dump_xmms_float(FILE *out, void *xmm) {
}