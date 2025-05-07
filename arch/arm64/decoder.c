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


int fpvm_memaddr_probe_readable_long(void *addr) {
  return 0;
}


int fpvm_decoder_init(void)
{
  DEBUG("decoder initialized\n");
  return 0;
}

void fpvm_decoder_deinit(void)
{
  DEBUG("decoder deinit\n");
}

fpvm_inst_t *fpvm_decoder_decode_inst(void *addr)
{
  // TODO:
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