#ifndef _FPVM_EMULATOR_
#define _FPVM_EMULATOR_

#include <fpvm/decoder.h>

// takes a bound instruction
int fpvm_emulator_emulate_inst(fpvm_inst_t *fi);
int fpvm_fp_restore(fpvm_inst_t *fi, fpvm_regs_t *fr);

// double (*orig_pow)(double a, double b) = 0;
// double (*orig_exp)(double a) = 0;
// double (*orig_log)(double a) = 0;
// double (*orig_sin)(double a) = 0;
// double (*orig_cos)(double a) = 0;
// double (*orig_tan)(double a) = 0;

#endif
