#ifndef _FPVM_EMULATOR_
#define _FPVM_EMULATOR_

#include <fpvm/fpvm_common.h>
#include <fpvm/decoder.h>


// takes a bound instruction and tells you if
// it should be emulated (i.e., it has nanboxed inputs
// or would cause an exception that FPVM can handle)
int fpvm_emulator_should_emulate_inst(fpvm_inst_t *fi);
// takes a bound instruction and emulates it
int fpvm_emulator_emulate_inst(fpvm_inst_t *fi, int *promotions, int *demotions, int *clobbers);
// handle a problematic, bound instruction that has been
// flagged by the static analysis and patcher
typedef enum {
  FPVM_CORRECT_ERROR=-1,
  FPVM_CORRECT_CONTINUE,
  FPVM_CORRECT_SKIP
} fpvm_emulator_correctness_response_t;
fpvm_emulator_correctness_response_t
fpvm_emulator_handle_correctness_for_inst(fpvm_inst_t *fi, fpvm_regs_t *fr, int *demotions);

int NO_TOUCH_FLOAT fpvm_emulator_demote_registers(fpvm_regs_t *fr);


// double (*orig_pow)(double a, double b) = 0;
// double (*orig_exp)(double a) = 0;
// double (*orig_log)(double a) = 0;
// double (*orig_sin)(double a) = 0;
// double (*orig_cos)(double a) = 0;
// double (*orig_tan)(double a) = 0;

#endif
