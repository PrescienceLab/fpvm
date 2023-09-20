#ifndef _FPVM_MPFR_
#define _FPVM_MPFR_
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <mpfr.h>

#define __MPFR_BIN_OP(type, op)                                                            \
  int mpfr_##op##_##type(                                                                  \
      op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) { \
    mpfr_ptr mpfr_a, mpfr_b, mpfr_result;                                                  \
  }


#endif
