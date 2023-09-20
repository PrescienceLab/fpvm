#pragma once

#define POSIT_NO_GENERICS
#include <universal/number/posit/posit.h>
#include <fpvm/number_system/nan_boxing.h>
#include <fpvm/number_system.h>
#define POSIT_NUMBER_SYSTEM 1

#define __POSIT_BIN_OP(type, op)\
    int posit_##op##_##type(op_special_t *special,void *dest, void *src1, void *src2, void *src3, void *src4){ \
    }

__POSIT_BIN_OP(add, double);
__POSIT_BIN_OP(sub, double);
__POSIT_BIN_OP(mul, double);
__POSIT_BIN_OP(div, double);

__POSIT_BIN_OP(add, float);
__POSIT_BIN_OP(sub, float);
__POSIT_BIN_OP(mul, float);
__POSIT_BIN_OP(div, float);


// MIN/MAX Operations
__POSIT_BIN_OP(max, double);
__POSIT_BIN_OP(min, double);
__POSIT_BIN_OP(max, float);
__POSIT_BIN_OP(min, float);


// Unary operations
__POSIT_BIN_OP(sqrt, float);
__POSIT_BIN_OP(sqrt, double);


// Fused operations
__POSIT_BIN_OP(madd, double);
__POSIT_BIN_OP(nmadd, double);
__POSIT_BIN_OP(madd, float);
__POSIT_BIN_OP(nmadd, float);

// unary functions
__POSIT_BIN_OP(f2i, double);
__POSIT_BIN_OP(f2u, double);
__POSIT_BIN_OP(f2i, float);
__POSIT_BIN_OP(f2u, float);
__POSIT_BIN_OP(i2f, double);
__POSIT_BIN_OP(u2f, double);
__POSIT_BIN_OP(i2f, float);
__POSIT_BIN_OP(u2f, float);
__POSIT_BIN_OP(f2f, double);
__POSIT_BIN_OP(f2f, float);
__POSIT_BIN_OP(cmp, double);
__POSIT_BIN_OP(cmp, float);
__POSIT_BIN_OP(ltmp, double);
__POSIT_BIN_OP(ltcmp, float);
