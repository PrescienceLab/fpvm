#ifndef _FPVM_ARB_PREC_
#define _FPVM_ARB_PREC_
#include <stdint.h>
#include "config.h"


/* Interface for plugging a number system into FPVM
 *
 * To use a different number system, include your header above and change the prefix for function
 * calls as per fp_ops.h Assumes your functions are named $prefix_op_float and $prefix_op_double
 * where op is add, sub, etc. Functions must handle NaN boxing themselves. Also should have an entry
 * for calling your GC/allocator functions, if they exist Example: ap_add_double ->
 * FPVM_NUMBER_SYSTEM_INIT(ap)
 *
 * @param prefix function name prefix - functions should be named $prefix_op_float and
 * $prefix_op_double where op is add, sub, etc.
 */


typedef struct {
  int byte_width;
  int truncate;
  int unordered;
  uint64_t *rflags;
} op_special_t;


// #if CONFIG_ALT_MATH_NONE
// #define PREFIX
// #elif CONFIG_ALT_MATH_IEEE
// #define PREFIX ieee
// #elif CONFIG_ALT_MATH_POSIT
// #define PREFIX posit
// #endif

#define FPVM_MATH_DECL(op, type) \
  int op##_##type(op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4)

#define FPVM_MATH_DECL_VANILLA_ALT(op, type)                                              \
  int vanilla_##op##_##type(                                                              \
      op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4); \
  int op##_##type(                                                                        \
      op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4);

#define FPVM_RESTORE_DECL(op, type) \
  int op##_##type(op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4)

#ifdef __cplusplus
extern "C" {
#endif

FPVM_MATH_DECL_VANILLA_ALT(add, double);
FPVM_MATH_DECL_VANILLA_ALT(sub, double);
FPVM_MATH_DECL_VANILLA_ALT(mul, double);
FPVM_MATH_DECL_VANILLA_ALT(div, double);

FPVM_MATH_DECL_VANILLA_ALT(add, float);
FPVM_MATH_DECL_VANILLA_ALT(sub, float);
FPVM_MATH_DECL_VANILLA_ALT(mul, float);
FPVM_MATH_DECL_VANILLA_ALT(div, float);


// MIN/MAX Operations
FPVM_MATH_DECL_VANILLA_ALT(max, double);
FPVM_MATH_DECL_VANILLA_ALT(min, double);
FPVM_MATH_DECL_VANILLA_ALT(max, float);
FPVM_MATH_DECL_VANILLA_ALT(min, float);


// Unary operations
FPVM_MATH_DECL_VANILLA_ALT(sqrt, float);
FPVM_MATH_DECL_VANILLA_ALT(sqrt, double);


// Fused operations

FPVM_MATH_DECL_VANILLA_ALT(madd, double);
FPVM_MATH_DECL_VANILLA_ALT(nmadd, double);
FPVM_MATH_DECL_VANILLA_ALT(madd, float);
FPVM_MATH_DECL_VANILLA_ALT(nmadd, float);


FPVM_MATH_DECL_VANILLA_ALT(msub, double);
FPVM_MATH_DECL_VANILLA_ALT(nmsub, double);
FPVM_MATH_DECL_VANILLA_ALT(msub, float);
FPVM_MATH_DECL_VANILLA_ALT(nmsub, float);


// unary functions
FPVM_MATH_DECL_VANILLA_ALT(f2i, double);
FPVM_MATH_DECL_VANILLA_ALT(f2u, double);
FPVM_MATH_DECL_VANILLA_ALT(f2i, float);
FPVM_MATH_DECL_VANILLA_ALT(f2u, float);
FPVM_MATH_DECL_VANILLA_ALT(i2f, double);
FPVM_MATH_DECL_VANILLA_ALT(u2f, double);
FPVM_MATH_DECL_VANILLA_ALT(i2f, float);
FPVM_MATH_DECL_VANILLA_ALT(u2f, float);
FPVM_MATH_DECL_VANILLA_ALT(f2f, double);
FPVM_MATH_DECL_VANILLA_ALT(f2f, float);
FPVM_MATH_DECL_VANILLA_ALT(cmp, double);
FPVM_MATH_DECL_VANILLA_ALT(cmp, float);
FPVM_MATH_DECL_VANILLA_ALT(ltcmp, double);
FPVM_MATH_DECL_VANILLA_ALT(ltcmp, float);

// moves
FPVM_MATH_DECL_VANILLA_ALT(move, double);
FPVM_MATH_DECL_VANILLA_ALT(move, float);



// restore from nanbox
FPVM_RESTORE_DECL(restore, float);
FPVM_RESTORE_DECL(restore, double);
void NO_TOUCH_FLOAT restore_double_in_place(uint64_t *);

// math functions
//  no float now
double pow(double, double);
double exp(double);
double log(double);
double sin(double);
double cos(double);
double tan(double);


void fpvm_number_init(void *);
void fpvm_number_deinit(void *);


#ifdef __cplusplus
}
#endif



#endif
