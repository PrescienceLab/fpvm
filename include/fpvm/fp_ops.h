
#pragma once
/*
 * Binary Operand Functions
 * ========================
 */
#include "number_system.h"


// @param fpvm_op_name See fpvm_op_t for list of supported FPVM operations
// @param function name of function without type suffix (eg. ap_add)
#if CONFIG_ALT_MATH_VANILLA
// Vanilla is always included, this avoids the name space confusion
// if it is the only one included
#define _FP_BIN_OP(fpvm_op_name, function) \
  [fpvm_op_name] = {vanilla_##function##_float, vanilla_##function##_double}
#else
#define _FP_BIN_OP(fpvm_op_name, function) [fpvm_op_name] = {function##_float, function##_double}
#endif

/*
 * Generates array designated initializers for FPVM's op map for binary operations (two operands)
 * Assumes your functions are named $prefix_op_float and $prefix_op_double where op is add, sub,
 * etc. Example: ap_add_float -> FP_BIN_OP(ap)
 *
 * @param prefix function name prefix - functions should be named $prefix_op_float and
 * $prefix_op_double where op is add, sub, etc.
 */
#define FP_BIN_OP()                                                                               \
  _FP_BIN_OP(FPVM_OP_ADD, add), _FP_BIN_OP(FPVM_OP_SUB, sub), _FP_BIN_OP(FPVM_OP_MUL, mul),       \
      _FP_BIN_OP(FPVM_OP_DIV, div), _FP_BIN_OP(FPVM_OP_SQRT, sqrt),                               \
      _FP_BIN_OP(FPVM_OP_MADD, madd), _FP_BIN_OP(FPVM_OP_NMADD, nmadd),                           \
      _FP_BIN_OP(FPVM_OP_MSUB, msub), _FP_BIN_OP(FPVM_OP_NMSUB, nmsub),                           \
      _FP_BIN_OP(FPVM_OP_CMP, cmp),                                                               \
      _FP_BIN_OP(FPVM_OP_UCMP, cmp), _FP_BIN_OP(FPVM_OP_CMPXX, cmpxx),	                          \
      _FP_BIN_OP(FPVM_OP_MIN, min), _FP_BIN_OP(FPVM_OP_MAX, max), _FP_BIN_OP(FPVM_OP_F2I, f2i),   \
      _FP_BIN_OP(FPVM_OP_F2U, f2u), _FP_BIN_OP(FPVM_OP_F2IT, f2i), _FP_BIN_OP(FPVM_OP_F2UT, f2u), \
      _FP_BIN_OP(FPVM_OP_F2F, f2f)

#define FPVM_NUMBER_SYSTEM_INIT()                                                \
  static op_map_t op_map[FPVM_OP_LAST] = {[0 ... FPVM_OP_LAST - 1] = {bad, bad}, \
                                                                                 \
      FP_BIN_OP()}
