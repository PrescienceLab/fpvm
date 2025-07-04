#include <fpvm/config.h>
#include <math.h>

#if 1  // CONFIG_ALT_MATH_NONE

#include <fpvm/fpvm_common.h>
#include <fpvm/fpvm_fenv.h>
#include <fpvm/fpvm_math.h>
#include <fpvm/number_system.h>

#if CONFIG_DEBUG_ALT_ARITH
#define MATH_DEBUG(S, ...) DEBUG("vanilla: " S, ##__VA_ARGS__)
#define MATH_SAFE_DEBUG(S) SAFE_DEBUG("vanilla: " S)
#define MATH_SAFE_DEBUG_QUAD(S,X) SAFE_DEBUG_QUAD("vanilla: " S, X)
#else
#define MATH_DEBUG(S, ...)
#define MATH_SAFE_DEBUG(S)
#define MATH_SAFE_DEBUG_QUAD(S,X)
#endif

#if !NO_OUTPUT
#define MATH_INFO(S, ...) INFO("vanilla: " S, ##__VA_ARGS__)
#define MATH_ERROR(S, ...) ERROR("vanilla: " S, ##__VA_ARGS__)
#else
#define MATH_INFO(S, ...)
#define MATH_ERROR(S, ...)
#endif

#define BIN_OP(TYPE, ITYPE, NAME, OP, SPEC, ISPEC)                                         \
  int vanilla_##NAME##_##TYPE(                                                             \
      op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) { \
    TYPE result = (*(TYPE *)src1)OP(*(TYPE *)src2);                                        \
                                                                                           \
    MATH_DEBUG(#NAME "_" #TYPE ": " SPEC " " #OP " " SPEC " = " SPEC " [" ISPEC "] (%p)\n",     \
        *(TYPE *)src1, *(TYPE *)src2, result, *(ITYPE *)&result, dest);                    \
    *(TYPE *)dest = result;                                                                \
                                                                                           \
    return 0;                                                                              \
  }

#define UN_FUNC(TYPE, ITYPE, NAME, FUNC, SPEC, ISPEC)                                           \
  int vanilla_##NAME##_##TYPE(                                                                  \
      op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) {      \
    TYPE result = FUNC((*(TYPE *)src1));                                                        \
                                                                                                \
    MATH_DEBUG(#NAME "_" #TYPE ": " #FUNC "(" SPEC ") = " SPEC " [" ISPEC "] (%p)\n", *(TYPE *)src1, \
        result, *(ITYPE *)&result, dest);                                                       \
    *(TYPE *)dest = result;                                                                     \
                                                                                                \
    return 0;                                                                                   \
  }

// use separate integer-based move operation to avoid any nan-normalization crap...
#define MOVE_OP(TYPE, ITYPE, SPEC, ISPEC)                                                       \
  int vanilla_move_##TYPE(						                        \
      op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) {      \
                                                                                                \
    MATH_DEBUG("move_" #TYPE ": " SPEC " = " SPEC " [" ISPEC "] (%p)\n", *(TYPE *)src1,*(TYPE *)src1, \
        *(ITYPE *)src1, dest);                                                                  \
    *(ITYPE *)dest = *(ITYPE *)src1;					                        \
                                                                                                \
    return 0;                                                                                   \
  }
  
#define BIN_FUNC(TYPE, ITYPE, NAME, FUNC, SPEC, ISPEC)                                     \
  int vanilla_##NAME##_##TYPE(                                                             \
      op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) { \
    TYPE result = FUNC((*(TYPE *)src1), (*(TYPE *)src2));                                  \
                                                                                           \
    MATH_DEBUG(#NAME "_" #TYPE ": " #FUNC "(" SPEC ", " SPEC ") = " SPEC " [" ISPEC "] (%p)\n", \
        *(TYPE *)src1, *(TYPE *)src2, result, *(ITYPE *)&result, dest);                    \
    *(TYPE *)dest = result;                                                                \
                                                                                           \
    return 0;                                                                              \
  }

#define FUSED_OP(TYPE, ITYPE, NAME, OP1, NEGOP, OP2, SPEC, ISPEC)                          \
  int vanilla_##NAME##_##TYPE(                                                             \
      op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) { \
    TYPE result = (NEGOP((*(TYPE *)src1)OP1(*(TYPE *)src2)))OP2(*(TYPE *)src3);            \
                                                                                           \
    MATH_DEBUG(#NAME "_" #TYPE ": (" #NEGOP "( " SPEC " " #OP1 " " SPEC " ) ) " #OP2 " " SPEC   \
                " = " SPEC " [" ISPEC "] (%p)\n",                                          \
        *(TYPE *)src1, *(TYPE *)src2, *(TYPE *)src3, result, *(ITYPE *)&result, dest);     \
    *(TYPE *)dest = result;                                                                \
                                                                                           \
    return 0;                                                                              \
  }

BIN_OP(double, uint64_t, add, +, "%lf", "%016lx");
BIN_OP(double, uint64_t, sub, -, "%lf", "%016lx");
BIN_OP(double, uint64_t, div, /, "%lf", "%016lx");
BIN_OP(double, uint64_t, mul, *, "%lf", "%016lx");
BIN_OP(float, uint32_t, add, +, "%f", "%08x");
BIN_OP(float, uint32_t, sub, -, "%f", "%08x");
BIN_OP(float, uint32_t, mul, *, "%f", "%08x");
BIN_OP(float, uint32_t, div, /, "%f", "%08x");

FUSED_OP(double, uint64_t, madd, *, +, +, "%lf", "%016lx");
FUSED_OP(double, uint64_t, nmadd, *, -, +, "%lf", "%016lx");
FUSED_OP(float, uint32_t, madd, *, +, +, "%f", "%08x");
FUSED_OP(float, uint32_t, nmadd, *, -, +, "%f", "%08x");

FUSED_OP(double, uint64_t, msub, *, +, -, "%lf", "%016lx");
FUSED_OP(double, uint64_t, nmsub, *, -, -, "%lf", "%016lx");
FUSED_OP(float, uint32_t, msub, *, +, -, "%f", "%08x");
FUSED_OP(float, uint32_t, nmsub, *, -, -, "%f", "%08x");

UN_FUNC(double, uint64_t, sqrt, sqrt, "%lf", "%016lx");
UN_FUNC(float, uint32_t, sqrt, sqrtf, "%f", "%08x");


static inline double maxd(double a, double b) {
  if (a > b) {
    return a;
  } else {
    return b;
  }
}
static inline double mind(double a, double b) {
  if (a < b) {
    return a;
  } else {
    return b;
  }
}
static inline float maxf(float a, float b) {
  if (a > b) {
    return a;
  } else {
    return b;
  }
}
static inline float minf(float a, float b) {
  if (a < b) {
    return a;
  } else {
    return b;
  }
}

BIN_FUNC(double, uint64_t, max, maxd, "%lf", "%016lx");
BIN_FUNC(double, uint64_t, min, mind, "%lf", "%016lx");
BIN_FUNC(float, uint32_t, max, maxf, "%f", "%08x");
BIN_FUNC(float, uint32_t, min, minf, "%f", "%08x");

/* int sqrt_double(void *dest, void *src1, void *src2, void *src3, void *src4)
 */
/* { */
/*   double result =  sqrt(*(double*)src1); */
/*   MATH_DEBUG("sqrt_double: sqrt(%lf) = %lf [%016lx] (%p)\n", *(double*)src1,
 * result, *(uint64_t*)&result, dest ); */
/*   *(double*)dest = result; */
/*   return 0; */
/* } */

/* int sqrt_float(void *dest, void *src1, void *src2, void *src3, void *src4) */
/* { */
/*   float result = sqrtf(*(float*)src1); */
/*   MATH_DEBUG("sqrt_single: sqrt(%f) = %f [%08x] (%p)\n", *(float*)src1,result,
 * *(uint32_t*)&result, dest ); */
/*   *(float*)dest = result; */
/*   return 0; */
/* } */

// We assume in the following that C converstion float to int will do truncation
// Intel truncating convert instructions assume indefinite result 0x8000....
// when overflowing Intel non-truncating converst instructions don't really
// specify what they do when overflowing We need to either find better
// documentation of the instructions or test them... the current version of the
// following does the C conversion in all cases.
//
#define CONVERT_F2I(FTYPE, ITYPE, FSPEC, ISPEC)                                                    \
  {                                                                                                \
    ITYPE result = (ITYPE)(*(FTYPE *)src1);                                                        \
    MATH_DEBUG("f2i[" #FTYPE " to " #ITYPE "](" FSPEC ") = " ISPEC " (%p)\n", (*(FTYPE *)src1), result, \
        dest);                                                                                     \
    *(ITYPE *)dest = result;                                                                       \
    return 0;                                                                                      \
  }

// THIS DOES NOT HANDLE THE SPECIAL CASES OR RAISE EXCEPTIONS
int vanilla_f2i_double(
    op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) {
  switch (special->byte_width) {
    case 1:
      CONVERT_F2I(double, int8_t, "%lf", "%hhd");
    case 2:
      CONVERT_F2I(double, int16_t, "%lf", "%hd");
    case 4:
      CONVERT_F2I(double, int32_t, "%lf", "%d");
    case 8:
      CONVERT_F2I(double, int64_t, "%lf", "%ld");
    default:
      MATH_ERROR("Cannot handle double->signed(%d)\n", special->byte_width);
      return -1;
      break;
  }
  return 0;
}

// THIS DOES NOT HANDLE THE SPECIAL CASES OR RAISE EXCEPTIONS
int vanilla_f2u_double(
    op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) {
  switch (special->byte_width) {
    case 1:
      CONVERT_F2I(double, uint8_t, "%lf", "%hhu");
    case 2:
      CONVERT_F2I(double, uint16_t, "%lf", "%hu");
    case 4:
      CONVERT_F2I(double, uint32_t, "%lf", "%u");
    case 8:
      CONVERT_F2I(double, uint64_t, "%lf", "%lu");
    default:
      MATH_ERROR("Cannot handle double->unsigned(%d)\n", special->byte_width);
      return -1;
      break;
  }
  return 0;
}

// THIS DOES NOT HANDLE THE SPECIAL CASES OR RAISE EXCEPTIONS
int vanilla_f2i_float(
    op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) {
  switch (special->byte_width) {
    case 1:
      CONVERT_F2I(float, int8_t, "%lf", "%hhd");
    case 2:
      CONVERT_F2I(float, int16_t, "%lf", "%hd");
    case 4:
      CONVERT_F2I(float, int32_t, "%lf", "%d");
    case 8:
      CONVERT_F2I(float, int64_t, "%lf", "%ld");
    default:
      MATH_ERROR("Cannot handle float->signed(%d)\n", special->byte_width);
      return -1;
      break;
  }
  return 0;
}

// THIS DOES NOT HANDLE THE SPECIAL CASES OR RAISE EXCEPTIONS
int vanilla_f2u_float(
    op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) {
  switch (special->byte_width) {
    case 1:
      CONVERT_F2I(float, uint8_t, "%lf", "%hhu");
    case 2:
      CONVERT_F2I(float, uint16_t, "%lf", "%hu");
    case 4:
      CONVERT_F2I(float, uint32_t, "%lf", "%u");
    case 8:
      CONVERT_F2I(float, uint64_t, "%lf", "%lu");
    default:
      MATH_ERROR("Cannot handle float->unsigned(%d)\n", special->byte_width);
      return -1;
      break;
  }
}

#define CONVERT_I2F(FTYPE, ITYPE, FSPEC, ISPEC)                                              \
  {                                                                                          \
    FTYPE result = (FTYPE)(*(ITYPE *)src1);                                                  \
    MATH_DEBUG("i2f[" #ITYPE " to " #FTYPE "](" #ISPEC ") = " #FSPEC " (%p)\n", (*(ITYPE *)src1), \
        result, dest);                                                                       \
    *(ITYPE *)dest = result;                                                                 \
    return 0;                                                                                \
  }

// THIS DOES NOT HANDLE THE SPECIAL CASES OR RAISE EXCEPTIONS
int vanilla_i2f_double(
    op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) {
  switch (special->byte_width) {
    case 1:
      CONVERT_I2F(double, int8_t, "%lf", "%hhd");
    case 2:
      CONVERT_I2F(double, int16_t, "%lf", "%hd");
    case 4:
      CONVERT_I2F(double, int32_t, "%lf", "%d");
    case 8:
      CONVERT_I2F(double, int64_t, "%lf", "%ld");
    default:
      MATH_ERROR("Cannot handle double->signed(%d)\n", special->byte_width);
      return -1;
      break;
  }
  return 0;
}

// THIS DOES NOT HANDLE THE SPECIAL CASES OR RAISE EXCEPTIONS
int vanilla_u2f_double(
    op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) {
  switch (special->byte_width) {
    case 1:
      CONVERT_I2F(double, uint8_t, "%lf", "%hhu");
    case 2:
      CONVERT_I2F(double, uint16_t, "%lf", "%hu");
    case 4:
      CONVERT_I2F(double, uint32_t, "%lf", "%u");
    case 8:
      CONVERT_I2F(double, uint64_t, "%lf", "%lu");
    default:
      MATH_ERROR("Cannot handle double->unsigned(%d)\n", special->byte_width);
      return -1;
      break;
  }
  return 0;
}

// THIS DOES NOT HANDLE THE SPECIAL CASES OR RAISE EXCEPTIONS
int vanilla_i2f_float(
    op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) {
  switch (special->byte_width) {
    case 1:
      CONVERT_I2F(float, int8_t, "%lf", "%hhd");
    case 2:
      CONVERT_I2F(float, int16_t, "%lf", "%hd");
    case 4:
      CONVERT_I2F(float, int32_t, "%lf", "%d");
    case 8:
      CONVERT_I2F(float, int64_t, "%lf", "%ld");
    default:
      MATH_ERROR("Cannot handle float->signed(%d)\n", special->byte_width);
      return -1;
      break;
  }
  return 0;
}

// THIS DOES NOT HANDLE THE SPECIAL CASES OR RAISE EXCEPTIONS
int vanilla_u2f_float(
    op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) {
  switch (special->byte_width) {
    case 1:
      CONVERT_I2F(float, uint8_t, "%lf", "%hhu");
    case 2:
      CONVERT_I2F(float, uint16_t, "%lf", "%hu");
    case 4:
      CONVERT_I2F(float, uint32_t, "%lf", "%u");
    case 8:
      CONVERT_I2F(float, uint64_t, "%lf", "%lu");
    default:
      MATH_ERROR("Cannot handle float->unsigned(%d)\n", special->byte_width);
      return -1;
      break;
  }
}

#define CONVERT_F2F(FITYPE, FOTYPE, FISPEC, FOSPEC)                                             \
  {                                                                                             \
    FOTYPE result = (FOTYPE)(*(FITYPE *)src1);                                                  \
    MATH_DEBUG("f2f[" #FITYPE " to " #FOTYPE "](" FISPEC ") = " FOSPEC " (%p)\n", (*(FITYPE *)src1), \
        result, dest);                                                                          \
    *(FOTYPE *)dest = result;                                                                   \
    return 0;                                                                                   \
  }

int vanilla_f2f_double(
    op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) {
  switch (special->byte_width) {
    case 4:
      CONVERT_F2F(double, float, "%lf", "%f");
    default:
      MATH_ERROR("Cannot handle double->float(%d)\n", special->byte_width);
      return -1;
      break;
  }
}

int vanilla_f2f_float(
    op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) {
  switch (special->byte_width) {
    case 8:
      CONVERT_F2F(float, double, "%f", "%lf");
    default:
      MATH_ERROR("Cannot handle float->float(%d)\n", special->byte_width);
      return -1;
      break;
  }
}


MOVE_OP(double,uint64_t,"%lf", "%016lx");
MOVE_OP(float,uint32_t,"%f", "%08x");


// masks for rflags condition code bits
#define RFLAGS_CF 0x1UL
#define RFLAGS_PF 0x4UL
#define RFLAGS_AF 0x10UL
#define RFLAGS_ZF 0x40UL
#define RFLAGS_SF 0x80UL
#define RFLAGS_OF 0x800UL

// note that this is the same between ordered and unordered compare
// ordered compare will raise INV if an operand is a nan
// which we do not handle...

int vanilla_cmp_double(
    op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) {
  double a = *(double *)src1;
  double b = *(double *)src2;
  uint64_t *rflags = special->rflags;
  int which = 0;

  *rflags &= ~(RFLAGS_OF | RFLAGS_AF | RFLAGS_SF | RFLAGS_ZF | RFLAGS_PF | RFLAGS_CF);

  if (isnan(a) || isnan(b)) {
    *rflags |= (RFLAGS_ZF | RFLAGS_PF | RFLAGS_CF);
    which = -2;
  } else {
    if (a < b) {
      *rflags |= (RFLAGS_CF);
      which = -1;
    } else if (a == b) {
      *rflags |= (RFLAGS_ZF);
      which = 0;
    } else {  // a>b
      // set nothing
      which = 1;
    }
  }

  MATH_DEBUG("double %s compare %lf %lf => flags %lx (%s)\n",
      special->unordered ? "unordered" : "ordered", a, b, *rflags,
      which == -2   ? "unordered"
      : which == -1 ? "less"
      : which == 0  ? "equal"
                    : "greater");

  (void)which;

  return 0;
}

int vanilla_cmp_float(
    op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) {
  float a = *(float *)src1;
  float b = *(float *)src2;
  uint64_t *rflags = special->rflags;
  int which = 0;

  *rflags &= ~(RFLAGS_OF | RFLAGS_AF | RFLAGS_SF | RFLAGS_ZF | RFLAGS_PF | RFLAGS_CF);

  if (isnan(a) || isnan(b)) {
    *rflags |= (RFLAGS_ZF | RFLAGS_PF | RFLAGS_CF);
    which = -2;
  } else {
    if (a < b) {
      *rflags |= (RFLAGS_CF);
      which = -1;
    } else if (a == b) {
      *rflags |= (RFLAGS_ZF);
      which = 0;
    } else {  // a>b
      // set nothing
      which = 1;
    }
  }

  MATH_DEBUG("float %s compare %f %f => flags %lx (%s)\n", special->unordered ? "unordered" : "ordered",
      a, b, *rflags,
      which == -2   ? "unordered"
      : which == -1 ? "less"
      : which == 0  ? "equal"
                    : "greater");

  (void)which;

  return 0;
}

int vanilla_cmpxx_double(
    op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) {
  double a = *(double *)src1;
  double b = *(double *)src2;
  uint64_t r=0;

  printf("special val: %d\n", special->compare_type);
  switch (special->compare_type) {
  case FPVM_INST_COMPARE_INVALID:
    ERROR("invalid compare - should not happen\n");
    return -1;
    break;
  case FPVM_INST_COMPARE_EQ:
    // ordered, signaling qnan
    r = a==b;
    break;
  case FPVM_INST_COMPARE_LT:
    // ordered, signaling qnan
    r = a<b;
    break;
  case FPVM_INST_COMPARE_LE:
    // ordered, signaling qnan
    r = a<=b;
    break;
  case FPVM_INST_COMPARE_UNORD:
    // unordered, non-signaling qnan
    r = isnan(a) || isnan(b);
    break;
  case FPVM_INST_COMPARE_NEQ:
    // ordered, signaling qnan
    r = a!=b;
    break;
  case FPVM_INST_COMPARE_NLT:
    // ordered, signaling qnan
    r = !(a<b);
    break;
  case FPVM_INST_COMPARE_NLE:
    // ordered, signaling qnan
    r = !(a<=b);
    break;
  case FPVM_INST_COMPARE_ORD:
    // ordered, signaling qnan
    r = !isnan(a) && !isnan(b);
    break;
  case FPVM_INST_COMPARE_EQ_UQ:
    // unordered, non-signaling qnan
    r = isnan(a) || isnan(b) || a==b;
    break;
  case FPVM_INST_COMPARE_NGE:
    // ordered, non-signaling qnan
    r = !(a>=b);
    break;
  case FPVM_INST_COMPARE_NGT:
    // ordered, non-signaling qnan
    r = !(a>b);
    break;
  case FPVM_INST_COMPARE_FALSE:
    // orderd, non-signaling
    r = 0;
    break;
  case FPVM_INST_COMPARE_NEQ_OQ:
    // ordered, non-signaling
    r = a!=b;
    break;
  case FPVM_INST_COMPARE_GE:
    // ordered, non-signaling
    r = a>=b;
    break;
  case FPVM_INST_COMPARE_GT:
    // ordered, non-signaling
    r = a>b;
    break;
  case FPVM_INST_COMPARE_TRUE:
    // ordered, non-signaling
    r = 1;
    break;
  case FPVM_INST_COMPARE_EQ_OS:
    // ordered, signaling
    r = a==b;
    break;
  case FPVM_INST_COMPARE_LT_OQ:
    // ordered, non-signaling
    r = a<b;
    break;
  case FPVM_INST_COMPARE_LE_OQ:
    // ordered, non-signaling
    r = a<=b;
    break;
  case FPVM_INST_COMPARE_UNORD_S:
    // unordered, signaling
    r = isnan(a) || isnan(b);
    break;
  case FPVM_INST_COMPARE_NEQ_US:
    // unordered, signaling
    r = isnan(a) || isnan(b) || a!=b;
    break;
  case FPVM_INST_COMPARE_NLT_UQ:
    // unordered, non-signaling
    r = isnan(a) || isnan(b) || !(a<b);
    break;
  case FPVM_INST_COMPARE_NLE_UQ:
    // unordered, non-signaling
    r = isnan(a) || isnan(b) || !(a<=b);
    break;
  case FPVM_INST_COMPARE_ORD_S:
    // ordered signaling
    r = !isnan(a) && !isnan(b);
    break;
  case FPVM_INST_COMPARE_EQ_US:
    // unordered, signalling
    r = isnan(a) || isnan(b) || a==b;
    break;
  case FPVM_INST_COMPARE_NGE_UQ:
    // unordered, non-signaling
    r = isnan(a) || isnan(b) || !(a>=b);
    break;
  case FPVM_INST_COMPARE_NGT_UQ:
    // unordered, non-signaling
    r = isnan(a) || isnan(b) || !(a>b);
    break;
  case FPVM_INST_COMPARE_FALSE_OS:
    // ordered, non-signaling
    r = 0;
    break;
  case FPVM_INST_COMPARE_NEQ_OS:
    // ordered, non-signaling
    r = a!=b;
    break;
  case FPVM_INST_COMPARE_GE_OQ:
    // ordered, non-signaling
    r = a>=b;
    break;
  case FPVM_INST_COMPARE_GT_OQ:
    // ordered, non-signaling
    r = a>b;
    break;
  case FPVM_INST_COMPARE_TRUE_US:
    r = 1;
    break;
  default:
    MATH_ERROR("unknown comparison type %d\n",special->compare_type);
    return -1;
    break;
  }

  MATH_DEBUG("cmpxx_double(%lf,%lf,%d) = %lu\n", a,b,special->compare_type,r);

  *(uint64_t*)dest=r ? -1 : 0;

  return 0;

}

int vanilla_cmpxx_float(
    op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) {
  float a = *(float *)src1;
  float b = *(float *)src2;
  uint32_t r=0;

  switch (special->compare_type) {
  case FPVM_INST_COMPARE_INVALID:
    ERROR("invalid compare - should not happen\n");
    return -1;
    break;
  case FPVM_INST_COMPARE_EQ:
    // ordered, signaling qnan
    r = a==b;
    break;
  case FPVM_INST_COMPARE_LT:
    // ordered, signaling qnan
    r = a<b;
    break;
  case FPVM_INST_COMPARE_LE:
    // ordered, signaling qnan
    r = a<=b;
    break;
  case FPVM_INST_COMPARE_UNORD:
    // unordered, non-signaling qnan
    r = isnan(a) || isnan(b);
    break;
  case FPVM_INST_COMPARE_NEQ:
    // ordered, signaling qnan
    r = a!=b;
    break;
  case FPVM_INST_COMPARE_NLT:
    // ordered, signaling qnan
    r = !(a<b);
    break;
  case FPVM_INST_COMPARE_NLE:
    // ordered, signaling qnan
    r = !(a<=b);
    break;
  case FPVM_INST_COMPARE_ORD:
    // ordered, signaling qnan
    r = !isnan(a) && !isnan(b);
    break;
  case FPVM_INST_COMPARE_EQ_UQ:
    // unordered, non-signaling qnan
    r = isnan(a) || isnan(b) || a==b;
    break;
  case FPVM_INST_COMPARE_NGE:
    // ordered, non-signaling qnan
    r = !(a>=b);
    break;
  case FPVM_INST_COMPARE_NGT:
    // ordered, non-signaling qnan
    r = !(a>b);
    break;
  case FPVM_INST_COMPARE_FALSE:
    // orderd, non-signaling
    r = 0;
    break;
  case FPVM_INST_COMPARE_NEQ_OQ:
    // ordered, non-signaling
    r = a!=b;
    break;
  case FPVM_INST_COMPARE_GE:
    // ordered, non-signaling
    r = a>=b;
    break;
  case FPVM_INST_COMPARE_GT:
    // ordered, non-signaling
    r = a>b;
    break;
  case FPVM_INST_COMPARE_TRUE:
    // ordered, non-signaling
    r = 1;
    break;
  case FPVM_INST_COMPARE_EQ_OS:
    // ordered, signaling
    r = a==b;
    break;
  case FPVM_INST_COMPARE_LT_OQ:
    // ordered, non-signaling
    r = a<b;
    break;
  case FPVM_INST_COMPARE_LE_OQ:
    // ordered, non-signaling
    r = a<=b;
    break;
  case FPVM_INST_COMPARE_UNORD_S:
    // unordered, signaling
    r = isnan(a) || isnan(b);
    break;
  case FPVM_INST_COMPARE_NEQ_US:
    // unordered, signaling
    r = isnan(a) || isnan(b) || a!=b;
    break;
  case FPVM_INST_COMPARE_NLT_UQ:
    // unordered, non-signaling
    r = isnan(a) || isnan(b) || !(a<b);
    break;
  case FPVM_INST_COMPARE_NLE_UQ:
    // unordered, non-signaling
    r = isnan(a) || isnan(b) || !(a<=b);
    break;
  case FPVM_INST_COMPARE_ORD_S:
    // ordered signaling
    r = !isnan(a) && !isnan(b);
    break;
  case FPVM_INST_COMPARE_EQ_US:
    // unordered, signalling
    r = isnan(a) || isnan(b) || a==b;
    break;
  case FPVM_INST_COMPARE_NGE_UQ:
    // unordered, non-signaling
    r = isnan(a) || isnan(b) || !(a>=b);
    break;
  case FPVM_INST_COMPARE_NGT_UQ:
    // unordered, non-signaling
    r = isnan(a) || isnan(b) || !(a>b);
    break;
  case FPVM_INST_COMPARE_FALSE_OS:
    // ordered, non-signaling
    r = 0;
    break;
  case FPVM_INST_COMPARE_NEQ_OS:
    // ordered, non-signaling
    r = a!=b;
    break;
  case FPVM_INST_COMPARE_GE_OQ:
    // ordered, non-signaling
    r = a>=b;
    break;
  case FPVM_INST_COMPARE_GT_OQ:
    // ordered, non-signaling
    r = a>b;
    break;
  case FPVM_INST_COMPARE_TRUE_US:
    r = 1;
    break;
  default:
    MATH_ERROR("unknown comparison type %d\n",special->compare_type);
    return -1;
    break;
  }

  MATH_DEBUG("cmpxx_float(%f,%f,%d) = %u\n", a,b,special->compare_type,r);

  *(uint32_t*)dest = r;
  
  return 0;

}

#if CONFIG_ALT_MATH_VANILLA
// we only have this package, so we need to provide inits

#define ORIG_IF_CAN(func, ...)                                          \
  if (orig_##func) {                                                    \
    if (!CONFIG_DEBUG_ALT_ARITH) {                                                \
      orig_##func(__VA_ARGS__);                                         \
    } else {                                                            \
      MATH_DEBUG("orig_" #func " returns 0x%x\n", orig_##func(__VA_ARGS__)); \
    }                                                                   \
  } else {                                                              \
    MATH_DEBUG("cannot call orig_" #func " - skipping\n");                   \
  }

#define MATH_STUB_ONE(NAME, TYPE, RET)                    \
  RET NAME(TYPE a) {                                      \
    ORIG_IF_CAN(fedisableexcept, FE_ALL_EXCEPT);          \
    RET ori = orig_##NAME(a);                             \
    MATH_DEBUG(#NAME " input (%lf ) result (%lf) \n", a, ori); \
    ORIG_IF_CAN(feenableexcept, FE_ALL_EXCEPT);           \
    ORIG_IF_CAN(feclearexcept, FE_ALL_EXCEPT);            \
    return ori;                                           \
  }

#define MATH_STUB_TWO(NAME, TYPE, RET)                          \
  RET NAME(TYPE a, TYPE b) {                                    \
    ORIG_IF_CAN(fedisableexcept, FE_ALL_EXCEPT);                \
    RET ori = orig_##NAME(a, b);                                \
    MATH_DEBUG(#NAME " input (%lf , %lf) result %lf \n", a, b, ori); \
    ORIG_IF_CAN(feenableexcept, FE_ALL_EXCEPT);                 \
    ORIG_IF_CAN(feclearexcept, FE_ALL_EXCEPT);                  \
    return ori;                                                 \
  }

#define MATH_STUB_MIXED(NAME, TYPE1, TYPE2, RET)               \
  RET NAME(TYPE1 a, TYPE2 b) {                                 \
    ORIG_IF_CAN(fedisableexcept, FE_ALL_EXCEPT);               \
    RET ori = orig_##NAME(a, b);                               \
    MATH_DEBUG(#NAME " input (%lf , %d) result %lf \n", a, b, ori); \
    ORIG_IF_CAN(feenableexcept, FE_ALL_EXCEPT);                \
    ORIG_IF_CAN(feclearexcept, FE_ALL_EXCEPT);                 \
    return ori;                                                \
  }

void sincos(double a, double *sin, double *cos) {
  ORIG_IF_CAN(fedisableexcept, FE_ALL_EXCEPT);
  orig_sincos(a, sin, cos);
  // MATH_DEBUG(#NAME " input (%lf , %d) result %lf \n", a, , ori);
  ORIG_IF_CAN(feenableexcept, FE_ALL_EXCEPT);
  ORIG_IF_CAN(feclearexcept, FE_ALL_EXCEPT);
  return;
}

MATH_STUB_TWO(pow, double, double)
MATH_STUB_ONE(log, double, double)
MATH_STUB_ONE(exp, double, double)
MATH_STUB_ONE(sin, double, double)
MATH_STUB_ONE(cos, double, double)
MATH_STUB_ONE(tan, double, double)

MATH_STUB_ONE(log10, double, double)
MATH_STUB_ONE(ceil, double, double)
MATH_STUB_ONE(floor, double, double)
MATH_STUB_ONE(round, double, double)
MATH_STUB_ONE(lround, double, long int)
MATH_STUB_MIXED(ldexp, double, int, double)
MATH_STUB_MIXED(__powidf2, double, int, double)

MATH_STUB_ONE(sinh, double, double)
MATH_STUB_ONE(cosh, double, double)
MATH_STUB_ONE(tanh, double, double)

MATH_STUB_ONE(asin, double, double)
MATH_STUB_ONE(acos, double, double)
MATH_STUB_ONE(atan, double, double)
MATH_STUB_ONE(asinh, double, double)
MATH_STUB_ONE(acosh, double, double)
MATH_STUB_ONE(atanh, double, double)

MATH_STUB_TWO(atan2, double, double)

// demote
int restore_double(
    op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) {
  // do nothing since src1..src4 are already demoted (not-nanboxed)

  return 0;
}

void NO_TOUCH_FLOAT restore_double_in_place(uint64_t *p)
{
  // does not do anything for vanilla
}


// demote
int restore_float(
    op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) {
  // should be an error
  return 0;
}

// demote - does nothing
int NO_TOUCH_FLOAT restore_xmm(void *ptr) {
  return 0;
}

void fpvm_number_init(void *ptr) {
  (void)ptr;
}

// TODO
void fpvm_number_deinit(void *ptr) {
  (void)ptr;
}
#endif

#endif
