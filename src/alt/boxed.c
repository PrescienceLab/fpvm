#include <fpvm/config.h>

#if CONFIG_ALT_MATH_BOXED_IEEE

#define RFLAGS_CF 0x1UL
#define RFLAGS_PF 0x4UL
#define RFLAGS_AF 0x10UL
#define RFLAGS_ZF 0x40UL
#define RFLAGS_SF 0x80UL
#define RFLAGS_OF 0x800UL

#include <math.h>
#include <stdlib.h>
#include <string.h>

#include <fpvm/fpvm_common.h>
#include <fpvm/fpvm_fenv.h>
#include <fpvm/fpvm_math.h>
#include <fpvm/gc.h>
#include <fpvm/number_system.h>
#include <fpvm/number_system/nan_boxing.h>

#define MALLOC_ALIGN_16 fpvm_gc_alloc

#ifdef DEBUG
#undef DEBUG
#define DEBUG(...)
#endif

#define EXIT(d) exit(d)  // not exit , what if there is really a nan

#define NANBOX(ITYPE, dest, nan_encoded) *(ITYPE *)dest = nan_encoded
// #define NANBOX(ITYPE, dest, nan_encoded)
// #define _NANBOX(ITYPE, dest, nan_encoded)

#define IEEE_REVERT_SIGN(ITYPE, TYPE, ptr_val, dest)                                              \
  {                                                                                               \
    DEBUG("CHECK IS THIS WIRED ? %016lx \n", *(uint64_t *)dest);                                  \
    volatile TYPE *_per_result = (TYPE *)MALLOC_ALIGN_16(sizeof(TYPE));                           \
    memset(_per_result, 0, sizeof(TYPE));                                                         \
    *_per_result = -*(TYPE *)ptr_val;                                                             \
    volatile ITYPE _nan_encoded = NANBOX_ENCODE((uint64_t)_per_result, *(uint64_t *)_per_result); \
    DEBUG("Nanbox result addr %p value %lf  \n", _per_result, *_per_result);                      \
    NANBOX(ITYPE, dest, _nan_encoded);                                                            \
    ptr_val = _per_result;                                                                        \
  }

#define BIN_OP(TYPE, ITYPE, NAME, OP, SPEC, ISPEC)                                                 \
  int NAME##_##TYPE(                                                                               \
      op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) {         \
    void *src_or1 = src1, *src_or2 = src2;                                                         \
    DEBUG(ISNAN(*(uint64_t *)src1) ? "True " : "False ");                                          \
    DEBUG(ISNAN(*(uint64_t *)src2) ? "True \n" : "False \n");                                      \
    DEBUG("src1 %p , %016lx,  src2 %p, %016lx \n", src1, *(uint64_t *)src1, src2,                  \
        *(uint64_t *)src2);                                                                        \
    if (ISNAN(*(uint64_t *)src1)) {                                                                \
      src1 = (void *)NANBOX_DECODE(*(uint64_t *)src1);                                             \
    }                                                                                              \
    if (ISNAN(*(uint64_t *)src2)) {                                                                \
      src2 = (void *)NANBOX_DECODE(*(uint64_t *)src2);                                             \
    }                                                                                              \
                                                                                                   \
    if (CORRUPTED(*(uint64_t *)src_or1, *(uint64_t *)src1))                                        \
      IEEE_REVERT_SIGN(ITYPE, TYPE, src1, src_or1);                                                \
    if (CORRUPTED(*(uint64_t *)src_or2, *(uint64_t *)src2))                                        \
      IEEE_REVERT_SIGN(ITYPE, TYPE, src2, src_or2);                                                \
    if (isnan(*(double *)src1)) {                                                                  \
      ERROR(                                                                                       \
          "not my nan, try fix %p ori ptr %p, val %016lx\n", src1, src_or1, *(uint64_t *)src_or1); \
      EXIT(1);                                                                                     \
    }                                                                                              \
    if (isnan(*(double *)src2)) {                                                                  \
      ERROR(                                                                                       \
          "not my nan, try fix %p ori ptr %p, val %016lx\n", src2, src_or2, *(uint64_t *)src_or2); \
      EXIT(1);                                                                                     \
    }                                                                                              \
    DEBUG("decoded src1 %p , %016lx,  src2 %p, %016lx \n", src1, *(uint64_t *)src1, src2,          \
        *(uint64_t *)src2);                                                                        \
    TYPE result = (*(TYPE *)src1)OP(*(TYPE *)src2);                                                \
                                                                                                   \
    volatile TYPE *per_result = (TYPE *)MALLOC_ALIGN_16(sizeof(TYPE));                             \
    memset(per_result, 0, sizeof(TYPE));                                                           \
    *per_result = result;                                                                          \
    volatile ITYPE nan_encoded = NANBOX_ENCODE((uint64_t)per_result, *(uint64_t *)&result);        \
    DEBUG(#NAME "_" #TYPE ": " SPEC " " #OP " " SPEC " = " SPEC " [" ISPEC "] (%p)\n",             \
        *(TYPE *)src1, *(TYPE *)src2, result, *(ITYPE *)&result, dest);                            \
    *(TYPE *)dest = result;                                                                        \
    DEBUG("Nanbox result addr %p value %lf  \n", per_result, *per_result);                         \
    NANBOX(ITYPE, dest, nan_encoded);                                                              \
                                                                                                   \
    return 0;                                                                                      \
  }

#define UN_FUNC(TYPE, ITYPE, NAME, FUNC, SPEC, ISPEC)                                           \
  int NAME##_##TYPE(                                                                            \
      op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) {      \
    void *src_or1 = src1;                                                                       \
    DEBUG(ISNAN(*(uint64_t *)src1) ? "True \n" : "False \n");                                   \
    DEBUG("src1 %p , %016lx\n", src1, *(uint64_t *)src1);                                       \
    if (ISNAN(*(uint64_t *)src1)) src1 = (void *)NANBOX_DECODE(*(uint64_t *)src1);              \
    if (CORRUPTED(*(uint64_t *)src_or1, *(uint64_t *)src1))                                     \
      IEEE_REVERT_SIGN(ITYPE, TYPE, src1, src_or1);                                             \
    TYPE result = FUNC((*(TYPE *)src1));                                                        \
                                                                                                \
    volatile TYPE *per_result = (TYPE *)MALLOC_ALIGN_16(sizeof(TYPE));                          \
    memset(per_result, 0, sizeof(TYPE));                                                        \
    *per_result = result;                                                                       \
    volatile ITYPE nan_encoded = NANBOX_ENCODE((uint64_t)per_result, *(uint64_t *)&result);     \
    DEBUG(#NAME "_" #TYPE ": " #FUNC "(" SPEC ") = " SPEC " [" ISPEC "] (%p)\n", *(TYPE *)src1, \
        result, *(ITYPE *)&result, dest);                                                       \
    *(TYPE *)dest = result;                                                                     \
    DEBUG("Nanbox result addr %p value %lf  \n", per_result, *per_result);                      \
    NANBOX(ITYPE, dest, nan_encoded);                                                           \
                                                                                                \
    return 0;                                                                                   \
  }

#define BIN_FUNC(TYPE, ITYPE, NAME, FUNC, SPEC, ISPEC)                                      \
  int NAME##_##TYPE(                                                                        \
      op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) {  \
    void *src_or1 = src1, *src_or2 = src2;                                                  \
    DEBUG(ISNAN(*(uint64_t *)src1) ? "True " : "False ");                                   \
    DEBUG(ISNAN(*(uint64_t *)src2) ? "True \n" : "False \n");                               \
    DEBUG("src1 %p , %016lx,  src2 %p, %016lx \n", src1, *(uint64_t *)src1, src2,           \
        *(uint64_t *)src2);                                                                 \
    if (ISNAN(*(uint64_t *)src1)) src1 = (void *)NANBOX_DECODE(*(uint64_t *)src1);          \
    if (ISNAN(*(uint64_t *)src2)) src2 = (void *)NANBOX_DECODE(*(uint64_t *)src2);          \
    if (CORRUPTED(*(uint64_t *)src_or1, *(uint64_t *)src1))                                 \
      IEEE_REVERT_SIGN(ITYPE, TYPE, src1, src_or1);                                         \
    if (CORRUPTED(*(uint64_t *)src_or2, *(uint64_t *)src2))                                 \
      IEEE_REVERT_SIGN(ITYPE, TYPE, src2, src_or2);                                         \
    TYPE result = FUNC((*(TYPE *)src1), (*(TYPE *)src2));                                   \
                                                                                            \
    volatile TYPE *per_result = (TYPE *)MALLOC_ALIGN_16(sizeof(TYPE));                      \
    memset(per_result, 0, sizeof(TYPE));                                                    \
    *per_result = result;                                                                   \
    volatile ITYPE nan_encoded = NANBOX_ENCODE((uint64_t)per_result, *(uint64_t *)&result); \
    DEBUG(#NAME "_" #TYPE ": " #FUNC "(" SPEC ", " SPEC ") = " SPEC " [" ISPEC "] (%p)\n",  \
        *(TYPE *)src1, *(TYPE *)src2, result, *(ITYPE *)&result, dest);                     \
    *(TYPE *)dest = result;                                                                 \
    DEBUG("Nanbox result addr %p value %lf  \n", per_result, *per_result);                  \
    NANBOX(ITYPE, dest, nan_encoded);                                                       \
                                                                                            \
    return 0;                                                                               \
  }

#define FUSED_OP(TYPE, ITYPE, NAME, OP1, NEGOP, OP2, SPEC, ISPEC)                                  \
  int NAME##_##TYPE(                                                                               \
      op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) {         \
    void *src_or1 = src1, *src_or2 = src2, *src_or3 = src3;                                        \
    DEBUG(ISNAN(*(uint64_t *)src1) ? "True " : "False ");                                          \
    DEBUG(ISNAN(*(uint64_t *)src2) ? "True " : "False ");                                          \
    DEBUG(ISNAN(*(uint64_t *)src3) ? "True \n" : "False \n");                                      \
    DEBUG("src1 %p , %016lx,  src2 %p, %016lx, src3 %p, %016lx \n", src1, *(uint64_t *)src1, src2, \
        *(uint64_t *)src2, src3, *(uint64_t *)src3);                                               \
    if (ISNAN(*(uint64_t *)src1)) src1 = (void *)NANBOX_DECODE(*(uint64_t *)src1);                 \
    if (ISNAN(*(uint64_t *)src2)) src2 = (void *)NANBOX_DECODE(*(uint64_t *)src2);                 \
    if (ISNAN(*(uint64_t *)src3)) src3 = (void *)NANBOX_DECODE(*(uint64_t *)src3);                 \
    if (CORRUPTED(*(uint64_t *)src_or1, *(uint64_t *)src1))                                        \
      IEEE_REVERT_SIGN(ITYPE, TYPE, src1, src_or1);                                                \
    if (CORRUPTED(*(uint64_t *)src_or2, *(uint64_t *)src2))                                        \
      IEEE_REVERT_SIGN(ITYPE, TYPE, src2, src_or2);                                                \
    if (CORRUPTED(*(uint64_t *)src_or3, *(uint64_t *)src3))                                        \
      IEEE_REVERT_SIGN(ITYPE, TYPE, src3, src_or3);                                                \
    TYPE result = (NEGOP((*(TYPE *)src1)OP1(*(TYPE *)src2)))OP2(*(TYPE *)src3);                    \
                                                                                                   \
    volatile TYPE *per_result = (TYPE *)MALLOC_ALIGN_16(sizeof(TYPE));                             \
    memset(per_result, 0, sizeof(TYPE));                                                           \
    *per_result = result;                                                                          \
    volatile ITYPE nan_encoded = NANBOX_ENCODE((uint64_t)per_result, *(uint64_t *)&result);        \
    DEBUG(#NAME "_" #TYPE ": (" #NEGOP "( " SPEC " " #OP1 " " SPEC " ) ) " #OP2 " " SPEC           \
                " = " SPEC " [" ISPEC "] (%p)\n",                                                  \
        *(TYPE *)src1, *(TYPE *)src2, *(TYPE *)src3, result, *(ITYPE *)&result, dest);             \
    *(TYPE *)dest = result;                                                                        \
    DEBUG("Nanbox result addr %p value %lf  \n", per_result, *per_result);                         \
    NANBOX(ITYPE, dest, nan_encoded);                                                              \
                                                                                                   \
    return 0;                                                                                      \
  }

static inline double maxd(double a, double b) {
  DEBUG("maxd \n");
  if (a > b) {
    return a;
  } else {
    return b;
  }
}
static inline double mind(double a, double b) {
  DEBUG("mind \n");

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

/* static int sqrt_double(void *dest, void *src1, void *src2, void *src3, void
 * *src4) */
/* { */
/*   double result =  sqrt(*(double*)src1); */
/*   DEBUG("sqrt_double: sqrt(%lf) = %lf [%016lx] (%p)\n", *(double*)src1,
 * result, *(uint64_t*)&result, dest ); */
/*   *(double*)dest = result; */
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
    DEBUG("f2i[" #FTYPE " to " #ITYPE "](" FSPEC ") = " ISPEC " (%p)\n", (*(FTYPE *)src1), result, \
        dest);                                                                                     \
    *(ITYPE *)dest = result;                                                                       \
    return 0;                                                                                      \
  }

#define DOUBLE_CONVERT_F2I(FTYPE, ITYPE, FSPEC, ISPEC)                                             \
  {                                                                                                \
    void *src_or1 = src1;                                                                          \
    DEBUG("src1 %p , %016lx\n", src1, *(uint64_t *)src1);                                          \
    if (ISNAN(*(uint64_t *)src1)) src1 = (void *)NANBOX_DECODE(*(uint64_t *)src1);                 \
    if (CORRUPTED(*(uint64_t *)src_or1, *(uint64_t *)src1))                                        \
      IEEE_REVERT_SIGN(uint64_t, double, src1, src_or1);                                           \
    ITYPE result = (ITYPE)(*(FTYPE *)src1);                                                        \
    DEBUG("f2i[" #FTYPE " to " #ITYPE "](" FSPEC ") = " ISPEC " (%p)\n", (*(FTYPE *)src1), result, \
        dest);                                                                                     \
    *(ITYPE *)dest = result;                                                                       \
    return 0;                                                                                      \
  }

// THIS DOES NOT HANDLE THE SPECIAL CASES OR RAISE EXCEPTIONS
int f2i_double(op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) {
  switch (special->byte_width) {
    case 1:
      DOUBLE_CONVERT_F2I(double, int8_t, "%lf", "%hhd");
    case 2:
      DOUBLE_CONVERT_F2I(double, int16_t, "%lf", "%hd");
    case 4:
      DOUBLE_CONVERT_F2I(double, int32_t, "%lf", "%d");
    case 8:
      DOUBLE_CONVERT_F2I(double, int64_t, "%lf", "%ld");
    default:
      ERROR("Cannot handle double->signed(%d)\n", special->byte_width);
      return -1;
      break;
  }
  return 0;
}

// THIS DOES NOT HANDLE THE SPECIAL CASES OR RAISE EXCEPTIONS
int f2u_double(op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) {
  switch (special->byte_width) {
    case 1:
      DOUBLE_CONVERT_F2I(double, uint8_t, "%lf", "%hhu");
    case 2:
      DOUBLE_CONVERT_F2I(double, uint16_t, "%lf", "%hu");
    case 4:
      DOUBLE_CONVERT_F2I(double, uint32_t, "%lf", "%u");
    case 8:
      DOUBLE_CONVERT_F2I(double, uint64_t, "%lf", "%lu");
    default:
      ERROR("Cannot handle double->unsigned(%d)\n", special->byte_width);
      return -1;
      break;
  }
  return 0;
}

int f2u_float(op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) {
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
      ERROR("Cannot handle float->unsigned(%d)\n", special->byte_width);
      return -1;
      break;
  }
}

#define CONVERT_I2F(FTYPE, ITYPE, FSPEC, ISPEC)                                              \
  {                                                                                          \
    FTYPE result = (FTYPE)(*(ITYPE *)src1);                                                  \
    DEBUG("i2f[" #ITYPE " to " #FTYPE "](" #ISPEC ") = " #FSPEC " (%p)\n", (*(ITYPE *)src1), \
        result, dest);                                                                       \
    *(uint64_t *)dest = *(uint64_t *)&result;                                                \
    return 0;                                                                                \
  }

// THIS DOES NOT HANDLE THE SPECIAL CASES OR RAISE EXCEPTIONS
int i2f_double(op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) {
  // special->operand_width = 8;
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
      ERROR("Cannot handle double->signed(%d)\n", special->byte_width);
      return -1;
      break;
  }
  return 0;
}

// THIS DOES NOT HANDLE THE SPECIAL CASES OR RAISE EXCEPTIONS
int u2f_double(op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) {
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
      ERROR("Cannot handle double->unsigned(%d)\n", special->byte_width);
      return -1;
      break;
  }
  return 0;
}

#define DOUBLE_CONVERT_F2F(FITYPE, FOTYPE, FISPEC, FOSPEC)                                      \
  {                                                                                             \
    void *src_or1 = src1;                                                                       \
    DEBUG("src1 %p , %016lx\n", src1, *(uint64_t *)src1);                                       \
    if (ISNAN(*(uint64_t *)src1)) src1 = (void *)NANBOX_DECODE(*(uint64_t *)src1);              \
    if (CORRUPTED(*(uint64_t *)src_or1, *(uint64_t *)src1))                                     \
      IEEE_REVERT_SIGN(uint64_t, double, src1, src_or1);                                        \
    FOTYPE result = (FOTYPE)(*(FITYPE *)src1);                                                  \
    DEBUG("f2f[" #FITYPE " to " #FOTYPE "](" FISPEC ") = " FOSPEC " (%p)\n", (*(FITYPE *)src1), \
        result, dest);                                                                          \
    *(FOTYPE *)dest = result;                                                                   \
    return 0;                                                                                   \
  }

#define CONVERT_F2F(FITYPE, FOTYPE, FISPEC, FOSPEC)                                             \
  {                                                                                             \
    if (ISNAN(*(uint64_t *)src1)) src1 = (void *)NANBOX_DECODE(*(uint64_t *)src1);              \
    FOTYPE result = (FOTYPE)(*(FITYPE *)src1);                                                  \
    DEBUG("f2f[" #FITYPE " to " #FOTYPE "](" FISPEC ") = " FOSPEC " (%p)\n", (*(FITYPE *)src1), \
        result, dest);                                                                          \
    *(FOTYPE *)dest = result;                                                                   \
    return 0;                                                                                   \
  }

int f2f_double(op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) {
  switch (special->byte_width) {
    case 4:
      DOUBLE_CONVERT_F2F(double, float, "%lf", "%f");
    // case 4: CONVERT_F2F(double,float,"%lf","%f");
    default:
      ERROR("Cannot handle double->float(%d)\n", special->byte_width);
      return -1;
      break;
  }
}

int f2f_float(op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) {
  switch (special->byte_width) {
    case 8:
      CONVERT_F2F(float, double, "%f", "%lf");
    default:
      ERROR("Cannot handle float->float(%d)\n", special->byte_width);
      return -1;
      break;
  }
}

int f2i_float(op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) {
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
      ERROR("Cannot handle float->signed(%d)\n", special->byte_width);
      return -1;
      break;
  }
  return 0;
}

// note that this is the same between ordered and unordered compare
// ordered compare will raise INV if an operand is a nan
// which we do not handle...

int cmp_double(op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) {
  void *src_or1 = src1, *src_or2 = src2;
  DEBUG("CMP !!!!! WTF deal with it \n");
  DEBUG("%s\n", ISNAN(*(uint64_t *)src1) ? "True " : "False ");
  DEBUG("%s\n", ISNAN(*(uint64_t *)src2) ? "True \n" : "False \n");
  DEBUG("src1 %p , %016lx,  src2 %p, %016lx \n", src1, *(uint64_t *)src1, src2, *(uint64_t *)src2);
  if (ISNAN(*(uint64_t *)src1)) {
    src1 = (void *)NANBOX_DECODE(*(uint64_t *)src1);
  }
  if (ISNAN(*(uint64_t *)src2)) {
    src2 = (void *)NANBOX_DECODE(*(uint64_t *)src2);
  }

  if (CORRUPTED(*(uint64_t *)src_or1, *(uint64_t *)src1))
    IEEE_REVERT_SIGN(uint64_t, double, src1, src_or1);
  if (CORRUPTED(*(uint64_t *)src_or2, *(uint64_t *)src2))
    IEEE_REVERT_SIGN(uint64_t, double, src2, src_or2);

  if (isnan(*(double *)src1)) {
    ERROR("not my nan, try fix %p ori ptr %p, val %016lx\n", src1, src_or1, *(uint64_t *)src1);
    EXIT(1);
  }
  if (isnan(*(double *)src2)) {
    ERROR("not my nan, try fix %p ori ptr %p, val %016lx\n", src2, src_or2, *(uint64_t *)src2);
    EXIT(1);
  }

  double a = *(double *)src1;
  double b = *(double *)src2;
  uint64_t *rflags = special->rflags;
  int which;
  (void)which;

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

  DEBUG("double %s compare %lf %lf => flags %lx (%s)\n",
      special->unordered ? "unordered" : "ordered", a, b, *rflags,
      which == -2   ? "unordered"
      : which == -1 ? "less"
      : which == 0  ? "equal"
                    : "greater");

  return 0;
}

int ltcmp_double(
    op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) {
  void *src_or1 = src1, *src_or2 = src2;
  DEBUG("LTCMP !!!!! WTF deal with it \n");
  DEBUG("%s\n", ISNAN(*(uint64_t *)src1) ? "True " : "False ");
  DEBUG("%s\n", ISNAN(*(uint64_t *)src2) ? "True \n" : "False \n");
  DEBUG("src1 %p , %016lx,  src2 %p, %016lx \n", src1, *(uint64_t *)src1, src2, *(uint64_t *)src2);
  if (ISNAN(*(uint64_t *)src1)) {
    src1 = (void *)NANBOX_DECODE(*(uint64_t *)src1);
  }
  if (ISNAN(*(uint64_t *)src2)) {
    src2 = (void *)NANBOX_DECODE(*(uint64_t *)src2);
  }
  if (CORRUPTED(*(uint64_t *)src_or1, *(uint64_t *)src1))
    IEEE_REVERT_SIGN(uint64_t, double, src1, src_or1);
  if (CORRUPTED(*(uint64_t *)src_or2, *(uint64_t *)src2))
    IEEE_REVERT_SIGN(uint64_t, double, src2, src_or2);
  if (isnan(*(double *)src1)) {
    ERROR("not my nan, try fix %p ori ptr %p, val %016lx\n", src1, src_or1, *(uint64_t *)src_or1);
    EXIT(1);
  }
  if (isnan(*(double *)src2)) {
    ERROR("not my nan, try fix %p ori ptr %p, val %016lx\n", src2, src_or2, *(uint64_t *)src_or2);
    EXIT(1);
  }
  DEBUG(
      "fault skip ? src1 %p , %lf,  src2 %p, %lf \n", src1, *(double *)src1, src2, *(double *)src2);
  double a = *(double *)src1;
  double b = *(double *)src2;
  int which;
  (void)which;
  // uint64_t *rflags = special->rflags;
  // *rflags &= ~(RFLAGS_OF | RFLAGS_AF | RFLAGS_SF | RFLAGS_ZF | RFLAGS_PF |
  // RFLAGS_CF);

  if (isnan(a) || isnan(b)) {
    DEBUG("fault here -1 %p \n", dest);
    // *rflags |= (RFLAGS_ZF | RFLAGS_PF | RFLAGS_CF);
    which = -2;
  } else {
    if (a < b) {
      DEBUG("fault here 1 %p \n", dest);
      *(uint64_t *)dest = 0xffffffffffffffffUL;
      // *(uint64_t*)dest = 0x0000000000000000UL;
      // *(uint64_t*)dest = 0x1UL<<64;
      which = -1;
    } else {  // a>b
      // set nothing
      DEBUG("fault here 2 %p \n", dest);
      *(uint64_t *)dest = 0x0000000000000000UL;
      which = 1;
    }
  }
  DEBUG("done here\n");
  // DEBUG("double %s compare %lf %lf => flags %lx (%s)\n", special->unordered ?
  // "unordered" : "ordered", a,b,*rflags, which==-2 ? "unordered" : which==-1 ?
  // "less" :  "equal/greater");

  return 0;
}

BIN_FUNC(double, uint64_t, max, maxd, "%lf", "%016lx");
BIN_FUNC(double, uint64_t, min, mind, "%lf", "%016lx");
BIN_OP(double, uint64_t, add, +, "%lf", "%016lx");
BIN_OP(double, uint64_t, sub, -, "%lf", "%016lx");
BIN_OP(double, uint64_t, div, /, "%lf", "%016lx");
BIN_OP(double, uint64_t, mul, *, "%lf", "%016lx");
FUSED_OP(double, uint64_t, madd, *, +, +, "%lf", "%016lx");
FUSED_OP(double, uint64_t, nmadd, *, -, +, "%lf", "%016lx");
FUSED_OP(double, uint64_t, msub, *, +, -, "%lf", "%016lx");
FUSED_OP(double, uint64_t, nmsub, *, -, -, "%lf", "%016lx");
UN_FUNC(double, uint64_t, sqrt, sqrt, "%lf", "%016lx");

// #define max_float max_double
// #define min_float min_double
// #define add_float add_double
// #define sub_float sub_double
// #define mul_float mul_double
// #define div_float div_double
// #define sqrt_float sqrt_double
// #define madd_float madd_double
// #define nmadd_float nmadd_double
// #define ltcmp_float ltcmp_double
// #define cmp_float cmp_double

#define DECL_DEFINITION(FUNC, TYPE) \
  FPVM_MATH_DECL(FUNC, TYPE) {      \
    printf("Nice.\n");              \
    return 0;                       \
  }

DECL_DEFINITION(add, float)
DECL_DEFINITION(sub, float)
DECL_DEFINITION(mul, float)
DECL_DEFINITION(div, float)
DECL_DEFINITION(max, float)
DECL_DEFINITION(min, float)
DECL_DEFINITION(sqrt, float)
DECL_DEFINITION(madd, float)
DECL_DEFINITION(nmadd, float)
DECL_DEFINITION(msub, float)
DECL_DEFINITION(nmsub, float)
DECL_DEFINITION(cmp, float)
DECL_DEFINITION(ltcmp, float)
DECL_DEFINITION(i2f, float)
DECL_DEFINITION(u2f, float)

// unary functions

// FPVM_MATH_DECL(i2f, double) {
//     printf("Nice.\n");
//     return 0;
// }
// FPVM_MATH_DECL(u2f, double) {
//     printf("Nice.\n");
//     return 0;
// }

// restore function

int restore_double(
    op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) {
// ERROR("About to restore %016lx  %016lx \n", *(uint64_t*) src1,  *(uint64_t*)
// src2);
#define n 4
  void *allsrc[n] = {src1, src2, src3, src4};
  for (int i = 0; i < n; i++) {
    uint64_t *src = (void *)allsrc[i];  // src1 is mem op
    if (src != NULL && ISNAN(*(uint64_t *)src)) {
      double a = *(double *)NANBOX_DECODE(*(uint64_t *)src);
      a = (CORRUPTED(*(uint64_t *)src, *(uint64_t *)&a) ? -a : a);
      *(uint64_t *)src = *(uint64_t *)&a;
    }
  }

  return 0;
}
int restore_float(
    op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) {
  // skip float
  return 0;
}

int restore_xmm(void *xmm_ptr) {
  uint64_t *src = (uint64_t *)xmm_ptr;  // src1 is mem op
  // printf("captures call here\n");
  if (src != NULL && ISNAN(*(uint64_t *)src)) {
    double a = *(double *)NANBOX_DECODE(*(uint64_t *)src);
    a = (CORRUPTED(*(uint64_t *)src, *(uint64_t *)&a) ? -a : a);
    *(uint64_t *)src = *(uint64_t *)&a;
    // printf("xmm0 value after %lf \n", *(uint64_t*) xmm_ptr);
  }
  // iterate to next one in xmm
  src = (uint64_t *)((char *)src + 8);
  // ERROR("%p - %p\n", src, xmm_ptr);
  if (src != NULL && ISNAN(*(uint64_t *)src)) {
    double a = *(double *)NANBOX_DECODE(*(uint64_t *)src);
    a = (CORRUPTED(*(uint64_t *)src, *(uint64_t *)&a) ? -a : a);
    *(uint64_t *)src = *(uint64_t *)&a;
    // printf("xmm0 value after %lf \n", *(uint64_t*) xmm_ptr);
  }
  return 0;
}

#define ORIG_IF_CAN(func, ...)                                          \
  if (orig_##func) {                                                    \
    if (!DEBUG_OUTPUT) {                                                \
      orig_##func(__VA_ARGS__);                                         \
    } else {                                                            \
      DEBUG("orig_" #func " returns 0x%x\n", orig_##func(__VA_ARGS__)); \
    }                                                                   \
  } else {                                                              \
    DEBUG("cannot call orig_" #func " - skipping\n");                   \
  }

#define RECOVER(a, xmm)                                                                      \
  {                                                                                          \
    if (ISNAN(*(uint64_t *)&a)) {                                                            \
      xmm = (void *)NANBOX_DECODE(*(uint64_t *)&a);                                          \
      a = (CORRUPTED(*(uint64_t *)&a, *(uint64_t *)xmm) ? -*(double *)xmm : *(double *)xmm); \
    }                                                                                        \
  }

#define MATH_STUB_ONE(NAME, TYPE, RET)           \
  RET NAME(TYPE a) {                             \
    ORIG_IF_CAN(fedisableexcept, FE_ALL_EXCEPT); \
    void *xmm1;                                  \
    RECOVER(a, xmm1);                            \
    RET ori = orig_##NAME(a);                    \
    DEBUG(#NAME " input (%lf ) result \n", a);   \
    ORIG_IF_CAN(feenableexcept, FE_ALL_EXCEPT);  \
    ORIG_IF_CAN(feclearexcept, FE_ALL_EXCEPT);   \
    return ori;                                  \
  }

#define MATH_STUB_TWO(NAME, TYPE, RET)                          \
  RET NAME(TYPE a, TYPE b) {                                    \
    ORIG_IF_CAN(fedisableexcept, FE_ALL_EXCEPT);                \
    void *xmm1, *xmm2;                                          \
    RECOVER(a, xmm1);                                           \
    RECOVER(b, xmm2);                                           \
    RET ori = orig_##NAME(a, b);                                \
    DEBUG(#NAME " input (%lf , %lf) result %lf \n", a, b, ori); \
    ORIG_IF_CAN(feenableexcept, FE_ALL_EXCEPT);                 \
    ORIG_IF_CAN(feclearexcept, FE_ALL_EXCEPT);                  \
    return ori;                                                 \
  }

#define MATH_STUB_MIXED(NAME, TYPE1, TYPE2, RET)               \
  RET NAME(TYPE1 a, TYPE2 b) {                                 \
    ORIG_IF_CAN(fedisableexcept, FE_ALL_EXCEPT);               \
    void *xmm1;                                                \
    RECOVER(a, xmm1);                                          \
    RET ori = orig_##NAME(a, b);                               \
    DEBUG(#NAME " input (%lf , %d) result %lf \n", a, b, ori); \
    ORIG_IF_CAN(feenableexcept, FE_ALL_EXCEPT);                \
    ORIG_IF_CAN(feclearexcept, FE_ALL_EXCEPT);                 \
    return ori;                                                \
  }

void sincos(double a, double *sin, double *cos) {
  ORIG_IF_CAN(fedisableexcept, FE_ALL_EXCEPT);
  void *xmm1;
  RECOVER(a, xmm1);
  orig_sincos(a, sin, cos);
  // DEBUG(#NAME " input (%lf , %d) result %lf \n", a, , ori);
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

// TODO
void fpvm_number_init(void *ptr) {
  (void)ptr;
}

// TODO
void fpvm_number_deinit(void *ptr) {
  (void)ptr;
}

#endif  // CONFIG_ALT_MATH_IEEE
