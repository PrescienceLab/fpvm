#include <fpvm/config.h>

#if CONFIG_ALT_MATH_POSIT

#define RFLAGS_CF 0x1UL
#define RFLAGS_PF 0x4UL
#define RFLAGS_AF 0x10UL
#define RFLAGS_ZF 0x40UL
#define RFLAGS_SF 0x80UL
#define RFLAGS_OF 0x800UL

#define POSIT_NO_GENERICS
#include <math.h>
#include <stdlib.h>
#include <string.h>

#include <fpvm/fpvm_common.h>
#include <fpvm/fpvm_fenv.h>
#include <fpvm/fpvm_math.h>
#include <fpvm/gc.h>
#include <fpvm/number_system.h>
#include <fpvm/number_system/nan_boxing.h>
#include <universal/number/posit/posit.h>

#ifdef DEBUG
#undef DEBUG
#define DEBUG(...)
#endif

// typedef struct  {
//   int      byte_width;
//   int      truncate;
//   int      unordered;
//   uint64_t    *rflags;
// } op_special_t;

#define MALLOC_ALIGN_16 malloc
// #define MALLOC_ALIGN_16 fpvm_gc_alloc

// posit128_add_exactp128
// 0000000000029600 T posit128_addp128
// 000000000000dcf0 T posit128_cmpp128
// 000000000002b000 T posit128_divp128
// 0000000000025140 T posit128_exp
// 0000000000024890 T posit128_fromd
// 0000000000026050 T posit128_fromf
// 0000000000023e00 T posit128_fromld
// 0000000000025520 T posit128_fromp128
// 0000000000025860 T posit128_fromp16
// 0000000000012880 T posit128_fromp128
// 00000000000259c0 T posit128_fromp32
// 0000000000025d50 T posit128_fromp4
// 0000000000023fa0 T posit128_fromsi
// 00000000000261f0 T posit128_fromsl
// 0000000000023c60 T posit128_fromsll
// 00000000000266e0 T posit128_fromui
// 0000000000026390 T posit128_fromul
// 0000000000026530 T posit128_fromull
// 0000000000024da0 T posit128_log
// 000000000002ab40 T posit128_mulp128
// 00000000000249d0 T posit128_sqrt
// 000000000000de30 T posit128_str

#define PCMP posit128_cmpp128
#define PFD posit128_fromd
#define PTD posit128_tod
#define POP(operator, sr1, src2) posit128_##operator##p128(src1, src2)
#define PTYPE posit128_t
#define PNEGATE(src) posit128_subp128(PFD(0.0), src)
#define PFUNC(FUNC, src) posit128_##FUNC##p128(src)
#define PBFUNC(FUNC, src1, src2) posit128_##FUNC##p128(src1, src2)

static inline PTYPE posit_max(PTYPE a, PTYPE b);
static inline PTYPE posit_min(PTYPE a, PTYPE b);

#define NANBOX(ITYPE, dest, nan_encoded) *(ITYPE *)dest = nan_encoded
// #define NANBOX(ITYPE, dest, nan_encoded)
#define EXIT(id) exit(id)

#define POSIT_ENCODE(ITYPE, TYPE, dest, result)                                \
  {                                                                            \
    volatile PTYPE *per_result = (PTYPE *)MALLOC_ALIGN_16(sizeof(PTYPE));      \
    memset(per_result, 0, sizeof(PTYPE));                                      \
    *per_result = result;                                                      \
    TYPE result_d = PTD(*per_result);                                          \
    volatile ITYPE nan_encoded =                                               \
        NANBOX_ENCODE((uint64_t)per_result, *(uint64_t *)&result_d);           \
    *(TYPE *)dest = result_d;                                                  \
    NANBOX(uint64_t, dest, nan_encoded);                                       \
    DEBUG("Nanbox result addr %p value %lf  \n", per_result, result_d);        \
  }

#define POSIT_REVERT_SIGN(ITYPE, TYPE, ptr_val, dest, val_d)                   \
  {                                                                            \
    DEBUG("CHECK IS THIS WIRED ? %016lx \n", *(uint64_t *)dest);               \
    volatile PTYPE *_per_result = (PTYPE *)MALLOC_ALIGN_16(sizeof(PTYPE));     \
    memset(_per_result, 0, sizeof(PTYPE));                                     \
    *_per_result = PNEGATE(*(PTYPE *)ptr_val);                                 \
    volatile ITYPE _nan_encoded =                                              \
        NANBOX_ENCODE((uint64_t)_per_result, *(uint64_t *)&val_d);             \
    DEBUG("Nanbox result addr %p value %lf  \n", _per_result,                  \
          PTD(*_per_result));                                                  \
    NANBOX(ITYPE, dest, _nan_encoded);                                         \
    *ptr_val = *_per_result;                                                   \
  }

#define POSIT_BIN_OP(TYPE, ITYPE, NAME, OP, SPEC, ISPEC)                       \
  int NAME##_##TYPE(op_special_t *special, void *dest, void *src1, void *src2, \
                    void *src3, void *src4) {                                  \
    void *src_or1 = src1, *src_or2 = src2;                                     \
    PTYPE op1, op2;                                                            \
    DEBUG(ISNAN(*(uint64_t *)src1) ? "True " : "False ");                      \
    DEBUG(ISNAN(*(uint64_t *)src2) ? "True \n" : "False \n");                  \
    DEBUG("src1 %p , %016lx,  src2 %p, %016lx \n", src1, *(uint64_t *)src1,    \
          src2, *(uint64_t *)src2);                                            \
    if (ISNAN(*(uint64_t *)src1)) {                                            \
      src1 = (void *)NANBOX_DECODE(*(uint64_t *)src1);                         \
      op1 = *(PTYPE *)src1;                                                    \
    } else {                                                                   \
      op1 = PFD(*(TYPE *)src1);                                                \
    }                                                                          \
    if (ISNAN(*(uint64_t *)src2)) {                                            \
      src2 = (void *)NANBOX_DECODE(*(uint64_t *)src2);                         \
      op2 = *(PTYPE *)src2;                                                    \
    } else {                                                                   \
      op2 = PFD(*(TYPE *)src2);                                                \
    }                                                                          \
                                                                               \
    double a = PTD(op1), b = PTD(op2);                                         \
    DEBUG("In double %lf, %lf \n", a, b);                                      \
    if (CORRUPTED(*(uint64_t *)src_or1, *(uint64_t *)&a))                      \
      POSIT_REVERT_SIGN(ITYPE, TYPE, &op1, src_or1, a);                        \
    if (CORRUPTED(*(uint64_t *)src_or2, *(uint64_t *)&b))                      \
      POSIT_REVERT_SIGN(ITYPE, TYPE, &op2, src_or2, b);                        \
    if (isnan(a)) {                                                            \
      ERROR("not my nan, try fix %p ori ptr %p, val %016lx\n", src1, src_or1,  \
            *(uint64_t *)src_or1);                                             \
      EXIT(1);                                                                 \
    }                                                                          \
    if (isnan(b)) {                                                            \
      ERROR("not my nan, try fix %p ori ptr %p, val %016lx\n", src2, src_or2,  \
            *(uint64_t *)src_or2);                                             \
      EXIT(1);                                                                 \
    }                                                                          \
    DEBUG("decoded src1 %p , %016lx,  src2 %p, %016lx \n", src1,               \
          *(uint64_t *)src1, src2, *(uint64_t *)src2);                         \
    PTYPE result = posit128_##NAME##p128(op1, op2);                            \
    a = PTD(op1), b = PTD(op2);                                                \
    DEBUG(#NAME "_" #TYPE ": " SPEC " " #OP " " SPEC " = " SPEC " [" ISPEC     \
                "] (%p)\n",                                                    \
          a, b, PTD(result), *(ITYPE *)&result, dest);                         \
    POSIT_ENCODE(ITYPE, TYPE, dest, result);                                   \
                                                                               \
    return 0;                                                                  \
  }

#define POSIT_UN_FUNC(TYPE, ITYPE, NAME, FUNC, SPEC, ISPEC)                    \
  int NAME##_##TYPE(op_special_t *special, void *dest, void *src1, void *src2, \
                    void *src3, void *src4) {                                  \
    void *src_or1 = src1;                                                      \
    PTYPE op1;                                                                 \
    DEBUG(ISNAN(*(uint64_t *)src1) ? "True \n" : "False \n");                  \
    DEBUG("src1 %p , %016lx\n", src1, *(uint64_t *)src1);                      \
    if (ISNAN(*(uint64_t *)src1)) {                                            \
      src1 = (void *)NANBOX_DECODE(*(uint64_t *)src1);                         \
      op1 = *(PTYPE *)src1;                                                    \
    } else {                                                                   \
      op1 = PFD(*(TYPE *)src1);                                                \
    }                                                                          \
    double a = PTD(op1);                                                       \
    DEBUG("In double %lf\n", a);                                               \
    if (CORRUPTED(*(uint64_t *)src_or1, *(uint64_t *)&a))                      \
      POSIT_REVERT_SIGN(ITYPE, TYPE, &op1, src_or1, a);                        \
    PTYPE result = posit128_##FUNC(op1);                                       \
                                                                               \
    POSIT_ENCODE(ITYPE, TYPE, dest, result);                                   \
    DEBUG(#NAME "_" #TYPE ": " #FUNC "(" SPEC ") = " SPEC " [" ISPEC           \
                "] (%p)\n",                                                    \
          a, PTD(result), *(ITYPE *)&result, dest);                            \
    return 0;                                                                  \
  }

#define POSIT_BIN_FUNC(TYPE, ITYPE, NAME, FUNC, SPEC, ISPEC)                   \
  int NAME##_##TYPE(op_special_t *special, void *dest, void *src1, void *src2, \
                    void *src3, void *src4) {                                  \
    void *src_or1 = src1, *src_or2 = src2;                                     \
    PTYPE op1, op2;                                                            \
    DEBUG(ISNAN(*(uint64_t *)src1) ? "True " : "False ");                      \
    DEBUG(ISNAN(*(uint64_t *)src2) ? "True \n" : "False \n");                  \
    DEBUG("src1 %p , %016lx,  src2 %p, %016lx \n", src1, *(uint64_t *)src1,    \
          src2, *(uint64_t *)src2);                                            \
    if (ISNAN(*(uint64_t *)src1)) {                                            \
      src1 = (void *)NANBOX_DECODE(*(uint64_t *)src1);                         \
      op1 = *(PTYPE *)src1;                                                    \
    } else {                                                                   \
      op1 = PFD(*(TYPE *)src1);                                                \
    }                                                                          \
    if (ISNAN(*(uint64_t *)src2)) {                                            \
      src2 = (void *)NANBOX_DECODE(*(uint64_t *)src2);                         \
      op2 = *(PTYPE *)src2;                                                    \
    } else {                                                                   \
      op2 = PFD(*(TYPE *)src2);                                                \
    }                                                                          \
                                                                               \
    double a = PTD(op1), b = PTD(op2);                                         \
    DEBUG("In double %lf, %lf \n", a, b);                                      \
    if (CORRUPTED(*(uint64_t *)src_or1, *(uint64_t *)&a))                      \
      POSIT_REVERT_SIGN(ITYPE, TYPE, &op1, src_or1, a);                        \
    if (CORRUPTED(*(uint64_t *)src_or2, *(uint64_t *)&b))                      \
      POSIT_REVERT_SIGN(ITYPE, TYPE, &op2, src_or2, b);                        \
    if (isnan(a)) {                                                            \
      ERROR("not my nan, try fix %p ori ptr %p, val %016lx\n", src1, src_or1,  \
            *(uint64_t *)src_or1);                                             \
      EXIT(1);                                                                 \
    }                                                                          \
    if (isnan(b)) {                                                            \
      ERROR("not my nan, try fix %p ori ptr %p, val %016lx\n", src2, src_or2,  \
            *(uint64_t *)src_or2);                                             \
      EXIT(1);                                                                 \
    }                                                                          \
    DEBUG("decoded src1 %p , %016lx,  src2 %p, %016lx \n", src1,               \
          *(uint64_t *)src1, src2, *(uint64_t *)src2);                         \
    PTYPE result = FUNC(op1, op2);                                             \
    a = PTD(op1), b = PTD(op2);                                                \
    DEBUG(#NAME "_" #TYPE ": " #FUNC "(" SPEC ", " SPEC ") = " SPEC " [" ISPEC \
                "] (%p)\n",                                                    \
          a, b, PTD(result), *(ITYPE *)&result, dest);                         \
    POSIT_ENCODE(ITYPE, TYPE, dest, result);                                   \
                                                                               \
    return 0;                                                                  \
  }

#define POSIT_FUSED_OP(TYPE, ITYPE, NAME, OP1, NEGOP, OP2, SPEC, ISPEC)        \
  int NAME##_##TYPE(op_special_t *special, void *dest, void *src1, void *src2, \
                    void *src3, void *src4) {                                  \
    void *src_or1 = src1, *src_or2 = src2, *src_or3 = src3;                    \
    PTYPE op1, op2, op3;                                                       \
    DEBUG(ISNAN(*(uint64_t *)src1) ? "True " : "False ");                      \
    DEBUG(ISNAN(*(uint64_t *)src2) ? "True " : "False ");                      \
    DEBUG(ISNAN(*(uint64_t *)src3) ? "True \n" : "False \n");                  \
    DEBUG("src1 %p , %016lx,  src2 %p, %016lx \n, src3 %p, %016lx \n, ", src1, \
          *(uint64_t *)src1, src2, *(uint64_t *)src2, src3,                    \
          *(uint64_t *)src3);                                                  \
    if (ISNAN(*(uint64_t *)src1)) {                                            \
      src1 = (void *)NANBOX_DECODE(*(uint64_t *)src1);                         \
      op1 = *(PTYPE *)src1;                                                    \
    } else {                                                                   \
      op1 = PFD(*(TYPE *)src1);                                                \
    }                                                                          \
    if (ISNAN(*(uint64_t *)src2)) {                                            \
      src2 = (void *)NANBOX_DECODE(*(uint64_t *)src2);                         \
      op2 = *(PTYPE *)src2;                                                    \
    } else {                                                                   \
      op2 = PFD(*(TYPE *)src2);                                                \
    }                                                                          \
    if (ISNAN(*(uint64_t *)src3)) {                                            \
      src3 = (void *)NANBOX_DECODE(*(uint64_t *)src3);                         \
      op3 = *(PTYPE *)src3;                                                    \
    } else {                                                                   \
      op3 = PFD(*(TYPE *)src3);                                                \
    }                                                                          \
                                                                               \
    double a = PTD(op1), b = PTD(op2), c = PTD(op3);                           \
    DEBUG("In double %lf, %lf, %lf \n", a, b, c);                              \
    if (CORRUPTED(*(uint64_t *)src_or1, *(uint64_t *)&a))                      \
      POSIT_REVERT_SIGN(ITYPE, TYPE, &op1, src_or1, a);                        \
    if (CORRUPTED(*(uint64_t *)src_or2, *(uint64_t *)&b))                      \
      POSIT_REVERT_SIGN(ITYPE, TYPE, &op2, src_or2, b);                        \
    if (CORRUPTED(*(uint64_t *)src_or3, *(uint64_t *)&c))                      \
      POSIT_REVERT_SIGN(ITYPE, TYPE, &op3, src_or3, c);                        \
    if (isnan(a)) {                                                            \
      ERROR("not my nan, try fix %p ori ptr %p, val %016lx\n", src1, src_or1,  \
            *(uint64_t *)src_or1);                                             \
      EXIT(1);                                                                 \
    }                                                                          \
    if (isnan(b)) {                                                            \
      ERROR("not my nan, try fix %p ori ptr %p, val %016lx\n", src2, src_or2,  \
            *(uint64_t *)src_or2);                                             \
      EXIT(1);                                                                 \
    }                                                                          \
    if (isnan(c)) {                                                            \
      ERROR("not my nan, try fix %p ori ptr %p, val %016lx\n", src3, src_or3,  \
            *(uint64_t *)src_or3);                                             \
      EXIT(1);                                                                 \
    }                                                                          \
    PTYPE result = posit128_##OP2##p128(                                       \
        posit128_##NEGOP##p128(PFD(0.0), posit128_##OP1##p128(op1, op2)),      \
        op3);                                                                  \
    a = PTD(op1), b = PTD(op2), c = PTD(op3);                                  \
    DEBUG(#NAME "_" #TYPE ": (" #NEGOP "( " SPEC " " #OP1 " " SPEC             \
                " ) ) " #OP2 " " SPEC " = " SPEC " [" ISPEC "] (%p)\n",        \
          a, b, c, PTD(result), *(ITYPE *)&result, dest);                      \
    POSIT_ENCODE(ITYPE, TYPE, dest, result);                                   \
                                                                               \
    return 0;                                                                  \
  }

// #define posit_cmp_float posit_cmp_double

static inline PTYPE posit_max(PTYPE a, PTYPE b) {
  DEBUG("posit max \n");

  if (PTD(a) > PTD(b)) {
    return a;
  } else {
    return b;
  }
}
static inline PTYPE posit_min(PTYPE a, PTYPE b) {
  DEBUG("posit min \n");
  if (PTD(a) < PTD(b)) {
    return a;
  } else {
    return b;
  }
}

int cmp_double(op_special_t *special, void *dest, void *src1, void *src2,
               void *src3, void *src4) {
#define ITYPE uint64_t
#define TYPE double
  DEBUG("CMP !!!!! WTF deal with it \n");
  void *src_or1 = src1, *src_or2 = src2;
  PTYPE op1, op2;
  DEBUG(ISNAN(*(uint64_t *)src1) ? "True " : "False ");
  DEBUG(ISNAN(*(uint64_t *)src2) ? "True \n" : "False \n");
  DEBUG("src1 %p , %016lx,  src2 %p, %016lx \n", src1, *(uint64_t *)src1, src2,
        *(uint64_t *)src2);
  if (ISNAN(*(uint64_t *)src1)) {
    src1 = (void *)NANBOX_DECODE(*(uint64_t *)src1);
    op1 = *(PTYPE *)src1;
  } else {
    op1 = PFD(*(TYPE *)src1);
  }
  if (ISNAN(*(uint64_t *)src2)) {
    src2 = (void *)NANBOX_DECODE(*(uint64_t *)src2);
    op2 = *(PTYPE *)src2;
  } else {
    op2 = PFD(*(TYPE *)src2);
  }

  double a = PTD(op1), b = PTD(op2);
  DEBUG("In double %lf, %lf \n", a, b);
  if (CORRUPTED(*(uint64_t *)src_or1, *(uint64_t *)&a))
    POSIT_REVERT_SIGN(ITYPE, TYPE, &op1, src_or1, a);
  if (CORRUPTED(*(uint64_t *)src_or2, *(uint64_t *)&b))
    POSIT_REVERT_SIGN(ITYPE, TYPE, &op2, src_or2, b);
  if (isnan(a)) {
    ERROR("not my nan, try fix %p ori ptr %p, val %016lx\n", src1, src_or1,
          *(uint64_t *)src_or1);
    EXIT(1);
  }
  if (isnan(b)) {
    ERROR("not my nan, try fix %p ori ptr %p, val %016lx\n", src2, src_or2,
          *(uint64_t *)src_or2);
    EXIT(1);
  }
  DEBUG("decoded src1 %p , %016lx,  src2 %p, %016lx \n", src1,
        *(uint64_t *)src1, src2, *(uint64_t *)src2);

  a = PTD(op1);
  b = PTD(op2);

  uint64_t *rflags = special->rflags;
  // int which;

  *rflags &=
      ~(RFLAGS_OF | RFLAGS_AF | RFLAGS_SF | RFLAGS_ZF | RFLAGS_PF | RFLAGS_CF);

  // it may happen when you transform from posit, you get a nan
  if (isnan(a) || isnan(b)) {
    *rflags |= (RFLAGS_ZF | RFLAGS_PF | RFLAGS_CF);
    // which = -2;
  } else {
    if (a < b) {
      *rflags |= (RFLAGS_CF);
      // which = -1;
    } else if (a == b) {
      *rflags |= (RFLAGS_ZF);
      // which = 0;
    } else { // a>b
      // set nothing
      // which =1;
    }
  }

  DEBUG("double %s compare %lf %lf => flags %lx (%s)\n",
        special->unordered ? "unordered" : "ordered", a, b, *rflags,
        which == -2   ? "unordered"
        : which == -1 ? "less"
        : which == 0  ? "equal"
                      : "greater");
#undef ITYPE
#undef TYPE
  return 0;
}

#define CONVERT_F2I(FTYPE, ITYPE, FSPEC, ISPEC)                                \
  {                                                                            \
    ITYPE result = (ITYPE)(*(FTYPE *)src1);                                    \
    DEBUG("f2i[" #FTYPE " to " #ITYPE "](" FSPEC ") = " ISPEC " (%p)\n",       \
          (*(FTYPE *)src1), result, dest);                                     \
    *(ITYPE *)dest = result;                                                   \
    return 0;                                                                  \
  }

#define DOUBLE_CONVERT_F2I(FTYPE, ITYPE, FSPEC, ISPEC)                         \
  {                                                                            \
    void *src_or1 = src1;                                                      \
    PTYPE op1;                                                                 \
    DEBUG("src1 %p , %016lx\n", src1, *(uint64_t *)src1);                      \
    if (ISNAN(*(uint64_t *)src1)) {                                            \
      src1 = (void *)NANBOX_DECODE(*(uint64_t *)src1);                         \
      op1 = *(PTYPE *)src1;                                                    \
    } else {                                                                   \
      op1 = PFD(*(FTYPE *)src1);                                               \
    }                                                                          \
    double a = PTD(op1);                                                       \
    DEBUG("In double %lf\n", a);                                               \
    if (CORRUPTED(*(uint64_t *)src_or1, *(uint64_t *)&a))                      \
      POSIT_REVERT_SIGN(uint64_t, double, &op1, src_or1, a);                   \
    a = PTD(op1);                                                              \
    ITYPE result = (ITYPE)(*(FTYPE *)&a);                                      \
    DEBUG("f2i[" #FTYPE " to " #ITYPE "](" FSPEC ") = " ISPEC " (%p)\n",       \
          (*(FTYPE *)&a), result, dest);                                       \
    *(ITYPE *)dest = result;                                                   \
    return 0;                                                                  \
  }

#define CONVERT_F2F(FITYPE, FOTYPE, FISPEC, FOSPEC)                            \
  {                                                                            \
    FOTYPE result = (FOTYPE)(*(FITYPE *)src1);                                 \
    DEBUG("f2f[" #FITYPE " to " #FOTYPE "](" FISPEC ") = " FOSPEC " (%p)\n",   \
          (*(FITYPE *)src1), result, dest);                                    \
    *(FOTYPE *)dest = result;                                                  \
    return 0;                                                                  \
  }

#define DOUBLE_CONVERT_F2F(FITYPE, FOTYPE, FISPEC, FOSPEC)                     \
  {                                                                            \
    void *src_or1 = src1;                                                      \
    PTYPE op1;                                                                 \
    DEBUG("src1 %p , %016lx\n", src1, *(uint64_t *)src1);                      \
    if (ISNAN(*(uint64_t *)src1)) {                                            \
      src1 = (void *)NANBOX_DECODE(*(uint64_t *)src1);                         \
      op1 = *(PTYPE *)src1;                                                    \
    } else {                                                                   \
      op1 = PFD(*(FITYPE *)src1);                                              \
    }                                                                          \
    double a = PTD(op1);                                                       \
    DEBUG("In double %lf\n", a);                                               \
    if (CORRUPTED(*(uint64_t *)src_or1, *(uint64_t *)&a))                      \
      POSIT_REVERT_SIGN(uint64_t, double, &op1, src_or1, a);                   \
    a = PTD(op1);                                                              \
    FOTYPE result = (FOTYPE)(*(FITYPE *)&a);                                   \
    DEBUG("f2f[" #FITYPE " to " #FOTYPE "](" FISPEC ") = " FOSPEC " (%p)\n",   \
          (*(FITYPE *)&a), result, dest);                                      \
    *(FOTYPE *)dest = result;                                                  \
    return 0;                                                                  \
  }

int f2i_double(op_special_t *special, void *dest, void *src1, void *src2,
               void *src3, void *src4) {
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
int f2u_double(op_special_t *special, void *dest, void *src1, void *src2,
               void *src3, void *src4) {
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

// THIS DOES NOT HANDLE THE SPECIAL CASES OR RAISE EXCEPTIONS
int f2i_float(op_special_t *special, void *dest, void *src1, void *src2,
              void *src3, void *src4) {
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

// THIS DOES NOT HANDLE THE SPECIAL CASES OR RAISE EXCEPTIONS
int f2u_float(op_special_t *special, void *dest, void *src1, void *src2,
              void *src3, void *src4) {
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

int f2f_double(op_special_t *special, void *dest, void *src1, void *src2,
               void *src3, void *src4) {
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

int f2f_float(op_special_t *special, void *dest, void *src1, void *src2,
              void *src3, void *src4) {
  switch (special->byte_width) {
  case 8:
    CONVERT_F2F(float, double, "%f", "%lf");
  default:
    ERROR("Cannot handle float->float(%d)\n", special->byte_width);
    return -1;
    break;
  }
}

POSIT_BIN_FUNC(double, uint64_t, max, posit_max, "%lf", "%016lx");
POSIT_BIN_FUNC(double, uint64_t, min, posit_min, "%lf", "%016lx");
POSIT_BIN_OP(double, uint64_t, add, +, "%lf", "%016lx");
POSIT_BIN_OP(double, uint64_t, sub, -, "%lf", "%016lx");
POSIT_BIN_OP(double, uint64_t, div, /, "%lf", "%016lx");
POSIT_BIN_OP(double, uint64_t, mul, *, "%lf", "%016lx");
POSIT_UN_FUNC(double, uint64_t, sqrt, sqrt, "%f", "%016lx");
POSIT_FUSED_OP(double, uint64_t, madd, mul, add, add, "%lf", "%016lx");
POSIT_FUSED_OP(double, uint64_t, nmadd, mul, sub, add, "%lf", "%016lx");
POSIT_FUSED_OP(double, uint64_t, msub, mul, add, sub, "%lf", "%016lx");
POSIT_FUSED_OP(double, uint64_t, nmsub, mul, sub, sub, "%lf", "%016lx");

// #define posit_max_float posit_max_double
// #define posit_min_float posit_min_double
// #define posit_add_float posit_add_double
// #define posit_sub_float posit_sub_double
// #define posit_mul_float posit_mul_double
// #define posit_div_float posit_div_double
// #define posit_sqrt_float posit_sqrt_double
// #define posit_madd_float posit_madd_double
// #define posit_nmadd_float posit_nmadd_double
// #define posit_ltcmp_float posit_ltcmp_double
// #define posit_cmp_float posit_cmp_double

// #define posit_shift_left_byte_float posit_shift_left_byte_double
// #define posit_shift_right_byte_float posit_shift_right_byte_double

FPVM_MATH_DECL(add, float) {
  fprintf(stderr, "posit should not be invoked with floats");
  return 0;
}
FPVM_MATH_DECL(sub, float) {
  fprintf(stderr, "posit should not be invoked with floats");
  return 0;
}
FPVM_MATH_DECL(nmsub, float) {
  fprintf(stderr, "posit should not be invoked with floats");
  return 0;
}
FPVM_MATH_DECL(msub, float) {
  fprintf(stderr, "posit should not be invoked with floats");
  return 0;
}
FPVM_MATH_DECL(mul, float) {
  fprintf(stderr, "posit should not be invoked with floats");
  return 0;
}
FPVM_MATH_DECL(div, float) {
  fprintf(stderr, "posit should not be invoked with floats");
  return 0;
}
FPVM_MATH_DECL(max, float) {
  fprintf(stderr, "posit should not be invoked with floats");
  return 0;
}
FPVM_MATH_DECL(min, float) {
  fprintf(stderr, "posit should not be invoked with floats");
  return 0;
}
FPVM_MATH_DECL(sqrt, float) {
  fprintf(stderr, "posit should not be invoked with floats");
  return 0;
}
FPVM_MATH_DECL(madd, float) {
  fprintf(stderr, "posit should not be invoked with floats");
  return 0;
}
FPVM_MATH_DECL(nmadd, float) {
  fprintf(stderr, "posit should not be invoked with floats");
  return 0;
}
// FPVM_MATH_DECL(f2i, float) { fprintf(stderr, "posit should not be invoked
// with floats"); return 0;} FPVM_MATH_DECL(f2u, float) { fprintf(stderr, "posit
// should not be invoked with floats"); return 0;}
FPVM_MATH_DECL(i2f, float) {
  fprintf(stderr, "posit should not be invoked with floats");
  return 0;
}
FPVM_MATH_DECL(u2f, float) {
  fprintf(stderr, "posit should not be invoked with floats");
  return 0;
}
// FPVM_MATH_DECL(f2f, float) { fprintf(stderr, "posit should not be invoked
// with floats"); return 0;}
FPVM_MATH_DECL(cmp, float) {
  fprintf(stderr, "posit should not be invoked with floats");
  return 0;
}

// POSIT_BIN_OP(float,  uint32_t,add,+,"%f","%08x");
// POSIT_BIN_OP(float,  uint32_t,sub,-,"%f","%08x");
// POSIT_BIN_OP(float,  uint32_t,mul,*,"%f","%08x");
// POSIT_BIN_OP(float,  uint32_t,div,/,"%f","%08x");
// POSIT_BIN_OP(float, f, 128, uint32_t, cmp, cmp,"%f","%08x");
// POSIT_BIN_OP(double, d,128,  uint64_t, cmp, cmp,"%lf","%016lx");
// POSIT_UN_FUNC(float, f, 128, uint32_t, sqrt, sqrt,"%f","%08x");
// POSIT_UN_FUNC(double, d, 128, uint64_t, sqrt, sqrt,"%f","%016lx");

#define ORIG_IF_CAN(func, ...)                                                 \
  if (orig_##func) {                                                           \
    if (!DEBUG_OUTPUT) {                                                       \
      orig_##func(__VA_ARGS__);                                                \
    } else {                                                                   \
      DEBUG("orig_" #func " returns 0x%x\n", orig_##func(__VA_ARGS__));        \
    }                                                                          \
  } else {                                                                     \
    DEBUG("cannot call orig_" #func " - skipping\n");                          \
  }

#define RECOVER(a, xmm)                                                        \
  {                                                                            \
    if (ISNAN(*(uint64_t *)&a)) {                                              \
      PTYPE op1;                                                               \
      xmm = (void *)NANBOX_DECODE(*(uint64_t *)&a);                            \
      op1 = *(PTYPE *)xmm;                                                     \
      double tmp = PTD(op1);                                                   \
      op1 = (CORRUPTED(*(uint64_t *)&a, *(uint64_t *)&tmp) ? PNEGATE(op1)      \
                                                           : op1);             \
      a = PTD(op1);                                                            \
    }                                                                          \
  }

#define MATH_STUB_ONE(NAME, TYPE, RET)                                         \
  RET NAME(TYPE a) {                                                           \
    ORIG_IF_CAN(fedisableexcept, FE_ALL_EXCEPT);                               \
    void *xmm1;                                                                \
    RECOVER(a, xmm1);                                                          \
    RET ori = orig_##NAME(a);                                                  \
    DEBUG(#NAME " input (%lf ) result \n", a);                                 \
    ORIG_IF_CAN(feenableexcept, FE_ALL_EXCEPT);                                \
    ORIG_IF_CAN(feclearexcept, FE_ALL_EXCEPT);                                 \
    return ori;                                                                \
  }

#define MATH_STUB_TWO(NAME, TYPE, RET)                                         \
  RET NAME(TYPE a, TYPE b) {                                                   \
    ORIG_IF_CAN(fedisableexcept, FE_ALL_EXCEPT);                               \
    void *xmm1, *xmm2;                                                         \
    RECOVER(a, xmm1);                                                          \
    RECOVER(b, xmm2);                                                          \
    RET ori = orig_##NAME(a, b);                                               \
    DEBUG(#NAME " input (%lf , %lf) result %lf \n", a, b, ori);                \
    ORIG_IF_CAN(feenableexcept, FE_ALL_EXCEPT);                                \
    ORIG_IF_CAN(feclearexcept, FE_ALL_EXCEPT);                                 \
    return ori;                                                                \
  }

#define MATH_STUB_MIXED(NAME, TYPE1, TYPE2, RET)                               \
  RET NAME(TYPE1 a, TYPE2 b) {                                                 \
    ORIG_IF_CAN(fedisableexcept, FE_ALL_EXCEPT);                               \
    void *xmm1;                                                                \
    RECOVER(a, xmm1);                                                          \
    RET ori = orig_##NAME(a, b);                                               \
    DEBUG(#NAME " input (%lf , %d) result %lf \n", a, b, ori);                 \
    ORIG_IF_CAN(feenableexcept, FE_ALL_EXCEPT);                                \
    ORIG_IF_CAN(feclearexcept, FE_ALL_EXCEPT);                                 \
    return ori;                                                                \
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

int restore_double(op_special_t *special, void *dest, void *src1, void *src2,
                   void *src3, void *src4) {
// ERROR("About to restore %016lx  %016lx \n", *(uint64_t*) src1,  *(uint64_t*)
// src2);
#define n 4
  void *allsrc[n] = {src1, src2, src3, src4};
  for (int i = 0; i < n; i++) {
    uint64_t *src = (void *)allsrc[i]; // src1 is mem op
    if (src != NULL && ISNAN(*(uint64_t *)src)) {
      PTYPE op1 = *(PTYPE *)NANBOX_DECODE(*(uint64_t *)src);
      double a = PTD(op1);
      op1 = (CORRUPTED(*(uint64_t *)src, *(uint64_t *)&a) ? PNEGATE(op1) : op1);
      a = PTD(op1);
      *(uint64_t *)src = *(uint64_t *)&a;
    }
  }

  return 0;
}

int restore_float(op_special_t *special, void *dest, void *src1, void *src2,
                  void *src3, void *src4) {
  return 0;
}

int restore_xmm(void *xmm_ptr) {
  uint64_t *src = (uint64_t *)xmm_ptr; // src1 is mem op
  if (src != NULL && ISNAN(*(uint64_t *)src)) {
    PTYPE op1 = *(PTYPE *)NANBOX_DECODE(*(uint64_t *)src);
    double a = PTD(op1);
    op1 = (CORRUPTED(*(uint64_t *)src, *(uint64_t *)&a) ? PNEGATE(op1) : op1);
    a = PTD(op1);
    *(uint64_t *)src = *(uint64_t *)&a;
  }
  // iterate to next one in xmm

  src = (uint64_t *)((char *)src + 8);
  if (src != NULL && ISNAN(*(uint64_t *)src)) {
    PTYPE op1 = *(PTYPE *)NANBOX_DECODE(*(uint64_t *)src);
    double a = PTD(op1);
    op1 = (CORRUPTED(*(uint64_t *)src, *(uint64_t *)&a) ? PNEGATE(op1) : op1);
    a = PTD(op1);
    *(uint64_t *)src = *(uint64_t *)&a;
  }
  return 0;
}

// TODO
void fpvm_number_init(void *ptr) { (void)ptr; }

// TODO
void fpvm_number_deinit(void *ptr) { (void)ptr; }

#endif // CONFIG_ALT_MATH_POSIT
