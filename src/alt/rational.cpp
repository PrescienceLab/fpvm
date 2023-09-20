// an implementation of MPFR as an alternative math library

#include <fpvm/config.h>

#if CONFIG_ALT_MATH_RATIONAL

#include <assert.h>
#include <fpvm/fpvm_common.h>
#include <fpvm/fpvm_fenv.h>
#include <fpvm/fpvm_math.h>
#include <fpvm/gc.h>
#include <fpvm/number_system.h>
#include <fpvm/number_system/nan_boxing.h>
#include <math.h>
#include <stdio.h>
#include <unistd.h>

#define RFLAGS_CF 0x1UL
#define RFLAGS_PF 0x4UL
#define RFLAGS_AF 0x10UL
#define RFLAGS_ZF 0x40UL
#define RFLAGS_SF 0x80UL
#define RFLAGS_OF 0x800UL

#define RESET "\e[0m"

#define MAX(a, b)           \
  ({                        \
    __typeof__(a) _a = (a); \
    __typeof__(b) _b = (b); \
    _a > _b ? _a : _b;      \
  })

#define MIN(a, b)           \
  ({                        \
    __typeof__(a) _a = (a); \
    __typeof__(b) _b = (b); \
    _a < _b ? _a : _b;      \
  })

#define RAT_DO_DEBUG

#ifdef RAT_DO_DEBUG
#define RAT_ERROR(...) fprintf(stderr, "\e[0;31m[RAT]\e[0m " __VA_ARGS__)
#define RAT_DEBUG(...) fprintf(stderr, "\e[0;32m[RAT]\e[0m " __VA_ARGS__)
#else
#define RAT_ERROR(...)
#define RAT_DEBUG(...)
#endif

void fpvm_number_init(void *ptr) {
  (void)ptr;
}

typedef struct fraction_s {
  double num;
  double den;
} rat_t;

void rat_print(rat_t a) {
  printf("%lf/%lf", a.num, a.den);
}

rat_t rat_simplify(rat_t a) {
  return a;
  long x1, x2, gcd;
  rat_t result;
  x1 = a.num;
  x2 = a.den;
  if (x1 < x2) {
    gcd = x1;
  } else {
    gcd = x2;
  }
  if (x1 == 0 || x2 == 0) {
    result.num = 0;
    result.den = 0;
  } else {
    while (gcd > 1) {
      if (x1 % gcd == 0 && x2 % gcd == 0) break;
      gcd--;
    }
    result.num = x1 / gcd;
    result.den = x2 / gcd;
  }
  return result;
}

// rat_t rat_new(long num, long den) {
// 	rat_t f = {num, den};
// 	return f;
// }

rat_t rat_new(double val) {
  rat_t f;

  double d;

  if (modf(val, &d) == 0) {
    // already a whole number
    f.num = val;
    f.den = 1.0;
    return f;
  }

  int exponent;
  double significand = frexp(val, &exponent);  // val = significand * 2^exponent
  double numerator = val;
  double denominator = 1;
  // 0.5 <= significand < 1.0
  // significand is a fraction, multiply it by two until it's a whole number
  // subtract exponent appropriately to maintain val = significand * 2^exponent
  do {
    significand *= 2;
    --exponent;
    assert(ldexp(significand, exponent) == val);
  } while (modf(significand, &d) != 0);

  assert(exponent <= 0);

  // significand is now a whole number
  f.num = significand;
  f.den = 1.0 / ldexp(1.0, exponent);

  // printf("rat_new(%16.8lf) = %lf/%lf\n", val, f.num, f.den);
  return f;

  return rat_simplify(f);
}

rat_t rat_sub(rat_t a, rat_t b) {
  rat_t result;
  result.num = a.num * b.den - b.num * a.den;
  result.den = a.den * b.den;
  return rat_simplify(result);
}

rat_t rat_add(rat_t a, rat_t b) {
  rat_t result;
  result.num = a.num * b.den + b.num * a.den;
  result.den = a.den * b.den;
  return rat_simplify(result);
}

rat_t rat_mul(rat_t a, rat_t b) {
  rat_t r;
  r.num = a.num * b.num;
  r.den = a.den * b.den;
  return rat_simplify(r);
}

rat_t rat_div(rat_t a, rat_t b) {
  rat_t r;
  r.num = a.num * b.den;
  r.den = a.den * b.num;
  return rat_simplify(r);
}

double rat_solve(rat_t f) {
  double val = 0.0;
  if (f.num != 0) {
    double val = (double)f.num / (double)f.den;
  }
  printf("%16.8lf/%18.8lf = %lf\n", f.num, f.den, val);
  uint64_t *ptr = (uint64_t *)&f;
  printf("%016lx %016lx\n", ptr[0], ptr[1]);
}

unsigned rat_signbit(rat_t f) {
  int num = (f.num < 0) ? 1 : 0;
  int den = (f.den < 0) ? 1 : 0;
  return num ^ den;
}

rat_t rat_neg(rat_t f) {
  f.num *= -1;
  return f;
}

rat_t rat_max(rat_t a, rat_t b) {
  return rat_new(MAX(rat_solve(a), rat_solve(b)));
}
rat_t rat_min(rat_t a, rat_t b) {
  return rat_new(MIN(rat_solve(a), rat_solve(b)));
}

void fpvm_number_deinit(void *ptr) {
  (void)ptr;
}

rat_t *allocate_rat(double initial_value = 0.0) {
  rat_t *val = (rat_t *)fpvm_gc_alloc(sizeof(*val));
  *val = rat_new(initial_value);
  return val;
}

// if ptr points to a valid double, return that. If it points to a boxed value,
// convert it to a double. Designed for debugging
static double decode_to_double(void *ptr) {
  double value = *(double *)ptr;
  rat_t *rat_value = (rat_t *)fpvm_gc_unbox(value);
  uint64_t sign_bit = (!!((*(uint64_t *)ptr) >> 63));
  if (rat_value != NULL) {
    value = rat_solve(*rat_value);
    // invert if the sign is different.
    if (sign_bit != rat_signbit(*rat_value)) {
      value *= -1.0;
    }
  }

  return value;
}

// if the value being boxed is negative, state that in the NaN.
static double rat_box(rat_t *ptr) {
  double value = fpvm_gc_box((void *)ptr);
  if (rat_signbit(*ptr)) {
    *(uint64_t *)&value |= (1LLU << 63);
  }
  return value;
}

// Decode an mpfr pointer from a pointer to a double, or construct a new one
static rat_t *rat_unbox(void *double_ptr) {
  double value = *(double *)double_ptr;
  uint64_t sign_bit = (!!((*(uint64_t *)double_ptr) >> 63));
  auto *rat_value = (rat_t *)fpvm_gc_unbox(value);

  if (rat_value == NULL) {
    // allocate the value
    rat_value = allocate_rat(value);
  } else if (true) {
    // If the value was boxed, but the sign of the NaN doesn't match the sign
    // of the rat_t, we need to copy the rat_t as a negated copy, as simply
    // updating the sign would change the sign on all other boxes that share
    // a reference to this rat_t
    // RAT_DEBUG("sign bits: %lx %lx\n", sign_bit, rat_signbit(*rat_value));
    if (sign_bit != rat_signbit(*rat_value)) {
      auto *new_value = allocate_rat();
      *rat_value = rat_neg(*rat_value);
      rat_value = new_value;
    }
  }

  assert(rat_value != nullptr);

  return rat_value;
}

static void fpvm_rat_debug_binary_op(const char *name, rat_t *src1, rat_t *src2) {
  // decode_to_double(src1);
  // decode_to_double(src2);

#ifdef RAT_DO_DEBUG
  RAT_DEBUG("%s \t", name);
  rat_print(*src1);
  printf("\t");
  rat_print(*src2);
  printf("\n");
#endif

  usleep(100000);

  // RAT_DEBUG("%s \t%.32RNf\t%.32RNf\n", name, src1, src2);
}

#define RAT_BINARY_OP(NAME, TYPE)                        \
  FPVM_MATH_DECL(NAME, TYPE) {                           \
    rat_t *rat_dst = allocate_rat();                     \
    rat_t *rat_src1 = rat_unbox(src1);                   \
    rat_t *rat_src2 = rat_unbox(src2);                   \
    fpvm_rat_debug_binary_op(#NAME, rat_src1, rat_src2); \
    *rat_dst = rat_##NAME(*rat_src1, *rat_src2);         \
    *(double *)dest = rat_box(rat_dst);                  \
    return 0;                                            \
  }

RAT_BINARY_OP(add, double);
RAT_BINARY_OP(sub, double);
RAT_BINARY_OP(mul, double);
RAT_BINARY_OP(div, double);
RAT_BINARY_OP(max, double);
RAT_BINARY_OP(min, double);

// fused multiply and add
FPVM_MATH_DECL(madd, double) {
  auto a = rat_unbox(src1);
  auto b = rat_unbox(src2);
  auto c = rat_unbox(src3);

  rat_t *dst = allocate_rat();
  // +a * b + c
  // dst <- a * b
  *dst = rat_mul(*a, *b);
  // dst <- dst + c
  *dst = rat_add(*dst, *c);
  *(double *)dest = rat_box(dst);
  return 0;
}

// fused negate multiply and add
FPVM_MATH_DECL(nmadd, double) {
  auto a = rat_unbox(src1);
  auto b = rat_unbox(src2);
  auto c = rat_unbox(src3);

  rat_t *dst = allocate_rat();
  // -a * b + c
  // invert a
  // dst <- -a
  *dst = rat_neg(*a);
  // do the math.
  // dst <- dst * b
  *dst = rat_mul(*dst, *b);
  // dst <- dst + c
  *dst = rat_add(*dst, *c);

  *(double *)dest = rat_box(dst);
  return 0;
}

// fused multiply and sub
FPVM_MATH_DECL(msub, double) {
  auto a = rat_unbox(src1);
  auto b = rat_unbox(src2);
  auto c = rat_unbox(src3);

  rat_t *dst = allocate_rat();
  // +a * b - c
  // dst <- a * b
  *dst = rat_mul(*a, *b);
  // dst <- dst - c
  *dst = rat_sub(*dst, *c);
  *(double *)dest = rat_box(dst);
  return 0;
}

// fused negate multiply and sub
FPVM_MATH_DECL(nmsub, double) {
  auto a = rat_unbox(src1);
  auto b = rat_unbox(src2);
  auto c = rat_unbox(src3);

  rat_t *dst = allocate_rat();
  // -a * b - c
  // invert a
  // dst <- -a
  *dst = rat_neg(*a);
  // do the math.
  // dst <- dst * b
  *dst = rat_mul(*dst, *b);
  // dst <- dst - c
  *dst = rat_sub(*dst, *c);

  *(double *)dest = rat_box(dst);
  return 0;
}

FPVM_MATH_DECL(f2i, double) {
  double value = decode_to_double(src1);
  switch (special->byte_width) {
    case 1:
      *(int8_t *)src2 = value;
      break;
    case 2:
      *(int16_t *)src2 = value;
      break;
    case 4:
      *(int32_t *)src2 = value;
      break;
    case 8:
      *(int64_t *)src2 = value;
      break;
    default:
      ERROR("Cannot handle double->signed(%d)\n", special->byte_width);
      return -1;
      break;
  }
  return 0;
}

FPVM_MATH_DECL(f2u, double) {
  double value = decode_to_double(src1);
  switch (special->byte_width) {
    case 1:
      *(uint8_t *)src2 = value;
      break;
    case 2:
      *(uint16_t *)src2 = value;
      break;
    case 4:
      *(uint32_t *)src2 = value;
      break;
    case 8:
      *(uint64_t *)src2 = value;
      break;
    default:
      ERROR("Cannot handle double->signed(%d)\n", special->byte_width);
      return -1;
      break;
  }
  return 0;
}

int f2f_double(op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) {
  double value = decode_to_double(src1);
  switch (special->byte_width) {
    case 4:
      *(float *)src2 = value;
      break;
    case 8:
      *(double *)src2 = value;
      break;
    default:
      ERROR("Cannot handle double->float(%d)\n", special->byte_width);
      return -1;
      break;
  }
  return 0;
}

FPVM_MATH_DECL(i2f, double) {
  RAT_ERROR("unhandled operation i2f\n");
  return 0;
}
FPVM_MATH_DECL(u2f, double) {
  RAT_ERROR("unhandled operation i2f\n");
  return 0;
}

int sqrt_double(op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) {
  // rat_t *dst = allocate_rat();
  *(double *)dest = sqrt(decode_to_double(src1));
  return 0;
}

int cmp_double(op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) {
  double a = decode_to_double(src1);
  double b = decode_to_double(src2);

  // fpvm_RAT_DEBUG_binary_op("cmp", a, b);

  // compare_result < 0 - src1 < src2
  // compare_result > 0 - src1 > src2
  // compare_result = 0 - src1 = src2
  int compare_result = a - b;
  uint64_t *rflags = special->rflags;
  *rflags &= ~(RFLAGS_OF | RFLAGS_AF | RFLAGS_SF | RFLAGS_ZF | RFLAGS_PF | RFLAGS_CF);

  if (isnan(a) || isnan(b)) {
    *rflags |= (RFLAGS_ZF | RFLAGS_PF | RFLAGS_CF);
  } else {
    if (compare_result < 0) {
      *rflags |= (RFLAGS_CF);
    } else if (compare_result == 0) {
      *rflags |= (RFLAGS_ZF);
    } else if (compare_result > 0) {  // a>b
                                      // set nothing
    }
  }
  return 0;
}

int restore_double(
    op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) {
  RAT_DEBUG("restore_double %016lx  %016lx\n", *(uint64_t *)src1, *(uint64_t *)src2);
  void *allsrc[4] = {src1, src2, src3, src4};
  for (int i = 0; i < 4; i++) {
    if (allsrc[i] != NULL) {
      *(double *)allsrc[i] = decode_to_double((void *)allsrc[i]);
    }
  }
  return 0;
}

int restore_float(
    op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) {
  RAT_ERROR("restore_float %016lx  %016lx\n", *(uint64_t *)src1, *(uint64_t *)src2);
  // skip float
  return 0;
}

int restore_xmm(void *xmm_ptr) {
  // RAT_DEBUG("restore_xmm %p\n", xmm_ptr);
  double *regs = (double *)xmm_ptr;
  for (int i = 0; i < 2; i++) {
    regs[i] = decode_to_double((void *)&regs[i]);
  }
  return 0;
}

// ignored float implementations
FPVM_MATH_DECL(add, float) {
  fprintf(stderr, "mpfr should not be invoked with floats");
  return 0;
}
FPVM_MATH_DECL(sub, float) {
  fprintf(stderr, "mpfr should not be invoked with floats");
  return 0;
}
FPVM_MATH_DECL(nmsub, float) {
  fprintf(stderr, "mpfr should not be invoked with floats");
  return 0;
}
FPVM_MATH_DECL(msub, float) {
  fprintf(stderr, "mpfr should not be invoked with floats");
  return 0;
}
FPVM_MATH_DECL(mul, float) {
  fprintf(stderr, "mpfr should not be invoked with floats");
  return 0;
}
FPVM_MATH_DECL(div, float) {
  fprintf(stderr, "mpfr should not be invoked with floats");
  return 0;
}
FPVM_MATH_DECL(max, float) {
  fprintf(stderr, "mpfr should not be invoked with floats");
  return 0;
}
FPVM_MATH_DECL(min, float) {
  fprintf(stderr, "mpfr should not be invoked with floats");
  return 0;
}
FPVM_MATH_DECL(sqrt, float) {
  fprintf(stderr, "mpfr should not be invoked with floats");
  return 0;
}
FPVM_MATH_DECL(madd, float) {
  fprintf(stderr, "mpfr should not be invoked with floats");
  return 0;
}
FPVM_MATH_DECL(nmadd, float) {
  fprintf(stderr, "mpfr should not be invoked with floats");
  return 0;
}
FPVM_MATH_DECL(f2i, float) {
  fprintf(stderr, "mpfr should not be invoked with floats");
  return 0;
}
FPVM_MATH_DECL(f2u, float) {
  fprintf(stderr, "mpfr should not be invoked with floats");
  return 0;
}
FPVM_MATH_DECL(i2f, float) {
  fprintf(stderr, "mpfr should not be invoked with floats");
  return 0;
}
FPVM_MATH_DECL(u2f, float) {
  fprintf(stderr, "mpfr should not be invoked with floats");
  return 0;
}
FPVM_MATH_DECL(f2f, float) {
  fprintf(stderr, "mpfr should not be invoked with floats");
  return 0;
}
FPVM_MATH_DECL(cmp, float) {
  fprintf(stderr, "mpfr should not be invoked with floats");
  return 0;
}

#endif
