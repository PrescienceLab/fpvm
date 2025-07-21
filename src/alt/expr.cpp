// an implementation of "Expression tracing" as an alternative math library

#include <fpvm/config.h>

#if CONFIG_ALT_MATH_EXPR_TRACE

#include <assert.h>
#include <fpvm/fpvm_common.h>
#include <fpvm/fpvm_fenv.h>
#include <fpvm/fpvm_math.h>
#include <fpvm/gc.h>
#include <fpvm/number_system.h>
#include <fpvm/nan_boxing.h>
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

// #define EXPR_DO_DEBUG
// RNDN: -1.416797517585610      -0.665436589132111
// RNDD: -1.416797517585610      -0.665436589132111
#define ROUNDING_MODE EXPR_RNDN

#define EXPR_ERROR(...)
#define EXPR_DEBUG(...)


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


#define EXPR_MAX_OPS 3
typedef struct expression {
  const char *op;
  // Cached Value
  double value;
  unsigned long depth;
  // Operands
  struct expression *ops[EXPR_MAX_OPS];
} expr_t;

static void print_expr(expr_t *expr, int depth) {
  if (expr == 0) {
    printf("???");
    return;
  }

  if (depth == 0) {
    printf(".");
    return;
  }

  if (expr->op == NULL) {
    printf("%lf", expr->value);
    return;
  }

  printf("(%s", expr->op);

  for (int i = 0; i < EXPR_MAX_OPS; i++) {
    if (i > 0 && expr->ops[i] == NULL) {
      continue;
    }
    printf(" ");
    print_expr(expr->ops[i], depth - 1);
  }

  printf(")");
}



long expr_depth(expr_t *e) {
  if (e == NULL) return 0;
  long sum = 1;

  for (int i = 0; i < EXPR_MAX_OPS; i++) {
    sum += expr_depth(e->ops[i]);
  }
  return sum;
}


void expr_trace(expr_t *e) {
  static FILE *out = fopen("expressions.scm", "w");
  // out = stderr;
  ORIG_IF_CAN(fedisableexcept, FE_ALL_EXCEPT);

  if (e->op == NULL) {
    fprintf(out, "%p %lf\n", e, e->value);

  } else {
    // fprintf(out, "%p (%s %llf", e, e->op, e->value);
    // // for (int i = 0; i < EXPR_MAX_OPS; i++) {
    // //   fprintf(out, " 0x%zx", (uint64_t)e->ops[i]);
    // // }
    // fprintf(out, ")\n");
  }

  ORIG_IF_CAN(feenableexcept, FE_ALL_EXCEPT);
  ORIG_IF_CAN(feclearexcept, FE_ALL_EXCEPT);

  // printf("DEPTH=%16lu %16lx ", e->depth, e->depth);


  // print_expr(e, 3);
  // printf("\n");
}


expr_t *expr_constant(double value) {
  expr_t *e = (expr_t *)fpvm_gc_alloc(sizeof(expr_t));
  e->op = NULL;  // No operation, just a constant
  e->value = value;
  e->depth = 1;
  e->ops[0] = NULL;
  e->ops[1] = NULL;
  e->ops[2] = NULL;

  expr_trace(e);
  return e;
}

expr_t *expr_create1(const char *op, double value, expr_t *a) {
  expr_t *e = (expr_t *)fpvm_gc_alloc(sizeof(expr_t));
  e->op = op;
  e->value = value;
  e->depth = 1 + a->depth;
  e->ops[0] = a;
  e->ops[1] = NULL;
  e->ops[2] = NULL;

  expr_trace(e);
  return e;
}

expr_t *expr_create2(const char *op, double value, expr_t *a, expr_t *b) {
  expr_t *e = (expr_t *)fpvm_gc_alloc(sizeof(expr_t));
  e->op = op;
  e->value = value;
  e->depth = 1 + a->depth + b->depth;
  e->ops[0] = a;
  e->ops[1] = b;
  e->ops[2] = NULL;

  expr_trace(e);
  return e;
}

expr_t *expr_create3(const char *op, double value, expr_t *a, expr_t *b, expr_t *c) {
  expr_t *e = (expr_t *)fpvm_gc_alloc(sizeof(expr_t));
  e->op = op;
  e->value = value;
  e->depth = 1 + a->depth + b->depth + c->depth;
  e->ops[0] = a;
  e->ops[1] = b;
  e->ops[2] = c;

  expr_trace(e);
  return e;
}

expr_t *expr_neg(expr_t *a) {
  return expr_create1("neg", -a->value, a);
}


int expr_signbit(expr_t *a) {
  return a->value >= 0;  // maybe??
}


void fpvm_number_init(void *ptr) {
  (void)ptr;
}

void fpvm_number_deinit(void *ptr) {
  // Intentionally not freeing for tracing reasons!
}


// if ptr points to a valid double, return that. If it points to a boxed value,
// convert it to a double. Designed for debugging
static double decode_to_double(void *ptr) {
  double value = *(double *)ptr;
  int sign_bit;
  expr_t *expr = (expr_t *)fpvm_gc_unbox(value, &sign_bit);
  if (expr != NULL) {
    value = expr->value;
    // invert if the sign is different.
    if (sign_bit != expr_signbit(expr)) {
      value *= -1;
    }
  }

  return value;
}

static uint64_t decode_to_double_bits(void *ptr) {
  double v = decode_to_double(ptr);
  return *(uint64_t *)&v;
}

// if the value being boxed is negative, state that in the NaN.
static double expr_box(expr_t *ptr) {
  expr_trace(ptr);
  int sign = expr_signbit(ptr);
  double value = fpvm_gc_box((void *)ptr, sign);
  if (expr_signbit(ptr)) *(uint64_t *)&value |= (1LLU << 63);
  return value;
}

static expr_t *expr_unbox(void *double_ptr) {
  double value = *(double *)double_ptr;
  int sign;
  expr_t *expr = (expr_t *)fpvm_gc_unbox(value, &sign);

  if (expr == NULL) {
    // allocate the value
    expr = expr_constant(value);
  } else if (true) {
    // If the value was boxed, but the sign of the NaN doesn't match the sign
    // of the expr_t, we need to copy the expr_t as a negated copy, as simply
    // updating the sign would change the sign on all other boxes that share
    // a reference to this expr_t
    if (sign != expr_signbit(expr)) {
      expr = expr_neg(expr);
      EXPR_ERROR("invert number!\n");
    }
  }

  assert(expr != nullptr);

  return expr;
}


#define EXPR_BINARY_OP(NAME, op, TYPE)             \
  FPVM_MATH_DECL(NAME, TYPE) {                     \
    expr_t *a = expr_unbox(src1);                  \
    expr_t *b = expr_unbox(src2);                  \
    double result = a->value op b->value;          \
    expr_t *r = expr_create2(#NAME, result, a, b); \
    *(double *)dest = expr_box(r);                 \
    return 0;                                      \
  }

EXPR_BINARY_OP(add, +, double);
EXPR_BINARY_OP(sub, -, double);
EXPR_BINARY_OP(mul, *, double);
EXPR_BINARY_OP(div, /, double);


FPVM_MATH_DECL(max, double) {
  auto a = expr_unbox(src1);
  auto b = expr_unbox(src2);
  if (a->value > b->value) {
    *(double *)dest = expr_box(a);
  } else {
    *(double *)dest = expr_box(b);
  }
}
FPVM_MATH_DECL(min, double) {
  auto a = expr_unbox(src1);
  auto b = expr_unbox(src2);
  if (a->value < b->value) {
    *(double *)dest = expr_box(a);
  } else {
    *(double *)dest = expr_box(b);
  }
}

// fused multiply and add
FPVM_MATH_DECL(madd, double) {
  auto a = expr_unbox(src1);
  auto b = expr_unbox(src2);
  auto c = expr_unbox(src3);


  double value = a->value * b->value + c->value;
  *(double *)dest = expr_box(expr_create3("madd", value, a, b, c));
  return 0;
}

// fused negate multiply and add
FPVM_MATH_DECL(nmadd, double) {
  auto a = expr_unbox(src1);
  auto b = expr_unbox(src2);
  auto c = expr_unbox(src3);


  double value = -a->value * b->value * c->value;
  *(double *)dest = expr_box(expr_create3("nmadd", value, a, b, c));
  return 0;
}

// fused multiply and sub
FPVM_MATH_DECL(msub, double) {
  auto a = expr_neg(expr_unbox(src1));
  auto b = expr_unbox(src2);
  auto c = expr_unbox(src3);


  double value = a->value * b->value - c->value;
  *(double *)dest = expr_box(expr_create3("msub", value, a, b, c));
  return 0;
}

// fused negate multiply and sub
FPVM_MATH_DECL(nmsub, double) {
  auto a = expr_neg(expr_unbox(src1));
  auto b = expr_unbox(src2);
  auto c = expr_unbox(src3);


  double value = -a->value * b->value - c->value;
  *(double *)dest = expr_box(expr_create3("nmsub", value, a, b, c));
  return 0;
}

FPVM_MATH_DECL(f2i, double) {
  double value = decode_to_double(src1);
  switch (special->byte_width) {
    case 1:
      *(int8_t *)dest = value;
      break;
    case 2:
      *(int16_t *)dest = value;
      break;
    case 4:
      *(int32_t *)dest = value;
      break;
    case 8:
      *(int64_t *)dest = value;
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
      *(uint8_t *)dest = value;
      break;
    case 2:
      *(uint16_t *)dest = value;
      break;
    case 4:
      *(uint32_t *)dest = value;
      break;
    case 8:
      *(uint64_t *)dest = value;
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
      *(float *)dest = value;
      break;
    case 8:
      *(double *)dest = value;
      break;
    default:
      ERROR("Cannot handle double->float(%d)\n", special->byte_width);
      return -1;
      break;
  }
  return 0;
}

FPVM_MATH_DECL(i2f, double) {
  EXPR_ERROR("unhandled operation i2f\n");
  return 0;
}
FPVM_MATH_DECL(u2f, double) {
  EXPR_ERROR("unhandled operation i2f\n");
  return 0;
}

int sqrt_double(op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) {
  expr_t *e = expr_unbox(src1);

  *(double *)dest = expr_box(expr_create1("sqrt", sqrt(e->value), e));
  return 0;
}


int cmpxx_float(op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) {
  ERROR("cmpxx float is not implemented\n");
  return -1;
}




int cmpxx_double(
    op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) {
  // TODO: this function should operate in MPFR precision, but just to
  // get things working we'll do it in double-land
  double a = decode_to_double(src1);
  double b = decode_to_double(src2);
  uint64_t r = 0;

  switch (special->compare_type) {
    case FPVM_INST_COMPARE_INVALID:
      ERROR("invalid compare - should not happen\n");
      return -1;
      break;
    case FPVM_INST_COMPARE_EQ:
      // ordered, signaling qnan
      r = a == b;
      break;
    case FPVM_INST_COMPARE_LT:
      // ordered, signaling qnan
      r = a < b;
      break;
    case FPVM_INST_COMPARE_LE:
      // ordered, signaling qnan
      r = a <= b;
      break;
    case FPVM_INST_COMPARE_UNORD:
      // unordered, non-signaling qnan
      r = isnan(a) || isnan(b);
      break;
    case FPVM_INST_COMPARE_NEQ:
      // ordered, signaling qnan
      r = a != b;
      break;
    case FPVM_INST_COMPARE_NLT:
      // ordered, signaling qnan
      r = !(a < b);
      break;
    case FPVM_INST_COMPARE_NLE:
      // ordered, signaling qnan
      r = !(a <= b);
      break;
    case FPVM_INST_COMPARE_ORD:
      // ordered, signaling qnan
      r = !isnan(a) && !isnan(b);
      break;
    case FPVM_INST_COMPARE_EQ_UQ:
      // unordered, non-signaling qnan
      r = isnan(a) || isnan(b) || a == b;
      break;
    case FPVM_INST_COMPARE_NGE:
      // ordered, non-signaling qnan
      r = !(a >= b);
      break;
    case FPVM_INST_COMPARE_NGT:
      // ordered, non-signaling qnan
      r = !(a > b);
      break;
    case FPVM_INST_COMPARE_FALSE:
      // orderd, non-signaling
      r = 0;
      break;
    case FPVM_INST_COMPARE_NEQ_OQ:
      // ordered, non-signaling
      r = a != b;
      break;
    case FPVM_INST_COMPARE_GE:
      // ordered, non-signaling
      r = a >= b;
      break;
    case FPVM_INST_COMPARE_GT:
      // ordered, non-signaling
      r = a > b;
      break;
    case FPVM_INST_COMPARE_TRUE:
      // ordered, non-signaling
      r = 1;
      break;
    case FPVM_INST_COMPARE_EQ_OS:
      // ordered, signaling
      r = a == b;
      break;
    case FPVM_INST_COMPARE_LT_OQ:
      // ordered, non-signaling
      r = a < b;
      break;
    case FPVM_INST_COMPARE_LE_OQ:
      // ordered, non-signaling
      r = a <= b;
      break;
    case FPVM_INST_COMPARE_UNORD_S:
      // unordered, signaling
      r = isnan(a) || isnan(b);
      break;
    case FPVM_INST_COMPARE_NEQ_US:
      // unordered, signaling
      r = isnan(a) || isnan(b) || a != b;
      break;
    case FPVM_INST_COMPARE_NLT_UQ:
      // unordered, non-signaling
      r = isnan(a) || isnan(b) || !(a < b);
      break;
    case FPVM_INST_COMPARE_NLE_UQ:
      // unordered, non-signaling
      r = isnan(a) || isnan(b) || !(a <= b);
      break;
    case FPVM_INST_COMPARE_ORD_S:
      // ordered signaling
      r = !isnan(a) && !isnan(b);
      break;
    case FPVM_INST_COMPARE_EQ_US:
      // unordered, signalling
      r = isnan(a) || isnan(b) || a == b;
      break;
    case FPVM_INST_COMPARE_NGE_UQ:
      // unordered, non-signaling
      r = isnan(a) || isnan(b) || !(a >= b);
      break;
    case FPVM_INST_COMPARE_NGT_UQ:
      // unordered, non-signaling
      r = isnan(a) || isnan(b) || !(a > b);
      break;
    case FPVM_INST_COMPARE_FALSE_OS:
      // ordered, non-signaling
      r = 0;
      break;
    case FPVM_INST_COMPARE_NEQ_OS:
      // ordered, non-signaling
      r = a != b;
      break;
    case FPVM_INST_COMPARE_GE_OQ:
      // ordered, non-signaling
      r = a >= b;
      break;
    case FPVM_INST_COMPARE_GT_OQ:
      // ordered, non-signaling
      r = a > b;
      break;
    case FPVM_INST_COMPARE_TRUE_US:
      r = 1;
      break;
    default:
      return -1;
      break;
  }

  *(uint64_t *)dest = r;

  return 0;
}




int cmp_double(op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) {
  // double a = decode_to_double(src1);
  // double b = decode_to_double(src2);
  expr_t *a = expr_unbox(src1);
  expr_t *b = expr_unbox(src2);

  // compare_result < 0 - src1 < src2
  // compare_result > 0 - src1 > src2
  // compare_result = 0 - src1 = src2

  int compare_result = 0;
  if (a->value < b->value) {
    compare_result = 1;
  } else if (a->value > b->value) {
    compare_result = -1;
  }

  uint64_t *rflags = special->rflags;
  *rflags &= ~(RFLAGS_OF | RFLAGS_AF | RFLAGS_SF | RFLAGS_ZF | RFLAGS_PF | RFLAGS_CF);

  if (0 /* ??? mpfr_nan_p(*a) || mpfr_nan_p(*b) ??? */) {
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


void NO_TOUCH_FLOAT restore_double_in_place(uint64_t *p) {
  *p = decode_to_double_bits((void *)p);
}

int restore_double(
    op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) {
  EXPR_DEBUG("restore_double %016lx  %016lx\n", *(uint64_t *)src1, *(uint64_t *)src2);
  void *allsrc[4] = {src1, src2, src3, src4};
  // int counter = 0;
  for (int i = 0; i < 4; i++) {
    if (allsrc[i] != NULL) {
      *(double *)allsrc[i] = decode_to_double((void *)allsrc[i]);
    }
  }
  return 0;
}

int restore_float(
    op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) {
  EXPR_ERROR("restore_float %016lx  %016lx\n", *(uint64_t *)src1, *(uint64_t *)src2);
  // skip float
  return 0;
}

int restore_xmm(void *xmm_ptr) {
  // EXPR_DEBUG("restore_xmm %p\n", xmm_ptr);
  double *regs = (double *)xmm_ptr;
  for (int i = 0; i < 2; i++) {
    regs[i] = decode_to_double((void *)&regs[i]);
  }
  return 0;
}

extern "C" {


#define MATH_STUB_ONE(NAME, TYPE, RET)            \
  RET NAME(TYPE a) {                              \
    ORIG_IF_CAN(fedisableexcept, FE_ALL_EXCEPT);  \
    auto src1 = expr_unbox((void *)&a);           \
    RET value = orig_##NAME(src1->value);         \
    auto *dst = expr_create1(#NAME, value, src1); \
    ORIG_IF_CAN(feenableexcept, FE_ALL_EXCEPT);   \
    ORIG_IF_CAN(feclearexcept, FE_ALL_EXCEPT);    \
    return expr_box(dst);                         \
  }

#define MATH_STUB_ONE_DEMOTE(NAME, TYPE, RET)      \
  RET NAME(TYPE a) {                               \
    ORIG_IF_CAN(fedisableexcept, FE_ALL_EXCEPT);   \
    double decoded = decode_to_double((void *)&a); \
    double res = orig_##NAME(decoded);             \
    ORIG_IF_CAN(feenableexcept, FE_ALL_EXCEPT);    \
    ORIG_IF_CAN(feclearexcept, FE_ALL_EXCEPT);     \
    return res;                                    \
  }

#define MATH_STUB_TWO(NAME, TYPE, RET)                  \
  RET NAME(TYPE a, TYPE b) {                            \
    ORIG_IF_CAN(fedisableexcept, FE_ALL_EXCEPT);        \
    auto src1 = expr_unbox((void *)&a);                 \
    auto src2 = expr_unbox((void *)&b);                 \
    RET value = orig_##NAME(src1->value, src2->value);  \
    auto *dst = expr_create2(#NAME, value, src1, src2); \
    ORIG_IF_CAN(feenableexcept, FE_ALL_EXCEPT);         \
    ORIG_IF_CAN(feclearexcept, FE_ALL_EXCEPT);          \
    return expr_box(dst);                               \
  }

MATH_STUB_TWO(pow, double, double)
MATH_STUB_ONE(log, double, double)
MATH_STUB_ONE(exp, double, double)
MATH_STUB_ONE(sin, double, double)
MATH_STUB_ONE(cos, double, double)
MATH_STUB_ONE(tan, double, double)

MATH_STUB_ONE(log10, double, double)

// the program wants round/ceil/floor, lets round
MATH_STUB_ONE_DEMOTE(ceil, double, double)
MATH_STUB_ONE_DEMOTE(floor, double, double)
MATH_STUB_ONE_DEMOTE(round, double, double)

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

double ldexp(double a, int b) {
  ORIG_IF_CAN(fedisableexcept, FE_ALL_EXCEPT);
  auto src1 = expr_unbox((void *)&a);
  double two = 2.0;
  double b_alt = (double)b;
  auto tmp1 = expr_unbox((void *)&two);
  auto tmp2 = expr_unbox((void *)&b_alt);

  double val = orig_ldexp(src1->value, b);

  expr_t *dst = expr_create2("exp", val, src1, expr_create2("mul", 2.0 * b, tmp1, tmp2));

  ORIG_IF_CAN(feenableexcept, FE_ALL_EXCEPT);
  ORIG_IF_CAN(feclearexcept, FE_ALL_EXCEPT);
  return expr_box(dst);
}

long int lround(double a) {
  ORIG_IF_CAN(fedisableexcept, FE_ALL_EXCEPT);
  auto src = expr_unbox((void *)&a);
  long int res = (long int)src->value;
  ORIG_IF_CAN(feenableexcept, FE_ALL_EXCEPT);
  ORIG_IF_CAN(feclearexcept, FE_ALL_EXCEPT);
  return res;
}

double __powidf2(double a, int b) {
  ORIG_IF_CAN(fedisableexcept, FE_ALL_EXCEPT);
  double src1 = decode_to_double((void *)&a);
  double res = orig___powidf2(src1, b);
  ORIG_IF_CAN(feenableexcept, FE_ALL_EXCEPT);
  ORIG_IF_CAN(feclearexcept, FE_ALL_EXCEPT);
  return res;
}

void sincos(double a, double *sin_dst, double *cos_dst) {
  *sin_dst = sin(a);
  *cos_dst = cos(a);
}
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
