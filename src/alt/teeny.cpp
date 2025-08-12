// an implementation of tiny numbers that are directly
// embedded in nans as opposed to having pointers to
// them embedded in the nans

#include <fpvm/config.h>

#if CONFIG_ALT_MATH_TEENY

#include <assert.h>
#include <fpvm/fpvm_common.h>
#include <fpvm/fpvm_fenv.h>
#include <fpvm/fpvm_math.h>
#include <fpvm/number_system.h>
#include <fpvm/nan_boxing.h>
#include <fpvm/gc.h>
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

//
// TODO -> Rounding Modes
//

//
// The basic idea here is that we will do all operations
// using "vanilla" double precision math, and then convert
// to/from the "teeny" format.
//
//

#if CONFIG_DEBUG_ALT_ARITH
#define MATH_DEBUG(...) DEBUG("teeny: " __VA_ARGS__)
#else
#define MATH_DEBUG(...)
#endif

#if !NO_OUTPUT
#define MATH_INFO(S, ...) INFO("teeny: " S, ##__VA_ARGS__)
#define MATH_ERROR(S, ...) ERROR("teeny: " S, ##__VA_ARGS__)
#else
#define MATH_INFO(S, ...)
#define MATH_ERROR(S, ...)
#endif


static int numbits_exp=CONFIG_TEENY_EXP_BITS;
static int numbits_mant=CONFIG_TEENY_MANT_BITS;
static int numbits_all=(1+(CONFIG_TEENY_EXP_BITS+CONFIG_TEENY_MANT_BITS));
static int bias = ((1<<(numbits_exp-1))-1);


void fpvm_number_init(void *ptr)
{
  (void)ptr;
  if (getenv("FPVM_TEENY_EXP_BITS")) {
    numbits_exp=atoi(getenv("FPVM_TEENY_EXP_BITS"));
  }
  if (getenv("FPVM_TEENY_MANT_BITS")) {
    numbits_exp=atoi(getenv("FPVM_TEENY_EXP_BITS"));
  }
  
  numbits_all = 1 + numbits_exp + numbits_mant;
  
  if (numbits_exp>11) {
    MATH_ERROR("too many exponent bits (%d) required, maximum is %d\n",numbits_exp,11);
    exit(-1);
  }
  
    
  if (numbits_all>47) {
    MATH_ERROR("too many bits (%d) required, but only %d available\n",numbits_all,47);
    exit(-1);
  }
  
  MATH_DEBUG("initialized with %d exponent (bias %d) and %d mantissa bits\n",numbits_exp,bias,numbits_mant);
}

void fpvm_number_deinit(void *ptr)
{
  (void)ptr;
  MATH_DEBUG("deinited%s\n","");
}

//
// Will return teeny number in bits 0..numbits_all-1
// with sign, then exp, then mantissa
//
uint64_t teeny_encode(double src)
{
  // NOT DONE
  return *(uint64_t*)&src;
}

// will decode the last 47 bits into a double
double teeny_decode(uint64_t src)
{
  //NOT DONE
  return *(double*)&src;
}


// if ptr points to a valid double, return that. If it points to a boxed value,
// convert it to a double. Designed for debugging
static double decode_to_double(void *ptr)
{
  double value = *(double *)ptr;
  int sign_bit;
  uint64_t tval;
  
  if (fpvm_gc_unbox_raw(value,&sign_bit,(void**)&tval)) {
    return teeny_decode(tval);
  } else {
    return value;
  }
}

static uint64_t decode_to_double_bits(void *ptr)
{
  double v = decode_to_double(ptr);
  return *(uint64_t*)&v;
}

// if the value being boxed is negative, state that in the NaN.
static double teeny_box(double val)
{
  uint64_t tval = teeny_encode(val);
  uint64_t sign = val<0;
  double result = fpvm_gc_box((void *)tval, sign);
  *(uint64_t *)&result |= (sign << 63);
  return result;
}

// Decode an mpfr pointer from a pointer to a double
static double teeny_unbox(double val) {
  int sign;
  uint64_t tval;

  if (fpvm_gc_unbox_raw(val,&sign,(void**)&tval)) {
    double result = teeny_decode(tval);
    int resultsign = result<0;
    if (sign != resultsign) {
      return -result;
    } else {
      return result;
    }
  } else {
    return val;
  }
}
#define teeny_add(x,y,r) ((x)+(y))
#define teeny_sub(x,y,r) ((x)-(y))
#define teeny_mul(x,y,r) ((x)*(y))
#define teeny_div(x,y,r) ((x)/(y))
#define teeny_max(x,y,r) ((x) > (y) ? (x) : (y))
#define teeny_min(x,y,r) ((x) < (y) ? (x) : (y))

#define TEENY_BINARY_OP(OP, TYPE)					\
  FPVM_MATH_DECL(OP, TYPE) {						\
    double dst;								\
    double a = teeny_unbox(*(double*)src1);				\
    double b = teeny_unbox(*(double*)src2);				\
    dst = teeny_##OP(a,b,ROUNDING_MODE);				\
    *(double *)dest = teeny_box(dst);					\
    return 0;								\
  }

TEENY_BINARY_OP(add, double);
TEENY_BINARY_OP(sub, double);
TEENY_BINARY_OP(mul, double);
TEENY_BINARY_OP(div, double);
TEENY_BINARY_OP(max, double);
TEENY_BINARY_OP(min, double);

// fused multiply and add
FPVM_MATH_DECL(madd, double)
{
  double a = teeny_unbox(*(double*)src1);
  double b = teeny_unbox(*(double*)src2);
  double c = teeny_unbox(*(double*)src3);
  double r = a * b + c; // ROUNDING_MODE
  *(double *)dest = teeny_box(r);
  return 0;
}

// fused negate multiply and add
FPVM_MATH_DECL(nmadd, double)
{
  double a = teeny_unbox(*(double*)src1);
  double b = teeny_unbox(*(double*)src2);
  double c = teeny_unbox(*(double*)src3);
  double r = (-a) * b + c; // ROUNDING_MODE
  *(double *)dest = teeny_box(r);
  return 0;
}

// fused multiply and sub
FPVM_MATH_DECL(msub, double)
{
  double a = teeny_unbox(*(double*)src1);
  double b = teeny_unbox(*(double*)src2);
  double c = teeny_unbox(*(double*)src3);
  double r = a * b - c; // ROUNDING_MODE
  *(double *)dest = teeny_box(r);
  return 0;
}

// fused negate multiply and sub
FPVM_MATH_DECL(nmsub, double) {
  double a = teeny_unbox(*(double*)src1);
  double b = teeny_unbox(*(double*)src2);
  double c = teeny_unbox(*(double*)src3);
  double r = (-a) * b - c; // ROUNDING_MODE
  *(double *)dest = teeny_box(r);
  return 0;
}

FPVM_MATH_DECL(f2i, double) {
  double value = decode_to_double(src1);
  return vanilla_f2i_double(special,dest,&value,0,0,0);
}

FPVM_MATH_DECL(f2u, double) {
  double value = decode_to_double(src1);
  return vanilla_f2u_double(special,dest,&value,0,0,0);
}

int f2f_double(op_special_t *special, void *dest, void *src1, void *src2,
               void *src3, void *src4) {
  double value = decode_to_double(src1);
  return vanilla_f2f_double(special,dest,&value,0,0,0);
}

FPVM_MATH_DECL(i2f, double) {
  MATH_ERROR("unhandled operation i2f\n");
  return 0;
}
FPVM_MATH_DECL(u2f, double) {
  MATH_ERROR("unhandled operation i2f\n");
  return 0;
}

int sqrt_double(op_special_t *special, void *dest, void *src1, void *src2,
                void *src3, void *src4) {
  double a = teeny_unbox(*(double*)src1);
  double r = sqrt(a);
  *(double *)dest = teeny_box(r);
  return 0;
}


int cmpxx_float(
    op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) {
  ERROR("cmpxx float is not implemented\n");
  return -1;
}




int cmpxx_double(
    op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) {
  
  double a = decode_to_double(src1);
  double b = decode_to_double(src2);

  return vanilla_cmpxx_double(special,dest,&a,&b,0,0);

}





int cmp_double(op_special_t *special, void *dest, void *src1, void *src2,
               void *src3, void *src4) {

  double a = decode_to_double(src1);
  double b = decode_to_double(src2);

  return vanilla_cmp_double(special,0,&a,&b,0,0);

}


void NO_TOUCH_FLOAT restore_double_in_place(uint64_t *p) {
  *p = decode_to_double_bits((void*)p);
}

int restore_double(op_special_t *special, void *dest, void *src1, void *src2,
                   void *src3, void *src4) {
  MATH_DEBUG("restore_double %016lx  %016lx\n", *(uint64_t *)src1,
             *(uint64_t *)src2);
  void *allsrc[4] = {src1, src2, src3, src4};
  // int counter = 0;
  for (int i = 0; i < 4; i++) {
    if (allsrc[i] != NULL) {
      *(double *)allsrc[i] = decode_to_double((void *)allsrc[i]);
    }
  }
  return 0;
}

int restore_float(op_special_t *special, void *dest, void *src1, void *src2,
                  void *src3, void *src4) {
  MATH_ERROR("restore_float %016lx  %016lx\n", *(uint64_t *)src1,
             *(uint64_t *)src2);
  // skip float
  return 0;
}

int restore_xmm(void *xmm_ptr) {
  // MPFR_DEBUG("restore_xmm %p\n", xmm_ptr);
  double *regs = (double *)xmm_ptr;
  for (int i = 0; i < 2; i++) {
    regs[i] = decode_to_double((void *)&regs[i]);
  }
  return 0;
}

extern "C" {

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

#define MATH_STUB_ONE(NAME, TYPE, RET)					\
  RET NAME(TYPE a) {							\
    ORIG_IF_CAN(fedisableexcept, FE_ALL_EXCEPT);			\
    double src1 = teeny_unbox(a);					\
    double res = orig_##NAME(src1);					\
    ORIG_IF_CAN(feenableexcept, FE_ALL_EXCEPT);				\
    ORIG_IF_CAN(feclearexcept, FE_ALL_EXCEPT);				\
    return teeny_box(res);						\
  }

#define MATH_STUB_ONE_DEMOTE(NAME, TYPE, RET)				\
  RET NAME(TYPE a) {							\
    ORIG_IF_CAN(fedisableexcept, FE_ALL_EXCEPT);			\
    double src1 = decode_to_double((void*)&a);				\
    double res = orig_##NAME(src1);					\
    ORIG_IF_CAN(feenableexcept, FE_ALL_EXCEPT);				\
    ORIG_IF_CAN(feclearexcept, FE_ALL_EXCEPT);				\
    return res;								\
  }
  
#define MATH_STUB_TWO(NAME, TYPE, RET)					\
  RET NAME(TYPE a, TYPE b) {						\
    ORIG_IF_CAN(fedisableexcept, FE_ALL_EXCEPT);			\
    double src1 = teeny_unbox(a);					\
    double src2 = teeny_unbox(b);					\
    double res = orig_##NAME(a,b);					\
    ORIG_IF_CAN(feenableexcept, FE_ALL_EXCEPT);				\
    ORIG_IF_CAN(feclearexcept, FE_ALL_EXCEPT);				\
    return teeny_box(res);						\
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
  double src = teeny_unbox(a);
  // hideous
  double res = src * orig_pow(2.0,(double)b);
  ORIG_IF_CAN(feenableexcept, FE_ALL_EXCEPT);
  ORIG_IF_CAN(feclearexcept, FE_ALL_EXCEPT);
  return teeny_box(res);
}

long int lround(double a) {
  ORIG_IF_CAN(fedisableexcept, FE_ALL_EXCEPT);
  double src = teeny_unbox(a);
  double res = orig_lround(src);
  ORIG_IF_CAN(feenableexcept, FE_ALL_EXCEPT);
  ORIG_IF_CAN(feclearexcept, FE_ALL_EXCEPT);
  return teeny_box(res);
}

double __powidf2(double a, int b) {
  ORIG_IF_CAN(fedisableexcept, FE_ALL_EXCEPT);
  double src = teeny_unbox(a);
  double res = orig___powidf2(src, b);
  ORIG_IF_CAN(feenableexcept, FE_ALL_EXCEPT);
  ORIG_IF_CAN(feclearexcept, FE_ALL_EXCEPT);
  return teeny_box(res);
}

// double pow(double a, double b){
//     auto src1 = mpfr_unbox((void*)&a);
//     auto src2 = mpfr_unbox((void*)&b);
//     mpfr_t *dst = allocate_mpfr();
//     mpfr_pow(*dst, *src1, *src2, MPFR_RNDD);
//     return mpfr_box(dst);
// }

// double sin(double a) {
//     auto src = mpfr_unbox((void*)&a);
//     mpfr_t *dst = allocate_mpfr();
//     mpfr_sin(*dst, *src, MPFR_RNDD);
//     return mpfr_box(dst);
// }
// double cos(double a) {
//     auto src = mpfr_unbox((void*)&a);
//     mpfr_t *dst = allocate_mpfr();
//     mpfr_cos(*dst, *src, MPFR_RNDD);
//     return mpfr_box(dst);
// }
// double tan(double a) {
//     auto src = mpfr_unbox((void*)&a);
//     mpfr_t *dst = allocate_mpfr();
//     mpfr_tan(*dst, *src, MPFR_RNDD);
//     return mpfr_box(dst);
// }
void sincos(double a, double *sin_dst, double *cos_dst) {
  *sin_dst = sin(a);
  *cos_dst = cos(a);
}
}

// ignored float implementations
FPVM_MATH_DECL(add, float) {
  fprintf(stderr, "teeny should not be invoked with floats");
  return 0;
}
FPVM_MATH_DECL(sub, float) {
  fprintf(stderr, "teeny should not be invoked with floats");
  return 0;
}
FPVM_MATH_DECL(nmsub, float) {
  fprintf(stderr, "teeny should not be invoked with floats");
  return 0;
}
FPVM_MATH_DECL(msub, float) {
  fprintf(stderr, "teeny should not be invoked with floats");
  return 0;
}
FPVM_MATH_DECL(mul, float) {
  fprintf(stderr, "teeny should not be invoked with floats");
  return 0;
}
FPVM_MATH_DECL(div, float) {
  fprintf(stderr, "teeny should not be invoked with floats");
  return 0;
}
FPVM_MATH_DECL(max, float) {
  fprintf(stderr, "teeny should not be invoked with floats");
  return 0;
}
FPVM_MATH_DECL(min, float) {
  fprintf(stderr, "teeny should not be invoked with floats");
  return 0;
}
FPVM_MATH_DECL(sqrt, float) {
  fprintf(stderr, "teeny should not be invoked with floats");
  return 0;
}
FPVM_MATH_DECL(madd, float) {
  fprintf(stderr, "teeny should not be invoked with floats");
  return 0;
}
FPVM_MATH_DECL(nmadd, float) {
  fprintf(stderr, "teeny should not be invoked with floats");
  return 0;
}
FPVM_MATH_DECL(f2i, float) {
  fprintf(stderr, "teeny should not be invoked with floats");
  return 0;
}
FPVM_MATH_DECL(f2u, float) {
  fprintf(stderr, "teeny should not be invoked with floats");
  return 0;
}
FPVM_MATH_DECL(i2f, float) {
  fprintf(stderr, "teeny should not be invoked with floats");
  return 0;
}
FPVM_MATH_DECL(u2f, float) {
  fprintf(stderr, "teeny should not be invoked with floats");
  return 0;
}
FPVM_MATH_DECL(f2f, float) {
  fprintf(stderr, "teeny should not be invoked with floats");
  return 0;
}
FPVM_MATH_DECL(cmp, float) {
  fprintf(stderr, "teeny should not be invoked with floats");
  return 0;
}

#endif
