// A Wrapper on Vanilla which mimics the "extrema" alt math but
// with full precision.

#include <fpvm/config.h>

#if CONFIG_ALT_MATH_EXTREMA

#include <assert.h>
#include <ctype.h>
#include <fpvm/fpvm_common.h>
#include <fpvm/fpvm_fenv.h>
#include <fpvm/fpvm_math.h>
#include <fpvm/number_system.h>
#include <fpvm/nan_boxing.h>
#include <fpvm/gc.h>
#include <math.h>
#include <stdio.h>
#include <unistd.h>
#include <ctype.h>


#define RFLAGS_CF 0x1UL
#define RFLAGS_PF 0x4UL
#define RFLAGS_AF 0x10UL
#define RFLAGS_ZF 0x40UL
#define RFLAGS_SF 0x80UL
#define RFLAGS_OF 0x800UL

#define RESET "\e[0m"

// support for trap all mode - will eventually
// get brought into arch layer

#if CONFIG_FPTRAPALL
extern void fptrapall_set_ts(void);
extern void fptrapall_clear_ts(void);
#else
#define fptrapall_clear_ts()
#define fptrapall_set_ts()
#endif

//
// TODO -> Rounding Modes
//

//
// The basic idea here is that we will do all operations
// using "vanilla" double precision math, and then convert
// to/from the "extrema" format.
//
//

#if CONFIG_DEBUG_ALT_ARITH
#define MATH_DEBUG(...) DEBUG("extrema: " __VA_ARGS__)
#else
#define MATH_DEBUG(...)
#endif

#if !NO_OUTPUT
#define MATH_INFO(S, ...) INFO("extrema: " S, ##__VA_ARGS__)
#define MATH_ERROR(S, ...) ERROR("extrema: " S, ##__VA_ARGS__)
#else
#define MATH_INFO(S, ...)
#define MATH_ERROR(S, ...)
#endif


#define UNUSED __attribute__((unused))

#define UNIMPL() do { MATH_ERROR("unimplemented code path%s!!\n",""); exit(-1); } while (0)


static void double_unpack(const double d, uint64_t *sign, uint64_t *exp, uint64_t *mantissa)
{
  uint64_t x = *(uint64_t*)&d;
  *sign = (x>>63) & 0x1;
  *exp = (x>>52) & 0x7ff;
  *mantissa = x & 0xfffffffffffffUL;
  //  MATH_DEBUG("double %016lx unpacks to sign=%lu, exp=%016lx (%lu, unbiased %ld, %s), mant=%016lx\n",
  //	     x,*sign,*exp,*exp,((int64_t)*exp)-1023,
  //	     *exp==0 ? "subnorm" : *exp==0x7ff ? *mantissa ? "nan" : "inf" : "norm", *mantissa);
}

static char *bitize(const uint64_t x, const uint64_t count, char *r)
{
  uint64_t i;
  uint64_t t=x;

  for (i=0;i<count;i++) {
    r[i] = (0x1 & (x>>(count-i-1))) ? '1' : '0';
  }
  r[count]=0;
  return r;
}



//
// Will return extrema number in bits 0..numbits_all-1
// with sign, then exp, then mantissa
//
// BAD: all rounding is trunctation
//
static uint64_t extrema_encode(const double x)
{
    return x;
}

// convert extrema into double (will always fit given the constraints,
// namely that numbits_exp<=11 and numbits_exp<=46-numbits_exp-1
static double extrema_decode(const uint64_t x)
{
    return x;
}


static void print_double(const double x)
{
  uint64_t s, e, m;
  char *c, *ib;
  char be[64], me[64];

  double_unpack(x,&s,&e,&m);

  c = e==0 ? "subnorm" : e==0x7ff ? m ? "nan" : "inf" : "norm";
  ib = e==0 ? "0" : e==0x7ff ? "?" : "1";
  bitize(e,11,be);
  bitize(m,52,me);
  
  printf("double %016lx (%16lf) unpacks to sign=%lu, exp=%016lx %s (%lu, unbiased %ld, %s), mant=%016lx %s.%s\n",
	 *(uint64_t *)&x,x,s,e,be,e,e-1023,c,m,ib,me);

}

static int seen_extrema = 0;
static double smallest_seen = 0.0;
static double largest_seen = 0.0;

static void
update_extrema(double v) {
    if(v < 0.0) {
	v = -v;
    }

    if(v == 0.0) {
	// Ignore zeros, we are looking for "tiny" and "massive" non-zero values
	return;
    }

    uint64_t raw = *(uint64_t*)&v;

    if(!seen_extrema) {
	smallest_seen = v;
	largest_seen = v;
	fprintf(stderr, "Starting extrema with value (%lf) raw=0x%lx\n",
		v,
		raw);
	seen_extrema = 1;
	return;
    }

    if(smallest_seen > v) {
	fprintf(stderr, "Updating smallest extrema with value (%lf) raw=0x%lx\n",
		v,
		raw);
	smallest_seen = v;
    }

    if(largest_seen < v) {
	fprintf(stderr, "Updating largest extrema with value (%lf) raw=0x%lx\n",
		v,
		raw);
	largest_seen = v;
    }

    return;
}

// if the value being boxed is negative, state that in the NaN.
static double extrema_box(double val)
{
    update_extrema(val);
    return val;
}

static double extrema_unbox(double val)
{
    update_extrema(val);
    return val;
}

// if ptr points to a valid double, return that. If it points to a boxed value,
// convert it to a double. Designed for debugging
static double decode_to_double(void *ptr)
{
  double value = *(double *)ptr;
  return extrema_unbox(value);
}

static uint64_t decode_to_double_bits(void *ptr)
{
  double v = decode_to_double(ptr);
  return *(uint64_t*)&v;
}

#define extrema_add(x,y,r) ((x)+(y))
#define extrema_sub(x,y,r) ((x)-(y))
#define extrema_mul(x,y,r) ({\
    	(x)*(y);\
	})

static void
update_division_extrema(double num, double den) {

static int seen_division_extrema = 0;
static double smallest_num = 0.0;
static double smallest_den = 0.0;

    if(num < 0.0) {num = -num;}
    if(den < 0.0) {den = -den;}

    uint64_t raw_num = *(uint64_t*)&num;
    uint64_t raw_den = *(uint64_t*)&den;

    double result = num / den;
    uint64_t raw_result = *(uint64_t*)&result;

    if(!seen_division_extrema) {
	smallest_den = den;
	smallest_num = num;
	fprintf(stderr, "Starting division extrema: num=%f, den=%f (raw_num=0x%lx, raw_den=0x%lx) result=%lf, raw_result=0x%lx\n",
		num, den, raw_num, raw_den, result, raw_result);
	seen_division_extrema = 1;
	return;
    }

    if(den == 0.0) {
	fprintf(stderr, "extrema_div: division by zero! num=%f, den=%f (raw_num=0x%lx, raw_den=0x%lx) result=%lf, raw_result=0x%lx\n",
		num, den, raw_num, raw_den, result, raw_result);
    }
    else if(den < smallest_den) {
	smallest_den = den;
        fprintf(stderr, "New division denominator extrema: num=%f, den=%f (raw_num=0x%lx, raw_den=0x%lx) result=%lf, raw_result=0x%lx\n",
		num, den, raw_num, raw_den, result, raw_result);
    }

    if(num == 0.0) {
	// Ignore numerators which are zero
    }
    else if(num < smallest_num) {
	smallest_num = num;
        fprintf(stderr, "New division numerator extrema: num=%f, den=%f (raw_num=0x%lx, raw_den=0x%lx) result=%lf, raw_result=0x%lx\n",
		num, den, raw_num, raw_den, result, raw_result);
    }
}

#define extrema_div(x,y,r) ({\
	update_division_extrema(x,y);\
	(x)/(y);\
	})
#define extrema_max(x,y,r) ((x) > (y) ? (x) : (y))
#define extrema_min(x,y,r) ((x) < (y) ? (x) : (y))

#define EXTREMA_BINARY_OP(OP, TYPE)					\
  FPVM_MATH_DECL(OP, TYPE) {						\
    double dst;								\
    double a = extrema_unbox(*(double*)src1);				\
    double b = extrema_unbox(*(double*)src2);				\
    dst = extrema_##OP(a,b,ROUNDING_MODE);				\
    *(double *)dest = extrema_box(dst);					\
    return 0;								\
  }

EXTREMA_BINARY_OP(add, double);
EXTREMA_BINARY_OP(sub, double);
EXTREMA_BINARY_OP(mul, double);
EXTREMA_BINARY_OP(div, double);
EXTREMA_BINARY_OP(max, double);
EXTREMA_BINARY_OP(min, double);

// fused multiply and add
FPVM_MATH_DECL(madd, double)
{
  double a = extrema_unbox(*(double*)src1);
  double b = extrema_unbox(*(double*)src2);
  double c = extrema_unbox(*(double*)src3);
  double r = a * b + c; // ROUNDING_MODE
  *(double *)dest = extrema_box(r);
  return 0;
}

// fused negate multiply and add
FPVM_MATH_DECL(nmadd, double)
{
  double a = extrema_unbox(*(double*)src1);
  double b = extrema_unbox(*(double*)src2);
  double c = extrema_unbox(*(double*)src3);
  double r = (-a) * b + c; // ROUNDING_MODE
  *(double *)dest = extrema_box(r);
  return 0;
}

// fused multiply and sub
FPVM_MATH_DECL(msub, double)
{
  double a = extrema_unbox(*(double*)src1);
  double b = extrema_unbox(*(double*)src2);
  double c = extrema_unbox(*(double*)src3);
  double r = a * b - c; // ROUNDING_MODE
  *(double *)dest = extrema_box(r);
  return 0;
}

// fused negate multiply and sub
FPVM_MATH_DECL(nmsub, double) {
  double a = extrema_unbox(*(double*)src1);
  double b = extrema_unbox(*(double*)src2);
  double c = extrema_unbox(*(double*)src3);
  double r = (-a) * b - c; // ROUNDING_MODE
  *(double *)dest = extrema_box(r);
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
  double a = extrema_unbox(*(double*)src1);
  double r = sqrt(a);
  *(double *)dest = extrema_box(r);
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

void altmath_demote_double_in_place(double *p)
{
  *p = extrema_unbox(*p);
}

void altmath_promote_double_in_place(double *p)
{
  *p = extrema_box(*p);
}

void altmath_print_double(double *p, char *dest, int n)
{
  double x = *p;
  int sign;
  uint64_t tval;
  uint64_t s, e, m;
  char *c;
  char *ib;
  char be[64], me[64];

  double_unpack(*p,&s,&e,&m);
  
  c = e==0 ? "subnorm" : e==0x7ff ? m ? "nan" : "inf" : "norm";
  ib = e==0 ? "0" : e==0x7ff ? "?" : "1";
  bitize(e,11,be);
  bitize(m,52,me);
  
  snprintf(dest,n,"double %016lx unpacks to sign=%lu, exp=%016lx %s (%lu, unbiased %ld, %s), mant=%016lx %s.%s [double=%lf]",
	     *(uint64_t *)&x,s,e,be,e,e-1023,c,m,ib,me,x);
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
    fptrapall_clear_ts();						\
    ORIG_IF_CAN(fedisableexcept, FE_ALL_EXCEPT);			\
    double src1 = extrema_unbox(a);					\
    double res = orig_##NAME(src1);					\
    ORIG_IF_CAN(feenableexcept, FE_ALL_EXCEPT);				\
    ORIG_IF_CAN(feclearexcept, FE_ALL_EXCEPT);				\
    res = extrema_box(res);						\
    fptrapall_set_ts();							\
    return res;								\
  }

#define MATH_STUB_ONE_DEMOTE(NAME, TYPE, RET)				\
  RET NAME(TYPE a) {							\
    fptrapall_clear_ts();						\
    ORIG_IF_CAN(fedisableexcept, FE_ALL_EXCEPT);			\
    double src1 = decode_to_double((void*)&a);				\
    double res = orig_##NAME(src1);					\
    ORIG_IF_CAN(feenableexcept, FE_ALL_EXCEPT);				\
    ORIG_IF_CAN(feclearexcept, FE_ALL_EXCEPT);				\
    fptrapall_set_ts();							\
    return res;								\
  }
  
#define MATH_STUB_TWO(NAME, TYPE, RET)					\
  RET NAME(TYPE a, TYPE b) {						\
    fptrapall_clear_ts();						\
    ORIG_IF_CAN(fedisableexcept, FE_ALL_EXCEPT);			\
    double src1 = extrema_unbox(a);					\
    double src2 = extrema_unbox(b);					\
    double res = orig_##NAME(a,b);					\
    ORIG_IF_CAN(feenableexcept, FE_ALL_EXCEPT);				\
    ORIG_IF_CAN(feclearexcept, FE_ALL_EXCEPT);				\
    res = extrema_box(res);						\
    fptrapall_set_ts();							\
    return res;								\
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
  fptrapall_clear_ts();			      
  ORIG_IF_CAN(fedisableexcept, FE_ALL_EXCEPT);
  double src = extrema_unbox(a);
  // hideous
  double res = src * orig_pow(2.0,(double)b);
  ORIG_IF_CAN(feenableexcept, FE_ALL_EXCEPT);
  ORIG_IF_CAN(feclearexcept, FE_ALL_EXCEPT);
  res =  extrema_box(res);
  fptrapall_set_ts();
  return res;
}

long int lround(double a) {
  fptrapall_clear_ts();			       
  ORIG_IF_CAN(fedisableexcept, FE_ALL_EXCEPT);
  double src = extrema_unbox(a);
  double res = orig_lround(src);
  ORIG_IF_CAN(feenableexcept, FE_ALL_EXCEPT);
  ORIG_IF_CAN(feclearexcept, FE_ALL_EXCEPT);
  res = extrema_box(res);
  fptrapall_set_ts();
  return res;
}

double __powidf2(double a, int b) {
  fptrapall_clear_ts();			       
  ORIG_IF_CAN(fedisableexcept, FE_ALL_EXCEPT);
  double src = extrema_unbox(a);
  double res = orig___powidf2(src, b);
  ORIG_IF_CAN(feenableexcept, FE_ALL_EXCEPT);
  ORIG_IF_CAN(feclearexcept, FE_ALL_EXCEPT);
  res = extrema_box(res);
  fptrapall_set_ts();
  return res;
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
  fptrapall_clear_ts();			       
  ORIG_IF_CAN(fedisableexcept, FE_ALL_EXCEPT);
  double src = extrema_unbox(a);
  orig_sincos(src, sin_dst, cos_dst);
  ORIG_IF_CAN(feenableexcept, FE_ALL_EXCEPT);
  ORIG_IF_CAN(feclearexcept, FE_ALL_EXCEPT);
  fptrapall_set_ts();
}

// ignored float implementations
FPVM_MATH_DECL(add, float) {
  fprintf(stderr, "extrema should not be invoked with floats\n");
  return 0;
}
FPVM_MATH_DECL(sub, float) {
  fprintf(stderr, "extrema should not be invoked with floats\n");
  return 0;
}
FPVM_MATH_DECL(nmsub, float) {
  fprintf(stderr, "extrema should not be invoked with floats\n");
  return 0;
}
FPVM_MATH_DECL(msub, float) {
  fprintf(stderr, "extrema should not be invoked with floats\n");
  return 0;
}
FPVM_MATH_DECL(mul, float) {
  fprintf(stderr, "extrema should not be invoked with floats\n");
  return 0;
}
FPVM_MATH_DECL(div, float) {
  fprintf(stderr, "extrema should not be invoked with floats\n");
  return 0;
}
FPVM_MATH_DECL(max, float) {
  fprintf(stderr, "extrema should not be invoked with floats\n");
  return 0;
}
FPVM_MATH_DECL(min, float) {
  fprintf(stderr, "extrema should not be invoked with floats\n");
  return 0;
}
FPVM_MATH_DECL(sqrt, float) {
  fprintf(stderr, "extrema should not be invoked with floats\n");
  return 0;
}
FPVM_MATH_DECL(madd, float) {
  fprintf(stderr, "extrema should not be invoked with floats\n");
  return 0;
}
FPVM_MATH_DECL(nmadd, float) {
  fprintf(stderr, "extrema should not be invoked with floats\n");
  return 0;
}
FPVM_MATH_DECL(f2i, float) {
  fprintf(stderr, "extrema should not be invoked with floats\n");
  return 0;
}
FPVM_MATH_DECL(f2u, float) {
  fprintf(stderr, "extrema should not be invoked with floats\n");
  return 0;
}
FPVM_MATH_DECL(i2f, float) {
  fprintf(stderr, "extrema should not be invoked with floats\n");
  return 0;
}
FPVM_MATH_DECL(u2f, float) {
  fprintf(stderr, "extrema should not be invoked with floats\n");
  return 0;
}
FPVM_MATH_DECL(f2f, float) {
  fprintf(stderr, "extrema should not be invoked with floats\n");
  return 0;
}
FPVM_MATH_DECL(cmp, float) {
  fprintf(stderr, "extrema should not be invoked with floats\n");
  return 0;
}

void fpvm_number_init(UNUSED void *x) {}
void fpvm_number_deinit(UNUSED void *y) {}

void fpvm_number_system_init()
{
  MATH_DEBUG("inited\n");
}

void fpvm_number_system_deinit()
{
  MATH_DEBUG("deinited\n");
}

#endif
