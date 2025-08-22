// an implementation of tiny numbers that are directly
// embedded in nans as opposed to having pointers to
// them embedded in the nans
//
//
// The current teeny implementation has the following requirements:
//
// 1) the number of exponent bits is at most 11 (this allows for
//    straightforward conversion into doubles.  Every teeny
//    has a representation of the same class in double)
//
// 2) the number of mantissa bits is at most 50 - numexp_bits - 1 bits
//    (this allows for FPVM NaN-boxing to be be used to directly
//    embed a teeny number in a double nan.
//
//
// A special problem here is that the "pointers" we will box
// could be all zero (NULL), which is a teeny positive zero.
// To handle this, when we box, we will make bit 50 1, and
// when we unbox, we will make bit 50 0.  This will force
// the boxed value to then always be a NAN.  More specifically,
// the boxer will create a value of form:
//
// S 11111111111 01ppppppppppppppppppppppppppppppppp
//   11 bits     52 bits
//

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


#define UNUSED __attribute__((unused))

static int numbits_exp=CONFIG_TEENY_EXP_BITS;
static int numbits_mant=CONFIG_TEENY_MANT_BITS;
static int numbits_all=(1+(CONFIG_TEENY_EXP_BITS+CONFIG_TEENY_MANT_BITS));
static int bias = ((1<<(CONFIG_TEENY_EXP_BITS))-1);
static uint64_t exp_bitmask=0;
static uint64_t mant_bitmask=0;


static uint64_t bitmask(const uint64_t count)
{
  return ~(-1ULL << count);
}



static double double_pack(uint64_t sign, uint64_t exp, uint64_t mantissa)
{
  uint64_t r;
  
  sign &= 0x1;
  exp &= 0x7ff;
  mantissa &= 0xfffffffffffffUL;
   
  r = (sign << 63) | (exp << 52) | mantissa;
  
  return *(double*)&r;
}

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



static int is_double_special_exp(const uint64_t exp)
{
  return exp == 0x7ff;
}

static int is_double_denorm_exp(const uint64_t exp)
{
  return exp == 0;
}



static uint64_t teeny_pack(uint64_t sign, uint64_t exp, uint64_t mantissa)
{
  uint64_t x;
  
  sign &= 0x1;
  exp &= exp_bitmask;
  mantissa &= mant_bitmask;
  
  x =  (sign << (numbits_exp + numbits_mant)) | (exp << numbits_mant) | mantissa;

  MATH_DEBUG("packing sign=%lu exp=%016lx mantissa=%016lx into %016lx\n",sign,exp,mantissa, x);

  return x;

}

static void teeny_unpack(const uint64_t x, uint64_t *sign, uint64_t *exp, uint64_t *mantissa)
{
  *sign = (x>>(numbits_exp + numbits_mant)) & 0x1;
  *exp = (x>>numbits_mant) & exp_bitmask;
  *mantissa = x & mant_bitmask;
  //  MATH_DEBUG("teeny %016lx unpacks to sign=%lu, exp=%016lx (%lu, unbiased %ld, %s), mant=%016lx\n",
  //	     x,*sign,*exp,*exp,((int64_t)*exp)-bias,
  //	     *exp==0 ? "subnorm" : *exp==exp_bitmask ? *mantissa ? "nan" : "inf" : "norm", *mantissa);
	    
}


static int is_teeny_special_exp(const uint64_t exp)
{
  return exp == exp_bitmask;
}

static int is_teeny_denorm_exp(const uint64_t exp)
{
  return exp == 0;
}


static int is_teeny_nan(const uint64_t x)
{
  uint64_t s,e,m;
  
  teeny_unpack(x,&s,&e,&m);
  
  return is_teeny_special_exp(e) && m!=0;
}

static int is_teeny_inf(const uint64_t x)
{
  uint64_t s,e,m;
  
  teeny_unpack(x,&s,&e,&m);
  
  return is_teeny_special_exp(e) && m==0;
}

#define UNIMPL() do { MATH_ERROR("unimplemented code path%s!!\n",""); exit(-1); } while (0)

//
// Will return teeny number in bits 0..numbits_all-1
// with sign, then exp, then mantissa
//
// BAD: all rounding is trunctation
//
static uint64_t teeny_encode(const double x)
{
  uint64_t s,e,m; // double sign, exp, mantissa
  uint64_t lz;    // leading zero count for teeny subnormal mantissa
  int64_t  ube;   // unbiased teeny exponent
  int64_t  be;    // rebiased double exponent

  double_unpack(x,&s,&e,&m);

  MATH_DEBUG("encode double %016lx (%lf)\n",*(uint64_t*)&x,x);
  
  if (is_double_special_exp(e)) {
    if (m==0) {
      // infinity
      MATH_DEBUG("infinity\n");
      return teeny_pack(s,exp_bitmask,m);
    } else {
      // nan - we will preserve the top bit and make sure it is nonzero
      // top bit is signalling/nonsignaling and is preserved
      // remaining bits are a  1 if any remaining bits in double
      // mantissa are 1.   This means that signalling nan
      // (top bit zero, some other bit nonzero), and quiet nan
      // (top bit one, perhaps all other bits zero) will both
      // turn into a nan, not an infinity
      MATH_DEBUG("nan mantissa=%016lx\n",m);
      m = (m >> (52 - numbits_mant)) | (!!__builtin_popcountl(m & 0x7ffffffffffffUL));
      MATH_DEBUG("teeny nan mantissa=%016lx\n",m);
      return teeny_pack(s,exp_bitmask,m);
    }
  } else {
    if (e!=0) {
      // normal
      ube = e - 1023;   // unbias double exp
      be = ube + bias;  // rebias exp for teeny
      MATH_DEBUG("norm exp=%016lx (%lu unbiased %ld rebiased %ld)\n", e,e,ube,be);
      if (be < -numbits_mant) {
	// cannot fit, underflow to zero
	MATH_DEBUG("underflow to zero\n");
	return teeny_pack(s,0,0);
      } else if ((int64_t)be < 1) {
	// be is in range [-numbits_mant,1)
	// toss on the leading 1
	m = m | 0x1000000000000UL;
	// shift it to eliminate bits we don't have in tiny
	// strictly, this should round here, but as a start
	// we will simple shift out the bits
	m >>= -be + 1;
	// now shift it to place (52 -> numbits_mant)
	m >>= 52 - numbits_mant;
	MATH_DEBUG("teeny subnorm mantisa=%016lx\n",m);
	return teeny_pack(s,0,m);
      } else if (be < exp_bitmask) {
	// just shift out the irrelevant bits
	m >>= 52 - numbits_mant;
	MATH_DEBUG("teeny norm mantissa=%016lx\n",m);
	return teeny_pack(s,be,m);
      } else {
	MATH_DEBUG("overflow to infinity\n");
	return teeny_pack(s,exp_bitmask,0);
      }
    } else {
      // subnorm
      ube = 1 - 1023;
      be = ube + bias;
      MATH_DEBUG("subnorm exp=%016lx (%lu unbiased %ld rebiased %ld)\n", e,e,ube,be);
      if (be < -numbits_mant) {
	// cannot fit, underflow to zero
	MATH_DEBUG("underflow to zero\n");
	return teeny_pack(s,0,0);
      } else if (be < 1) {
	// be is in range [-numbits_mant,1)
	// use mantissa directly, since implicit leading bit is zero
	//
	// shift it to eliminate bits we don't have in tiny
	// strictly, this should round here, but as a start
	// we will simple shift out the bits
	m >>= -be + 1;
	// now shift it to place (52 -> numbits_mant)
	m >>= 52 - numbits_mant;
	MATH_DEBUG("teeny subnorm mantisa=%016lx\n",m);
	return teeny_pack(s,0,m);
      } else if (be < exp_bitmask) {
	// just shift out the irrelevant bits
	m >>= 52 - numbits_mant;
	MATH_DEBUG("teeny norm mantissa=%016lx\n",m);
	return teeny_pack(s,be,m);
      } else {
	MATH_DEBUG("overflow to infinity\n");
	return teeny_pack(s,exp_bitmask,0);
      }
      
    }
  }
}

// convert teeny into double (will always fit given the constraints,
// namely that numbits_exp<=11 and numbits_exp<=46-numbits_exp-1
static double teeny_decode(const uint64_t x)
{
  uint64_t s,e,m; // teeny sign, exp, mantissa
  uint64_t r=0;   // output result bitpattern
  int64_t  lz;    // leading zero count for teeny subnormal mantissa
  int64_t  ube;   // unbiased teeny exponent
  int64_t  be;    // rebiased double exponent

  teeny_unpack(x,&s,&e,&m);

  if (is_teeny_special_exp(e)) {
    // infinity or nan, just immediately build thing as a
    // double, reusing sign and the mantissa bits we have available
    return double_pack(s,0x7ffUL,m << (52 - numbits_mant));
  } else {
    if (e!=0) {
      // normal
      ube = e - bias; // unbias teeny exp
      // given the constraint on the number of teeny exp bits,
      // this must fit into a double normal
      be = ube + 1023;  // rebias exp for double
      return double_pack(s,be,m << (52 - numbits_mant));
    } else { // e==0
      if (m==0) {
	// zero
	return double_pack(s,0,0);
      } else {
	// subnormal, nonzero - mantissa has some 1
	ube = 1 - bias;   // teeny subnormal exponent
	be = ube + 1023;  // rebias exp for double
	lz = __builtin_clzl(m) - (64 - numbits_mant);
	// can we make it a normal in double?
	// if we subtract the shift (lz+1), the biased
	// exponent must be >=1
	if ((be - (lz + 1)) < 1) {
	  // nope, make subnormal, easy
	  return double_pack(s,0,m << (52 - numbits_mant));
	} else {
	  // yes, make normal, note that mantissa
	  // shifts left lz+1 slots, and then the
	  // leading one is dropped (becomes implied)
	  // clear current leading 1
	  m &= ~(0x1ULL << (numbits_mant - lz - 1));
	  // shift remaining bits over to after the
	  // binary point in the teeny mantissa
	  m <<= (lz + 1);
	  // shrink the bias due to the shift
	  be -= (lz + 1);
	  return double_pack(s,be,m << (52 - numbits_mant));
	}	  
      }
    }
  }
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

static void print_teeny(const uint64_t x)
{
  uint64_t s, e, m;
  char *c;
  char *ib;
  char be[64], me[64];
  
  teeny_unpack(x,&s,&e,&m);

  c = e==0 ? "subnorm" : e==exp_bitmask ? m ? "nan" : "inf" : "norm";
  ib = e==0 ? "0" : e==exp_bitmask ? "?" : "1";
  bitize(e,numbits_exp,be);
  bitize(m,numbits_mant,me);


  printf("teeny %016lx unpacks to sign=%lu, exp=%016lx %s (%lu, unbiased %ld, %s), mant=%016lx %s.%s\n",
	 x,s,e,be,e,e-bias,c,m,ib,me);
  
}



// if ptr points to a valid double, return that. If it points to a boxed value,
// convert it to a double. Designed for debugging
static double decode_to_double(void *ptr)
{
  double value = *(double *)ptr;
  int sign;
  uint64_t tval;
  
  if (fpvm_gc_unbox_raw(value,&sign,(void**)&tval)) {
    // reset bit 50+ before decoding
    tval &= 0x3ffffffffffffUL;
    double result = teeny_decode(tval);
    int resultsign = result<0;
    if (sign != resultsign) {
      return -result;
    } else {
      return result;
    }
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
  // set bit 50 to make sure it's not a "null pointer"
  tval |= (0x1UL << 50);
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
    // reset bit 50+ before decoding
    tval &= 0x3ffffffffffffUL;
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

void teeny_shell(void)
{
  char buf[80];
  char buf2[80];
  uint64_t di, ti, bi;
  double d,t,b;
  uint64_t s,e,m;
  
  while (1) {
    printf("teeny> ");
    if (!fgets(buf,80,stdin)) {
      break;
    }
    if (sscanf(buf,"d %s",buf2)==1) {
      // from double
      if (sscanf(buf2,"0x%lx",&di)==1) {
	d = *(double*)&di;
      } else if (sscanf(buf2,"%lf",&d)==1) {
	di = *(uint64_t*)&d;
      } else {
	printf("d 0x<num> or d <double>\n");
	continue;
      }
      // convert to teeny, then convert back
      print_double(d);
      ti = teeny_encode(d);
      t = *(double*)&ti;
      print_teeny(ti);
      b = teeny_box(d);
      bi = *(uint64_t*)&b;
      printf("boxed teeny encoding: %016lx %lf\n", b, bi);
      d = teeny_unbox(b);
      di = *(uint64_t*)&d;
      print_double(d);
      continue;
    } else if (sscanf(buf,"t 0x%lx",&ti)==1) {
      // from teeny (in hex only)
      print_teeny(ti);
      d = teeny_decode(ti);
      di = *(uint64_t*)&d;
      print_double(d);
      continue;
    } else if (sscanf(buf,"b %lx",&ti)==1) {
      // from boxed teeny
      t = *(double*)&ti;
      printf("boxed teeny %016lx %lf\n",ti,t);
      d = teeny_unbox(t);
      di = *(uint64_t*)&d;
      print_double(d);
      continue;
    } else if (buf[0]=='q') {
      break;
    } else {
      printf("d 0x<num> | <double> = double to teeny to boxed teeny to unboxed double\n");
      printf("t 0x<num>            = teeny to double\n");
      printf("b 0x<num>            = boxed teeny to double\n");
      printf("q\n");
      continue;
    }
  }
}


void fpvm_number_init(UNUSED void *ptr)
{
  if (getenv("FPVM_TEENY_EXP_BITS")) {
    numbits_exp=atoi(getenv("FPVM_TEENY_EXP_BITS"));
  }
  if (getenv("FPVM_TEENY_MANT_BITS")) {
    numbits_mant=atoi(getenv("FPVM_TEENY_MANT_BITS"));
  }
  
  numbits_all = 1 + numbits_exp + numbits_mant;
  
  if (numbits_exp>11) {
    MATH_ERROR("too many exponent bits (%d) required, maximum is %d\n",numbits_exp,11);
    exit(-1);
  }
  
    
  if (numbits_all>50) {
    MATH_ERROR("too many bits (%d) required, but only %d available\n",numbits_all,50);
    exit(-1);
  }

  bias = ((1<<(numbits_exp-1))-1);

  exp_bitmask = bitmask(numbits_exp);
  mant_bitmask = bitmask(numbits_mant);
 
  MATH_DEBUG("initialized with %d exponent bits (bias %d) [bitmask %016lx] and %d mantissa bits [bitmask %016lx]\n",numbits_exp,bias,exp_bitmask,numbits_mant,mant_bitmask);

  teeny_shell();

  exit(0);
}

void fpvm_number_deinit(UNUSED void *ptr)
{
  MATH_DEBUG("deinited%s\n","");
}


#endif
