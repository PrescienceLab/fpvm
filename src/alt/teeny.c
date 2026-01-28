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
#include <ctype.h>
#include <fpvm/fpvm_common.h>
#include <fpvm/fpvm_fenv.h>
#include <fpvm/fpvm_math.h>
#include <fpvm/number_system.h>
#include <fpvm/nan_boxing.h>
#include <fpvm/gc.h>
#include <fpvm/trapall.h>
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

static int numbits_type = CONFIG_TEENY_TYPE_BITS;

struct teeny_type
{
    int numbits_exp;
    int numbits_mant;
    int too_small_away;

    // Computed types
    int bias;
    uint64_t exp_bitmask;
    uint64_t mant_bitmask;
};

#define TEENY_DOUBLE_TYPE (-1)
static struct teeny_type
default_teeny_type = {
#define TEENY_DEFAULT_TYPE (0)
    .numbits_exp = CONFIG_TEENY_EXP_BITS,
    .numbits_mant = CONFIG_TEENY_MANT_BITS,
    .too_small_away = CONFIG_TEENY_ROUND_TOO_SMALLS_AWAY_FROM_ZERO,

    .bias = ((1<<((CONFIG_TEENY_EXP_BITS)-1))-1),
    .exp_bitmask = ~(-1ULL << CONFIG_TEENY_EXP_BITS),
    .mant_bitmask = ~(-1ULL << CONFIG_TEENY_MANT_BITS),
};

static unsigned long num_teeny_types = 1;
static struct teeny_type *teeny_types = &default_teeny_type;

struct unpacked_teeny {
    uint64_t sign; // 0 -> positive 1 -> negative
    uint64_t exp; // biased exponent (stored in low order bits)
    uint64_t mantissa; // 64-bit mantissa (low order bits may be rounded)
    int type;
};

static uint64_t bitmask(const uint64_t count)
{
  return ~(-1ULL << count);
}

static inline int
validate_teeny_type(
	struct teeny_type *type)
{ 
  int numbits_all = numbits_type + 1 + type->numbits_mant + type->numbits_exp;

  // Compute derived fields
  type->bias = ((1<<(type->numbits_exp-1))-1);
  type->exp_bitmask = bitmask(type->numbits_exp);
  type->mant_bitmask = bitmask(type->numbits_mant); 

  // Validate the fields
  if (type->numbits_exp>11) {
    MATH_ERROR("too many exponent bits (%d) required, maximum is %d\n",type->numbits_exp,11);
    return -1;
  }
   
  if (numbits_all>50) {
    MATH_ERROR("too many bits (%d) required, but only %d available\n",numbits_all,50);
    return -1;
  }

  return 0;
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

static uint64_t teeny_pack(struct unpacked_teeny unpacked)
{
  uint64_t x;

  if(unpacked.type >= num_teeny_types) {
      MATH_ERROR("Trying to pack teeny of undefined type %d! (packing as default type instead)\n",
	      unpacked.type);
      unpacked.type = TEENY_DEFAULT_TYPE;
  }
  struct teeny_type *type = &teeny_types[unpacked.type];

  uint64_t sign = unpacked.sign;
  uint64_t exp = unpacked.exp;
  uint64_t mantissa = unpacked.mantissa;
  uint64_t type_index = unpacked.type;

  sign &= 0x1;
  exp &= type->exp_bitmask;
  mantissa &= type->mant_bitmask;
  type_index &= bitmask(numbits_type);

  if(exp == type->exp_bitmask) {
      //if(mantissa == 0) {
      //    // +-Inf
      //    //fprintf(stderr, "teeny_pack: Creating an infinite value\n");
      //} else {
      //    // NaN
      //    //fprintf(stderr, "teeny_pack: Creating a NaN value\n");
      //}
  }

  //if(exp == 0 && mantissa == 0) {
  //    //fprintf(stderr, "teeny_pack: Creating a zero value\n");
  //}
 
  // Building Up the NaN payload
  x = sign;

  x <<= type->numbits_exp;
  x |= exp;

  x <<= type->numbits_mant;
  x |= mantissa;

  x <<= numbits_type;
  x |= type_index;

  MATH_DEBUG("packing sign=%lu exp=%016lx mantissa=%016lx type=%016lx into %016lx\n",sign,exp,mantissa, type_index, x);

  return x;

}

static void teeny_unpack(const uint64_t x, struct unpacked_teeny *unpacked)
{
  unpacked->type = x & bitmask(numbits_type);

  if(unpacked->type >= num_teeny_types) {
      MATH_ERROR("Trying to unpack teeny of undefined type %d! (unpacking as default type instead? this is almost certainly wrong...)\n",
	      unpacked->type);
      unpacked->type = TEENY_DEFAULT_TYPE;
  }
  struct teeny_type *type = &teeny_types[unpacked->type];

  unpacked->sign = (x>>(type->numbits_exp + type->numbits_mant + numbits_type)) & 0x1;
  unpacked->exp = (x>>(type->numbits_mant + numbits_type)) & type->exp_bitmask;
  unpacked->mantissa = x & type->mant_bitmask;
  
//    MATH_DEBUG("teeny %016lx unpacks to sign=%lu, exp=%016lx (%lu, unbiased %ld, %s), mant=%016lx, type=%d\n",
//  	     x,unpacked->sign,unpacked->exp,unpacked->exp,((int64_t)unpacked->exp)-type->bias,
//  	     unpacked->exp==0 ? "subnorm" : unpacked->exp==type->exp_bitmask ? unpacked->mantissa ? "nan" : "inf" : "norm", unpacked->mantissa,
//	     (int)unpacked->type);
	    
}


static int is_teeny_special_exp(const struct unpacked_teeny unpacked)
{
  return unpacked.exp == teeny_types[unpacked.type].exp_bitmask;
}

static int is_teeny_denorm_exp(const struct unpacked_teeny unpacked)
{
  return unpacked.exp == 0;
}


static int is_teeny_nan(const uint64_t x)
{
  struct unpacked_teeny unpacked;
  teeny_unpack(x,&unpacked); 
  return is_teeny_special_exp(unpacked) && unpacked.mantissa!=0;
}

static int is_teeny_inf(const uint64_t x)
{
  struct unpacked_teeny unpacked;
  teeny_unpack(x,&unpacked); 
  return is_teeny_special_exp(unpacked) && unpacked.mantissa==0; }

#define UNIMPL() do { MATH_ERROR("unimplemented code path%s!!\n",""); exit(-1); } while (0)

//
// Will return teeny number in bits 0..numbits_all-1
// with sign, then exp, then mantissa
//
static uint64_t teeny_encode(const double x, int type_index, fpvm_round_mode_t round_mode)
{
  uint64_t s,e,m; // double sign, exp, mantissa
  uint64_t lz;    // leading zero count for teeny subnormal mantissa
  int64_t  ube;   // unbiased teeny exponent
  int64_t  be;    // rebiased double exponent

  double_unpack(x,&s,&e,&m);

  MATH_DEBUG("encode double %016lx (%lf)\n",*(uint64_t*)&x,x);

  if(type_index >= num_teeny_types) {
      MATH_ERROR("Trying to encode teeny of undefined type: %d! (encoding as default type instead)\n",
	      type_index);
      type_index = TEENY_DEFAULT_TYPE;
  }
  struct teeny_type *type = &teeny_types[type_index];

  uint64_t mantissa = m << (64-52); // 64 bit mantissa (leading one is implied 1.XXXXXX)
  ube = e - 1023; // 64-bit unbiased exponent

  if(is_double_special_exp(e)) {
      struct unpacked_teeny unpacked;
      unpacked.type = type_index;
      unpacked.sign = s;
      unpacked.exp = type->exp_bitmask;
      if(m) {
	  // NaN
	  unpacked.mantissa = mantissa ? mantissa : 1;
      } else {
	  // Inf
	  unpacked.mantissa = 0;
      }
      return teeny_pack(unpacked);
  }

  // Handle subnormal numbers
  if(e == 0) {
      if(mantissa != 0) {
	  ube += 1; // the "true" exponent is one greater for subnormals

	  // Shift so that the leading 1 is not implied
	  int leading_zeros = __builtin_clzl(mantissa);
	  mantissa <<= (leading_zeros+1);
	  ube -= (leading_zeros+1);
      } else {
	  // This is actually a zero
	  const struct unpacked_teeny zero = {
	      .type = type_index,
	      .sign = s,
	      .exp = 0,
	      .mantissa = 0,
	  };
	  return teeny_pack(zero);
      }
  }

  be = ube + type->bias;

  if(be >= 1) {
      if(be < ((1UL<<type->numbits_exp)-1)) {
	  // This can be represented as a normal teeny
	  
	  // Get the bit which will be rounded off
	  int lost_bit = mantissa >> ((64-(type->numbits_mant+1)) & 1);

	  // Shift the mantissa into place
	  mantissa >>= (64-type->numbits_mant);

	  // Rounding behavior (suspect) -KJH
	  if(lost_bit) {
	      if(mantissa == type->mant_bitmask) {
		  mantissa = 0;
		  be++;
		  if(be == type->exp_bitmask) {
		      // Rounded up to infinity
		      MATH_DEBUG("Rounding during teeny_encode caused the generation of an infinite value!\n");
		  }
	      } else {
	        mantissa += 1;
	      }
	  }
	  struct unpacked_teeny unpacked = {
	      .type = type_index,
	      .sign = s,
	      .exp = be,
	      .mantissa = mantissa,
	  };
	  return teeny_pack(unpacked);
      }
      else {
	  // Overflow to infinity
	  struct unpacked_teeny inf = {
	      .type = type_index,
	      .sign = s,
	      .exp = type->exp_bitmask,
	      .mantissa = 0,
	  };
          return teeny_pack(inf);
      }
  } else {
      // Too small to be normal
      // Denormalize it (Make the leading one explicit)
      // 1.XXXXXX -> 0.1XXXXXX
      mantissa >>= 1;
      mantissa |= (1UL<<63);
      // We don't need to add 1 to the exponent, because the "special case"
      // that subnormals have the same exponent as (exp=1) already does that for us implicitly.

      // Shift the extra exponent bits away (this will implicitly round to zero on underflow
      mantissa >>= -be;

      be = 0; // Mark it as subnormal

      mantissa >>= (64-type->numbits_mant);

      if(type->too_small_away && mantissa == 0) {
	  mantissa = 1;
      }

      struct unpacked_teeny subnormal = {
	  .type = type_index,
	  .sign = s,
	  .exp = be,
	  .mantissa = mantissa,
      };
      return teeny_pack(subnormal);
  }
}

// convert teeny into double (will always fit given the constraints,
// namely that numbits_exp<=11 and numbits_exp<=46-numbits_exp-1
static double teeny_decode(const struct unpacked_teeny unpacked)
{
  uint64_t s,e,m; // teeny sign, exp, mantissa
  uint64_t r=0;   // output result bitpattern
  int64_t  lz;    // leading zero count for teeny subnormal mantissa
  int64_t  ube;   // unbiased teeny exponent
  int64_t  be;    // rebiased double exponent

  struct teeny_type *type = &teeny_types[unpacked.type];
  s = unpacked.sign;
  e = unpacked.exp;
  m = unpacked.mantissa;

  ube = e - type->bias;

  if(is_teeny_special_exp(unpacked)) {
      if(m) {
	  // This is a NaN
	  return double_pack(s,(1UL<<11)-1,m);
      } else {
	  // This is an Inf
	  return double_pack(s,(1UL<<11)-1,0);
      }
  }

  int64_t mantissa = m << (64-type->numbits_mant); // 1.XXXXXX (still need to account for sub-normals)
  if(e == 0) {
      if(m == 0) {
	  // This is exactly zero
	  return double_pack(s,0,0);
      } else {
	  // This is a subnormal number
	  ube += 1; // "true" exponent of a subnormal (exp=0) same as (exp=1)

	  // Normalize it so there is an implied one
	  lz = __builtin_clzl(mantissa);
	  mantissa <<= (lz+1);
	  ube -= (lz+1);
      }
  }

  be = ube + 1023;

  if(be >= (int64_t)((1UL<<11)-1)) {
      // Somehow we overflowed?
      // (This shouldn't be possible when converting from teeny to a double
      MATH_ERROR("teeny overflow to infinity when converting teeny to double!? be=%ld, ube=%ld\n", be, ube);
      // Return infinity but this is deeeeeply suspicious
      return double_pack(s,(1UL<<11)-1,0);
  }

  if(be >= 1) {
      // This can be encoded as a "normal" double
      return double_pack(s,be,mantissa>>(64-52));
  }
  else {
      // This must be encoded as a sub-normal double
      // Make the leading one explicit
      mantissa >>= 1;
      mantissa |= (1UL<<63);
      // We don't need to add 1 to the exponent, because the "special case"
      // that subnormals have the same exponent as (exp=1) already does that for us implicitly.

      // Shift the extra exponent bits away (this will implicitly round to zero on underflow
      mantissa >>= -be;

      // Create the sub-normal double
      return double_pack(s,0,mantissa>>(64-52));
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
  
  struct unpacked_teeny unpacked;
  teeny_unpack(x,&unpacked);
  struct teeny_type *type = &teeny_types[unpacked.type];
  s = unpacked.sign;
  e = unpacked.exp;
  m = unpacked.mantissa;

  c = e==0 ? "subnorm" : e==type->exp_bitmask ? m ? "nan" : "inf" : "norm";
  ib = e==0 ? "0" : e==type->exp_bitmask ? "?" : "1";
  bitize(e,type->numbits_exp,be);
  bitize(m,type->numbits_mant,me);


  printf("teeny %016lx unpacks to sign=%lu, exp=%016lx %s (%lu, unbiased %ld, %s), mant=%016lx %s.%s\n",
	 x,s,e,be,e,e-type->bias,c,m,ib,me);
  
}


// if the value being boxed is negative, state that in the NaN.
static double teeny_box(double val, int type_index, fpvm_round_mode_t round_mode)
{
  if(type_index == TEENY_DOUBLE_TYPE) {
      // This is a double, do not round it
      return val;
  }
  uint64_t tval = teeny_encode(val, type_index, round_mode);
  // set bit 50 to make sure it's not a "null pointer"
  tval |= (0x1UL << 50);
  uint64_t sign = val<0;
  double result = fpvm_gc_box((void *)tval, sign);
  *(uint64_t *)&result |= (sign << 63);
  return result;
}

static double teeny_unbox(double val, int *type) {
  int sign;
  uint64_t tval;

  if (fpvm_gc_unbox_raw(val,&sign,(void**)&tval)) {
    // reset bit 50+ before decoding
    tval &= 0x3ffffffffffffUL;
    struct unpacked_teeny unpacked;
    teeny_unpack(tval, &unpacked);
//    printf("unpacked: sign=0x%lx, exp=0x%lx, mant=0x%lx, type=0x%lx\n",
//	    (unsigned long)unpacked.sign,
//	    (unsigned long)unpacked.exp,
//	    (unsigned long)unpacked.mantissa,
//	    (unsigned long)unpacked.type);
    double result = teeny_decode(unpacked);
    int resultsign = result<0;
    if(type != NULL) {
	*type = unpacked.type;
    }
    if (sign != resultsign) {
      result = -result;
    }
    return result;
  } else {
    if(type != NULL) {
	*type = TEENY_DOUBLE_TYPE;
    }
    return val;
  }
}

// if ptr points to a valid double, return that. If it points to a boxed value,
// convert it to a double. Designed for debugging
static double decode_to_double(void *ptr)
{
  double value = *(double *)ptr;
  value = teeny_unbox(value, NULL);
  return value;
}

static uint64_t decode_to_double_bits(void *ptr)
{
  double v = decode_to_double(ptr);
  return *(uint64_t*)&v;
}

int
teeny_unary_op_type(int type)
{
    return TEENY_DEFAULT_TYPE;
}

int
teeny_binary_op_type(int lhs, int rhs)
{
    return TEENY_DEFAULT_TYPE;
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
    int type_a, type_b; 						\
    double a = teeny_unbox(*(double*)src1, &type_a);			\
    double b = teeny_unbox(*(double*)src2, &type_b);			\
    dst = teeny_##OP(a,b,ROUNDING_MODE);				\
    *(double *)dest = teeny_box(dst, 					\
	                        teeny_binary_op_type(type_a,type_b), 	\
				special->round_mode);			\
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
  int a_type,b_type,c_type;
  double a = teeny_unbox(*(double*)src1, &a_type);
  double b = teeny_unbox(*(double*)src2, &b_type);
  double c = teeny_unbox(*(double*)src3, &c_type);
  double r = (a * b) + c; // TODO ROUNDING_MODE
  int prod_type = teeny_binary_op_type(a_type,b_type);
  int sum_type = teeny_binary_op_type(prod_type,c_type);
  *(double *)dest = teeny_box(r, sum_type, special->round_mode);
  return 0;
}

// fused negate multiply and add
FPVM_MATH_DECL(nmadd, double)
{
  int a_type,b_type,c_type;
  double a = teeny_unbox(*(double*)src1, &a_type);
  double b = teeny_unbox(*(double*)src2, &b_type);
  double c = teeny_unbox(*(double*)src3, &c_type);
  double r = -(a * b) + c; // TODO ROUNDING_MODE
  int prod_type = teeny_binary_op_type(a_type,b_type);
  int diff_type = teeny_binary_op_type(prod_type,c_type); 
  *(double *)dest = teeny_box(r, diff_type, special->round_mode);
  return 0;
}

// fused multiply and sub
FPVM_MATH_DECL(msub, double)
{
  int a_type,b_type,c_type;
  double a = teeny_unbox(*(double*)src1, &a_type);
  double b = teeny_unbox(*(double*)src2, &b_type);
  double c = teeny_unbox(*(double*)src3, &c_type);
  double r = (a * b) - c; // TODO ROUNDING_MODE
  int prod_type = teeny_binary_op_type(a_type,b_type);
  int diff_type = teeny_binary_op_type(prod_type,c_type); 
  *(double *)dest = teeny_box(r, diff_type, special->round_mode);
  return 0;
}

// fused negate multiply and sub
FPVM_MATH_DECL(nmsub, double) {
  int a_type,b_type,c_type;
  double a = teeny_unbox(*(double*)src1, &a_type);
  double b = teeny_unbox(*(double*)src2, &b_type);
  double c = teeny_unbox(*(double*)src3, &c_type);
  double r = -(a * b) - c; // TODO ROUNDING_MODE
  int prod_type = teeny_binary_op_type(a_type,b_type);
  int diff_type = teeny_binary_op_type(prod_type,c_type);
  *(double *)dest = teeny_box(r, diff_type, special->round_mode);
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
  int a_type;
  double a = teeny_unbox(*(double*)src1, &a_type);
  double r = sqrt(a);
  int sqrt_type = teeny_unary_op_type(a_type);
  *(double *)dest = teeny_box(r, sqrt_type, special->round_mode);
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
  *p = teeny_unbox(*p, NULL);
}

void altmath_promote_double_in_place(double *p)
{
  // TODO Can't get rounding mode here?
  *p = teeny_box(*p, TEENY_DEFAULT_TYPE, FPVM_ROUND_DEFAULT);
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

  if (fpvm_gc_unbox_raw(*p,&sign,(void**)&tval)) {
    // this is one of ours
    // reset bit 50+ before decoding
    tval &= 0x3ffffffffffffUL;
    struct unpacked_teeny unpacked;
    teeny_unpack(tval,&unpacked);
    struct teeny_type *type = &teeny_types[unpacked.type];
    s = unpacked.sign;
    e = unpacked.exp;
    m = unpacked.mantissa;
    double result = teeny_decode(unpacked);
    int resultsign = result<0;
    if (sign != resultsign) {
      result = -result;
    }
    c = e==0 ? "subnorm" : e==type->exp_bitmask ? m ? "nan" : "inf" : "norm";
    ib = e==0 ? "0" : e==type->exp_bitmask ? "?" : "1";
    bitize(e,type->numbits_exp,be);
    bitize(m,type->numbits_mant,me);
    snprintf(dest,n,"teeny %016lx unpacks to sign=%lu, exp=%016lx %s (%lu, unbiased %ld, %s), mant=%016lx %s.%s [sign=%d double=%lf]",
	     *(uint64_t*)&x,s,e,be,e,e-type->bias,c,m,ib,me,sign,result);
  } else {
    double_unpack(*p,&s,&e,&m);
    
    c = e==0 ? "subnorm" : e==0x7ff ? m ? "nan" : "inf" : "norm";
    ib = e==0 ? "0" : e==0x7ff ? "?" : "1";
    bitize(e,11,be);
    bitize(m,52,me);
  
    snprintf(dest,n,"double %016lx unpacks to sign=%lu, exp=%016lx %s (%lu, unbiased %ld, %s), mant=%016lx %s.%s [double=%lf]",
	     *(uint64_t *)&x,s,e,be,e,e-1023,c,m,ib,me,x);

  }
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
    TRAPALL_OFF();						\
    ORIG_IF_CAN(fedisableexcept, FE_ALL_EXCEPT);			\
    int type1; \
    double src1 = teeny_unbox(a, &type1);					\
    double res = orig_##NAME(src1);					\
    ORIG_IF_CAN(feenableexcept, FE_ALL_EXCEPT);				\
    ORIG_IF_CAN(feclearexcept, FE_ALL_EXCEPT);				\
    res = teeny_box(res, teeny_unary_op_type(type1), FPVM_ROUND_DEFAULT); /* TODO: Need access to rounding mode */ \
    TRAPALL_ON();							\
    return res;								\
  }

#define MATH_STUB_ONE_DEMOTE(NAME, TYPE, RET)				\
  RET NAME(TYPE a) {							\
    TRAPALL_OFF();						\
    ORIG_IF_CAN(fedisableexcept, FE_ALL_EXCEPT);			\
    double src1 = decode_to_double((void*)&a);				\
    double res = orig_##NAME(src1);					\
    ORIG_IF_CAN(feenableexcept, FE_ALL_EXCEPT);				\
    ORIG_IF_CAN(feclearexcept, FE_ALL_EXCEPT);				\
    TRAPALL_ON();							\
    return res;								\
  }
  
#define MATH_STUB_TWO(NAME, TYPE, RET)					\
  RET NAME(TYPE a, TYPE b) {						\
    TRAPALL_OFF();						\
    ORIG_IF_CAN(fedisableexcept, FE_ALL_EXCEPT);			\
    int type1,type2; \
    double src1 = teeny_unbox(a, &type1);					\
    double src2 = teeny_unbox(b, &type2);					\
    double res = orig_##NAME(src1,src2);					\
    ORIG_IF_CAN(feenableexcept, FE_ALL_EXCEPT);				\
    ORIG_IF_CAN(feclearexcept, FE_ALL_EXCEPT);				\
    res = teeny_box(res, teeny_binary_op_type(type1,type2), FPVM_ROUND_DEFAULT); /* TODO: Need access to rounding mode */ \
    TRAPALL_ON();							\
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
  TRAPALL_OFF();			      
  ORIG_IF_CAN(fedisableexcept, FE_ALL_EXCEPT);
  int type;
  double src = teeny_unbox(a, &type);
  // hideous
  double res = src * orig_pow(2.0,(double)b);
  ORIG_IF_CAN(feenableexcept, FE_ALL_EXCEPT);
  ORIG_IF_CAN(feclearexcept, FE_ALL_EXCEPT);
  // TODO Can't get rounding mode here?
  res =  teeny_box(res, teeny_unary_op_type(type), FPVM_ROUND_DEFAULT);
  TRAPALL_ON();
  return res;
}

long int lround(double a) {
  TRAPALL_OFF();			       
  ORIG_IF_CAN(fedisableexcept, FE_ALL_EXCEPT);
  int type;
  double src = teeny_unbox(a, &type);
  double res = orig_lround(src);
  ORIG_IF_CAN(feenableexcept, FE_ALL_EXCEPT);
  ORIG_IF_CAN(feclearexcept, FE_ALL_EXCEPT);
  // TODO Can't get rounding mode here?
  res = teeny_box(res, teeny_unary_op_type(type), FPVM_ROUND_DEFAULT);
  TRAPALL_ON();
  return res;
}

double __powidf2(double a, int b) {
  TRAPALL_OFF();			       
  ORIG_IF_CAN(fedisableexcept, FE_ALL_EXCEPT);
  int type;
  double src = teeny_unbox(a, &type);
  double res = orig___powidf2(src, b);
  ORIG_IF_CAN(feenableexcept, FE_ALL_EXCEPT);
  ORIG_IF_CAN(feclearexcept, FE_ALL_EXCEPT);
  // TODO Can't get rounding mode here?
  res = teeny_box(res, teeny_unary_op_type(type), FPVM_ROUND_DEFAULT);
  TRAPALL_ON();
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
  TRAPALL_OFF();			       
  ORIG_IF_CAN(fedisableexcept, FE_ALL_EXCEPT);
  int type;
  double src = teeny_unbox(a, &type);
  orig_sincos(src, sin_dst, cos_dst);
  ORIG_IF_CAN(feenableexcept, FE_ALL_EXCEPT);
  ORIG_IF_CAN(feclearexcept, FE_ALL_EXCEPT);
  // TODO IMPORTANT: We don't pack/round the results -KJH
  TRAPALL_ON();
}

// ignored float implementations
FPVM_MATH_DECL(add, float) {
  fprintf(stderr, "teeny should not be invoked with floats\n");
  return 0;
}
FPVM_MATH_DECL(sub, float) {
  fprintf(stderr, "teeny should not be invoked with floats\n");
  return 0;
}
FPVM_MATH_DECL(nmsub, float) {
  fprintf(stderr, "teeny should not be invoked with floats\n");
  return 0;
}
FPVM_MATH_DECL(msub, float) {
  fprintf(stderr, "teeny should not be invoked with floats\n");
  return 0;
}
FPVM_MATH_DECL(mul, float) {
  fprintf(stderr, "teeny should not be invoked with floats\n");
  return 0;
}
FPVM_MATH_DECL(div, float) {
  fprintf(stderr, "teeny should not be invoked with floats\n");
  return 0;
}
FPVM_MATH_DECL(max, float) {
  fprintf(stderr, "teeny should not be invoked with floats\n");
  return 0;
}
FPVM_MATH_DECL(min, float) {
  fprintf(stderr, "teeny should not be invoked with floats\n");
  return 0;
}
FPVM_MATH_DECL(sqrt, float) {
  fprintf(stderr, "teeny should not be invoked with floats\n");
  return 0;
}
FPVM_MATH_DECL(madd, float) {
  fprintf(stderr, "teeny should not be invoked with floats\n");
  return 0;
}
FPVM_MATH_DECL(nmadd, float) {
  fprintf(stderr, "teeny should not be invoked with floats\n");
  return 0;
}
FPVM_MATH_DECL(f2i, float) {
  fprintf(stderr, "teeny should not be invoked with floats\n");
  return 0;
}
FPVM_MATH_DECL(f2u, float) {
  fprintf(stderr, "teeny should not be invoked with floats\n");
  return 0;
}
FPVM_MATH_DECL(i2f, float) {
  fprintf(stderr, "teeny should not be invoked with floats\n");
  return 0;
}
FPVM_MATH_DECL(u2f, float) {
  fprintf(stderr, "teeny should not be invoked with floats\n");
  return 0;
}
FPVM_MATH_DECL(f2f, float) {
  fprintf(stderr, "teeny should not be invoked with floats\n");
  return 0;
}
FPVM_MATH_DECL(cmp, float) {
  fprintf(stderr, "teeny should not be invoked with floats\n");
  return 0;
}

void teeny_shell(void)
{
  char buf[80];
  char buf2[80];
  uint64_t di, ti, bi;
  double d,t,b;
  uint64_t s,e,m;
  
  TRAPALL_OFF();			       
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
      // TODO: Rounding properly
      ti = teeny_encode(d, TEENY_DEFAULT_TYPE, FPVM_ROUND_DEFAULT);
      t = *(double*)&ti;
      print_teeny(ti);
      // TODO: Rounding properly
      b = teeny_box(d, TEENY_DEFAULT_TYPE, FPVM_ROUND_DEFAULT);
      bi = *(uint64_t*)&b;
      printf("boxed teeny encoding: %016lx %lf\n", b, bi);
      d = teeny_unbox(b, NULL);
      di = *(uint64_t*)&d;
      print_double(d);
      continue;
    } else if (sscanf(buf,"t 0x%lx",&ti)==1) {
      // from teeny (in hex only)
      print_teeny(ti);
      struct unpacked_teeny unpacked;
      teeny_unpack(ti, &unpacked);
      d = teeny_decode(unpacked);
      di = *(uint64_t*)&d;
      print_double(d);
      continue;
    } else if (sscanf(buf,"b %lx",&ti)==1) {
      // from boxed teeny
      t = *(double*)&ti;
      printf("boxed teeny %016lx %lf\n",ti,t);
      d = teeny_unbox(t, NULL);
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
  TRAPALL_ON();
}

void fpvm_number_init(UNUSED void *x) {}
void fpvm_number_deinit(UNUSED void *y) {}


void fpvm_number_system_init()
{
  struct teeny_type *default_type = &teeny_types[TEENY_DEFAULT_TYPE];

  if (getenv("FPVM_TEENY_TYPE_BITS")) {
    numbits_type=atoi(getenv("FPVM_TEENY_TYPE_BITS"));
  }
  if (getenv("FPVM_TEENY_EXP_BITS")) {
    default_type->numbits_exp=atoi(getenv("FPVM_TEENY_EXP_BITS"));
  }
  if (getenv("FPVM_TEENY_MANT_BITS")) {
    default_type->numbits_mant=atoi(getenv("FPVM_TEENY_MANT_BITS"));
  }
  if (getenv("FPVM_TEENY_ROUND_TOO_SMALLS_AWAY_FROM_ZERO")) {
    default_type->too_small_away = tolower(getenv("FPVM_TEENY_ROUND_TOO_SMALLS_AWAY_FROM_ZERO")[0]) == 'y';
  }

  num_teeny_types = 1ULL<<numbits_type;
  teeny_types = malloc(sizeof(struct teeny_type) * num_teeny_types);
  if(teeny_types == NULL) {
      MATH_ERROR("Failed to allocate enough space for %lu teeny types!\n",
	      num_teeny_types);
      exit(-1);
  }
  // Set every teeny type to be a copy of the default type
  for(unsigned long i = 0; i < num_teeny_types; i++) {
      teeny_types[i] = default_teeny_type;
  }

  // Try to load more types from a file of the form
  //
  // EXP_BITS_0:MANTISSA_BITS_0
  // EXP_BITS_1:MANTISSA_BITS_1
  // ...
  // EXP_BITS_n:MANTISSA_BITS_n
  //
  {
      const char *path = getenv("FPVM_TEENY_TYPES_PATH");
      if(path != NULL) {
          MATH_INFO("Reading teeny types from \"%s\"\n", path);
          FILE *file = fopen(path, "r");
          // I do not like using fscanf (because I am sane) but I want this to work ASAP and don't
          // really care if a slightly ill-formed input file causes a crash -KJH
	  unsigned long cur_type = 0;
	  while(cur_type < num_teeny_types) {
            unsigned long cur_numbits_exp, cur_numbits_mant;
            int read = fscanf(file, " %lu : %lu", &cur_numbits_exp, &cur_numbits_mant);
	    if (read != 2) {
              fclose(file);
	      break;
	    }
	    struct teeny_type *type = &teeny_types[cur_type];
	    type->numbits_exp = cur_numbits_exp;
	    type->numbits_mant = cur_numbits_mant;
	    MATH_INFO("Initialized teeny type %d with %lu exponent bits and %lu mantissa bits\n",
		    cur_type,
		    type->numbits_exp,
		    type->numbits_mant);
	    cur_type++;
	  }
      }
  }

  for(unsigned long i = 0; i < num_teeny_types; i++) {
      if(validate_teeny_type(&teeny_types[i])) {
          MATH_ERROR("Failed to validate teeny type %lu!\n", i);
          exit(-1);
      }
  }

  MATH_DEBUG("initialized with %d exponent bits (bias %d) [bitmask %016lx] and %d mantissa bits [bitmask %016lx] too_small_away=%s \n",numbits_exp,bias,exp_bitmask,numbits_mant,mant_bitmask, too_small_away ? "y" : "n");

  //  teeny_shell();
  //  exit(0);
}

void fpvm_number_system_deinit()
{
  MATH_DEBUG("deinited%s\n","");
}


#endif
