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
#include <fpvm/nan_boxing.h>

#ifndef CONFIG_FPTRAPALL
#define fptrapall_clear_ts()
#define fptrapall_set_ts()
#else
extern void fptrapall_set_ts(void);
extern void fptrapall_clear_ts(void);
#endif

#if CONFIG_DEBUG_ALT_ARITH
#define MATH_DEBUG(S, ...) DEBUG("boxed: " S, ##__VA_ARGS__)
#define MATH_SAFE_DEBUG(S) SAFE_DEBUG("boxed: " S)
#define MATH_SAFE_DEBUG_QUAD(S,X) SAFE_DEBUG_QUAD("boxed: " S, X)
#else
#define MATH_DEBUG(S, ...)
#define MATH_SAFE_DEBUG(S)
#define MATH_SAFE_DEBUG_QUAD(S,X)
#endif

#if !NO_OUTPUT
#define MATH_INFO(S, ...) INFO("boxed: " S, ##__VA_ARGS__)
#define MATH_ERROR(S, ...) ERROR("boxed: " S, ##__VA_ARGS__)
#else
#define MATH_INFO(S, ...)
#define MATH_ERROR(S, ...)
#endif

//#define EXIT(d) exit(d)  // not exit , what if there is really a nan

//#define NANBOX(ITYPE, dest, nan_encoded) *(ITYPE *)dest = nan_encoded
// #define NANBOX(ITYPE, dest, nan_encoded)
// #define _NANBOX(ITYPE, dest, nan_encoded)

#define ALLOC(n)   fpvm_gc_alloc(n)
#define BOX(p,t)   fpvm_gc_box_to_ptr(p,t,GET_SIGN(*(uint64_t*)(p))) ; MATH_DEBUG("%p now contains %016lx\n",t,*(uint64_t*)t);
#define TRACKED(p) fpvm_gc_is_tracked_nan_from_ptr(p)
#define UNBOX(p,s) fpvm_gc_unbox_from_ptr(p,&s)
#define UNBOX_TRACKED(p,t)			\
  {						\
  int _sign=-1;					\
  void *_np;					\
  (_np) = UNBOX(p,_sign);			\
  if (_np) {								\
    MATH_DEBUG("%p maps to %p sign %d\n",p,_np,_sign);			\
    if (_sign != GET_SIGN(*(uint64_t*)_np)) {				\
      MATH_DEBUG("flipping sign\n");					\
      *(uint64_t*)&t = *(uint64_t*)_np;		\
      *(uint64_t*)&t=FLIP_SIGN(*(uint64_t*)&t);	\
      (p) = &t;					\
    } else {					\
      (p) = _np;				\
    }						\
  } else { (p)=(p);  MATH_DEBUG("no mapping\n");}			\
  MATH_DEBUG("unboxed to %p %s sign %d (%lf)\n",(p),(p)==&t?"temp":"orig",_sign,*(double*)(p)); \
  }

#define UNBOX_VAL_IN_PLACE(v)			\
  {						\
  uint64_t *_up = (uint64_t*)&v;		\
  int _sign;					\
  void *_np;					\
  _np = UNBOX(_up,_sign);			\
  if (_np) {								\
    MATH_DEBUG("value %016lx maps to %p sign %d\n",*_up,_np,_sign);	\
    *_up=*(uint64_t*)_np;						\
    if (_sign != GET_SIGN(*_up)) {					\
      MATH_DEBUG("flipping value sign\n");				\
      *_up = FLIP_SIGN(*_up);					  \
    }								  \
  }								  \
  MATH_DEBUG("unboxed to value %016lx (%lf)\n",*_up, v);	  \
  }

    

/*
#define IEEE_REVERT_SIGN(ITYPE, TYPE, ptr_val, dest)                                              \
  {                                                                                               \
    MATH_DEBUG("REVERT_SIGN %016lx (potential corruption)\n", *(uint64_t *)dest);                                  \
    volatile TYPE *_per_result = (TYPE *)ALLOC(sizeof(TYPE));                           \
    memset(_per_result, 0, sizeof(TYPE));                                                         \
    *_per_result = -*(TYPE *)ptr_val;                                                             \
    volatile ITYPE _nan_encoded = NANBOX_ENCODE((uint64_t)_per_result, *(uint64_t *)_per_result); \
    MATH_DEBUG("Nanbox result addr %p value %lf  \n", _per_result, *_per_result);                      \
    NANBOX(ITYPE, dest, _nan_encoded);                                                            \
    ptr_val = _per_result;                                                                        \
  }
*/

#define BIN_OP(TYPE, ITYPE, NAME, OP, SPEC, ISPEC)			\
  int NAME##_##TYPE(							\
		    op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) { \
    double t1, t2;							\
    MATH_DEBUG("src1 tracked: %s\n", TRACKED(src1) ? "True" : "False");	\
    MATH_DEBUG("src2 tracked: %s\n", TRACKED(src2) ? "True" : "False");	\
    UNBOX_TRACKED(src1,t1);						\
    UNBOX_TRACKED(src2,t2);						\
    TYPE *result = (TYPE *)ALLOC(sizeof(TYPE));				\
    *result = (*(TYPE *)src1)OP(*(TYPE *)src2);				\
    MATH_DEBUG(#NAME "_" #TYPE ": " SPEC " " #OP " " SPEC " = " SPEC " [" ISPEC "] (%p)\n", \
	  *(TYPE *)src1, *(TYPE *)src2, *result, *(ITYPE *)result, dest);	\
    BOX(result,dest);							\
    return 0;								\
  }

#define UN_FUNC(TYPE, ITYPE, NAME, FUNC, SPEC, ISPEC)			\
  int NAME##_##TYPE(							\
		    op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) { \
    double t1;								\
    MATH_DEBUG("src1 tracked: %s\n", TRACKED(src1) ? "True" : "False");	\
    UNBOX_TRACKED(src1,t1);						\
    TYPE *result = (TYPE *)ALLOC(sizeof(TYPE));				\
    *result = FUNC((*(TYPE *)src1));					\
    MATH_DEBUG(#NAME "_" #TYPE ": " #FUNC "(" SPEC ") = " SPEC " [" ISPEC "] (%p)\n", \
	  *(TYPE *)src1, *result, *(ITYPE *)result, dest);			\
    BOX(result,dest);							\
    return 0;								\
  }

#define BIN_FUNC(TYPE, ITYPE, NAME, FUNC, SPEC, ISPEC)                                      \
  int NAME##_##TYPE(                                                                        \
      op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) {  \
    double t1, t2;							\
    MATH_DEBUG("src1 tracked: %s\n", TRACKED(src1) ? "True" : "False");	\
    MATH_DEBUG("src2 tracked: %s\n", TRACKED(src2) ? "True" : "False");	\
    UNBOX_TRACKED(src1,t1);						\
    UNBOX_TRACKED(src2,t2);						\
    TYPE *result = (TYPE *)ALLOC(sizeof(TYPE));				\
    *result = FUNC((*(TYPE *)src1), (*(TYPE *)src2));			\
    MATH_DEBUG(#NAME "_" #TYPE ": " #FUNC "(" SPEC ", " SPEC ") = " SPEC " [" ISPEC "] (%p)\n", \
	  *(TYPE *)src1, *(TYPE *)src2, *result, *(ITYPE *)result, dest);	\
    BOX(result,dest);							\
    return 0;								\
  }

#define FUSED_OP(TYPE, ITYPE, NAME, OP1, NEGOP, OP2, SPEC, ISPEC)                                  \
  int NAME##_##TYPE(                                                                               \
      op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) {         \
    double t1, t2, t3;							\
    MATH_DEBUG("src1 tracked: %s\n", TRACKED(src1) ? "True" : "False");	\
    MATH_DEBUG("src2 tracked: %s\n", TRACKED(src2) ? "True" : "False");	\
    MATH_DEBUG("src3 tracked: %s\n", TRACKED(src3) ? "True" : "False");	\
    UNBOX_TRACKED(src1,t1);						\
    UNBOX_TRACKED(src2,t2);						\
    UNBOX_TRACKED(src3,t3);						\
    TYPE *result = (TYPE *)ALLOC(sizeof(TYPE));				\
    *result = (NEGOP((*(TYPE *)src1)OP1(*(TYPE *)src2)))OP2(*(TYPE *)src3); \
    MATH_DEBUG(#NAME "_" #TYPE ": (" #NEGOP "( " SPEC " " #OP1 " " SPEC " ) ) " #OP2 " " SPEC \
	  " = " SPEC " [" ISPEC "] (%p)\n",				\
	  *(TYPE *)src1, *(TYPE *)src2, *(TYPE *)src3, *result, *(ITYPE *)result, dest); \
    BOX(result,dest);							\
    return 0;                                                                                      \
  }

static inline double maxd(double a, double b) {
  MATH_DEBUG("maxd \n");
  if (a > b) {
    return a;
  } else {
    return b;
  }
}
static inline double mind(double a, double b) {
  MATH_DEBUG("mind \n");

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
/*   MATH_DEBUG("sqrt_double: sqrt(%lf) = %lf [%016lx] (%p)\n", *(double*)src1,
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

// should not fire
#define CONVERT_F2I(FTYPE, ITYPE, FSPEC, ISPEC)				\
  { MATH_ERROR("convert_f2i float should not happen\n");			\
    ITYPE result = (ITYPE)(*(FTYPE *)src1);				\
    MATH_DEBUG("f2i[" #FTYPE " to " #ITYPE "](" FSPEC ") = " ISPEC " (%p)\n", (*(FTYPE *)src1), result, \
	  dest);							\
    *(ITYPE *)dest = result;						\
    return 0;								\
  }

// unbox src, int output
#define DOUBLE_CONVERT_F2I(FTYPE, ITYPE, FSPEC, ISPEC)			\
  {									\
    MATH_DEBUG("src1 tracked: %s\n", TRACKED(src1) ? "True" : "False");	\
    double t1;								\
    UNBOX_TRACKED(src1,t1);						\
    ITYPE result = (ITYPE)(*(FTYPE *)src1);                                                        \
    MATH_DEBUG("f2i[" #FTYPE " to " #ITYPE "](" FSPEC ") = " ISPEC " (%p)\n", (*(FTYPE *)src1), result, \
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
      MATH_ERROR("Cannot handle double->signed(%d)\n", special->byte_width);
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
      MATH_ERROR("Cannot handle double->unsigned(%d)\n", special->byte_width);
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
      MATH_ERROR("Cannot handle float->unsigned(%d)\n", special->byte_width);
      return -1;
      break;
  }
}

// produces an unboxed result
#define CONVERT_I2F(FTYPE, ITYPE, FSPEC, ISPEC)				\
  { MATH_ERROR("convert_i2f float should not happen\n");			\
    FTYPE result = (FTYPE)(*(ITYPE *)src1);				\
    MATH_DEBUG("i2f[" #ITYPE " to " #FTYPE "](" #ISPEC ") = " #FSPEC " (%p)\n", (*(ITYPE *)src1), \
	  result, dest);						\
    *(uint64_t *)dest = *(uint64_t *)&result;				\
    return 0;								\
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
      MATH_ERROR("Cannot handle double->signed(%d)\n", special->byte_width);
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
      MATH_ERROR("Cannot handle double->unsigned(%d)\n", special->byte_width);
      return -1;
      break;
  }
  return 0;
}

// unbox input, but do not box result
#define DOUBLE_CONVERT_F2F(FITYPE, FOTYPE, FISPEC, FOSPEC)		\
  {									\
    double t1;								\
    MATH_DEBUG("src1 tracked: %s\n", TRACKED(src1) ? "True" : "False");	\
    UNBOX_TRACKED(src1,t1);						\
    FOTYPE result = (FOTYPE)(*(FITYPE *)src1);                                                  \
    MATH_DEBUG("f2f[" #FITYPE " to " #FOTYPE "](" FISPEC ") = " FOSPEC " (%p)\n", (*(FITYPE *)src1), \
        result, dest);                                                                          \
    *(FOTYPE *)dest = result;                                                                   \
    return 0;                                                                                   \
  }

#define CONVERT_F2F(FITYPE, FOTYPE, FISPEC, FOSPEC)			\
  { MATH_ERROR("convert_f2f float should not happen\n");			\
  FOTYPE result = *(FITYPE*)src1;					\
  MATH_DEBUG("f2f[" #FITYPE " to " #FOTYPE "](" FISPEC ") = " FOSPEC " (%p)\n", (*(FITYPE *)src1), \
	  result, dest);						\
  *(FOTYPE *)dest = result;						\
  return 0;								\
  }

int f2f_double(op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) {
  switch (special->byte_width) {
    case 4:
      DOUBLE_CONVERT_F2F(double, float, "%lf", "%f");
    // case 4: CONVERT_F2F(double,float,"%lf","%f");
    default:
      MATH_ERROR("Cannot handle double->float(%d)\n", special->byte_width);
      return -1;
      break;
  }
}

int f2f_float(op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) {
  switch (special->byte_width) {
    case 8:
      CONVERT_F2F(float, double, "%f", "%lf");
    default:
      MATH_ERROR("Cannot handle float->float(%d)\n", special->byte_width);
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
      MATH_ERROR("Cannot handle float->signed(%d)\n", special->byte_width);
      return -1;
      break;
  }
  return 0;
}

// note that this is the same between ordered and unordered compare
// ordered compare will raise INV if an operand is a nan
// which we do not handle...

int cmp_double(op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) {
  double t1, t2;
  MATH_DEBUG("src1 tracked: %s\n", TRACKED(src1) ? "True" : "False");	
  MATH_DEBUG("src2 tracked: %s\n", TRACKED(src2) ? "True" : "False");	
  UNBOX_TRACKED(src1,t1);							
  UNBOX_TRACKED(src2,t2);							
  double a = *(double *)src1;
  double b = *(double *)src2;
  uint64_t *rflags = special->rflags;
  int which;

  MATH_DEBUG("on entry, rflags=%016lx\n",*rflags);
  
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
  
  MATH_DEBUG("double %s compare %lf %lf => flags %016lx (%s)\n",
	     special->unordered ? "unordered" : "ordered", a, b, *rflags,
	     which == -2   ? "unordered"
	     : which == -1 ? "less"
	     : which == 0  ? "equal"
	     : which == +1 ? "greater"
	     : "BUG BUG BUG");

  (void)which;

  return 0;
}


int cmpxx_double(
    op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) {
  double t1, t2;
  MATH_DEBUG("src1 tracked: %s\n", TRACKED(src1) ? "True" : "False");	
  MATH_DEBUG("src2 tracked: %s\n", TRACKED(src2) ? "True" : "False");	
  UNBOX_TRACKED(src1,t1);							
  UNBOX_TRACKED(src2,t2);							
  double a = *(double *)src1;
  double b = *(double *)src2;
  uint64_t r=0;

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

  *(uint64_t*)dest = r;
  
  return 0;

}

int cmpxx_float(
    op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) {
  ERROR("cmpxx float is not implemented\n");
  return -1;
}

int ltcmp_double(
    op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) {
  ERROR("ltcmp has been superceded by cmpxx and should not be called!\n");
  return -1;
  
  double t1, t2;
  MATH_DEBUG("LTCMP !!!!! WTF deal with it (this is likely crazy code...) \n");
#if 1
  MATH_DEBUG("LTCMP !!!!! Treating like cmp\n");
  return cmp_double(special,dest,src1,src2,src3,src4);
#else 
  MATH_DEBUG("src1 tracked: %s\n", TRACKED(src1) ? "True" : "False");	
  MATH_DEBUG("src2 tracked: %s\n", TRACKED(src2) ? "True" : "False");	
  UNBOX_TRACKED(src1,t1);							
  UNBOX_TRACKED(src2,t2);							
  double a = *(double *)src1;
  double b = *(double *)src2;
  int which;
  (void)which;
  // uint64_t *rflags = special->rflags;
  // *rflags &= ~(RFLAGS_OF | RFLAGS_AF | RFLAGS_SF | RFLAGS_ZF | RFLAGS_PF |
  // RFLAGS_CF);

  if (isnan(a) || isnan(b)) {
    MATH_DEBUG("fault here -1 %p \n", dest);
    // *rflags |= (RFLAGS_ZF | RFLAGS_PF | RFLAGS_CF);
    which = -2;
  } else {
    if (a < b) {
      MATH_DEBUG("fault here 1 %p \n", dest);
      *(uint64_t *)dest = 0xffffffffffffffffUL;
      // *(uint64_t*)dest = 0x0000000000000000UL;
      // *(uint64_t*)dest = 0x1UL<<64;
      which = -1;
    } else {  // a>b
      // set nothing
      MATH_DEBUG("fault here 2 %p \n", dest);
      *(uint64_t *)dest = 0x0000000000000000UL;
      which = 1;
    }
  }
  MATH_DEBUG("double %s compare %lf %lf => flags %lx (%s)\n", special->unordered ?
	"unordered" : "ordered", a,b,*rflags, which==-2 ? "unordered" : which==-1 ?
	"less" :  "equal/greater");

  return 0;
#endif
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
    MATH_ERROR("huh?  %s invoked\n", #FUNC);	\
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

  // if ptr points to a valid double, return that. If it points to a boxed value,
// convert it to a double. Designed for debugging
static double decode_to_double(void *ptr) {
  double t1;
  UNBOX_TRACKED(ptr,t1);
  return *(double*)ptr;
}

  
int restore_double(op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) {
#define n 4
  void *allsrc[n] = {src1, src2, src3, src4};
  for (int i = 0; i < n; i++) {
    if (allsrc[i]) {
      *(double*)allsrc[i] = decode_to_double(allsrc[i]);
    }
  }
  return 0;
}

int restore_float(
    op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) {
  // skip float
  return 0;
}

void NO_TOUCH_FLOAT restore_double_in_place(uint64_t *p) {
  uint64_t *np;
  int s=0;
  np = UNBOX(p,s);
  if (np) {
#if CONFIG_DEBUG_ALT_ARITH
    // the following is a redundant check
    // basically to just let us play with it
    if (fpvm_memaddr_probe_readable_long(np)) {
      *p = *(uint64_t*)np;
      if (s != GET_SIGN(*(uint64_t*)p)) {
	*p = FLIP_SIGN(*p);
      }
    } else {
      MATH_SAFE_DEBUG_QUAD("cannot read through tracked value addr",np);
    }
#else
    // just do the ref
    *p = *(uint64_t*)np;
    if (s != GET_SIGN(*(uint64_t*)p)) {
      *p = FLIP_SIGN(*p);
    }
#endif
  }
}

#define ORIG_IF_CAN(func, ...)                                          \
  if (orig_##func) {                                                    \
    if (!CONFIG_DEBUG_ALT_ARITH) {					\
      orig_##func(__VA_ARGS__);                                         \
    } else {                                                            \
      MATH_DEBUG("orig_" #func " returns 0x%x\n", orig_##func(__VA_ARGS__)); \
    }                                                                   \
  } else {                                                              \
    MATH_DEBUG("cannot call orig_" #func " - skipping\n");		\
  }

/*
#define RECOVER(a, xmm)                                                                      \
  {                                                                                          \
    if (ISNAN(*(uint64_t *)&a)) {                                                            \
      xmm = (void *)NANBOX_DECODE(*(uint64_t *)&a);                                          \
      a = (CORRUPTED(*(uint64_t *)&a, *(uint64_t *)xmm) ? -*(double *)xmm : *(double *)xmm); \
    }                                                                                        \
  }
*/

#define MATH_STUB_ONE(NAME, TYPE, RET, RSPEC)	 \
  RET NAME(TYPE a) {                             \
    fptrapall_clear_ts(); \
    ORIG_IF_CAN(fedisableexcept, FE_ALL_EXCEPT); \
    UNBOX_VAL_IN_PLACE(a);			 \
    RET ori = orig_##NAME(a);                    \
    MATH_DEBUG(#NAME "(%lf) = " RSPEC "\n", a,ori);	 \
    ORIG_IF_CAN(feenableexcept, FE_ALL_EXCEPT);  \
    ORIG_IF_CAN(feclearexcept, FE_ALL_EXCEPT);   \
    fptrapall_set_ts(); \
    return ori;                                  \
  }

#define MATH_STUB_ONE_MIXED(NAME, TYPE, RET)     \
  RET NAME(TYPE a) {                             \
    fptrapall_clear_ts(); \
    ORIG_IF_CAN(fedisableexcept, FE_ALL_EXCEPT); \
    UNBOX_VAL_IN_PLACE(a);				 \
    RET ori = orig_##NAME(a);                    \
    MATH_DEBUG(#NAME "(%lf) = %lf \n", a,ori);	 \
    ORIG_IF_CAN(feenableexcept, FE_ALL_EXCEPT);  \
    ORIG_IF_CAN(feclearexcept, FE_ALL_EXCEPT);   \
    fptrapall_set_ts(); \
    return ori;                                  \
  }

#define MATH_STUB_TWO(NAME, TYPE, RET)                          \
  RET NAME(TYPE a, TYPE b) {                                    \
    fptrapall_clear_ts(); \
    ORIG_IF_CAN(fedisableexcept, FE_ALL_EXCEPT);                \
    UNBOX_VAL_IN_PLACE(a);						\
    UNBOX_VAL_IN_PLACE(b);						\
    RET ori = orig_##NAME(a, b);                                \
    MATH_DEBUG(#NAME "(%lf, %lf) = %lf \n", a, b, ori);		\
    ORIG_IF_CAN(feenableexcept, FE_ALL_EXCEPT);                 \
    ORIG_IF_CAN(feclearexcept, FE_ALL_EXCEPT);                  \
    fptrapall_set_ts(); \
    return ori;                                                 \
  }

#define MATH_STUB_MIXED(NAME, TYPE1, TYPE2, RET)               \
  RET NAME(TYPE1 a, TYPE2 b) {                                 \
    ORIG_IF_CAN(fedisableexcept, FE_ALL_EXCEPT);               \
    fptrapall_clear_ts(); \
    UNBOX_VAL_IN_PLACE(a);				       \
    RET ori = orig_##NAME(a, b);                               \
    MATH_DEBUG(#NAME "(%lf , %d) = %lf \n", a, b, ori);	       \
    ORIG_IF_CAN(feenableexcept, FE_ALL_EXCEPT);                \
    ORIG_IF_CAN(feclearexcept, FE_ALL_EXCEPT);                 \
    fptrapall_set_ts(); \
    return ori;                                                \
  }

void sincos(double a, double *sin, double *cos) { 
  fptrapall_clear_ts();
  ORIG_IF_CAN(fedisableexcept, FE_ALL_EXCEPT);
  UNBOX_VAL_IN_PLACE(a);
  orig_sincos(a, sin, cos);
  MATH_DEBUG("sincos(%lf) = (%lf, %lf)\n", a, *sin, *cos);
  ORIG_IF_CAN(feenableexcept, FE_ALL_EXCEPT);
  ORIG_IF_CAN(feclearexcept, FE_ALL_EXCEPT);
  fptrapall_set_ts();
  return;
}

MATH_STUB_TWO(pow, double, double)
MATH_STUB_ONE(log, double, double, "%lf")
MATH_STUB_ONE(exp, double, double, "%lf")
MATH_STUB_ONE(sin, double, double, "%lf")
MATH_STUB_ONE(cos, double, double, "%lf")
MATH_STUB_ONE(tan, double, double, "%lf")

MATH_STUB_ONE(log10, double, double, "%lf")
MATH_STUB_ONE(ceil, double, double, "%lf")
MATH_STUB_ONE(floor, double, double, "%lf")
MATH_STUB_ONE(round, double, double, "%lf")
MATH_STUB_ONE(lround, double, long int, "%ld")
MATH_STUB_MIXED(ldexp, double, int, double)
MATH_STUB_MIXED(__powidf2, double, int, double)

MATH_STUB_ONE(sinh, double, double, "%lf")
MATH_STUB_ONE(cosh, double, double, "%lf")
MATH_STUB_ONE(tanh, double, double, "%lf")

MATH_STUB_ONE(asin, double, double, "%lf")
MATH_STUB_ONE(acos, double, double, "%lf")
MATH_STUB_ONE(atan, double, double, "%lf")
MATH_STUB_ONE(asinh, double, double, "%lf")
MATH_STUB_ONE(acosh, double, double, "%lf")
MATH_STUB_ONE(atanh, double, double, "%lf")

MATH_STUB_TWO(atan2, double, double)

// constructor
void fpvm_number_init(void *ptr) {
  
}

// destructor
void fpvm_number_deinit(void *ptr) {
}

#endif  // CONFIG_ALT_MATH_IEEE
