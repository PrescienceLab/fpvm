// an implementation of MPFR as an alternative math library

#include <fpvm/config.h>

#if CONFIG_ALT_MATH_MPFR



#include <fpvm/number_system.h>
#include <fpvm/number_system/nan_boxing.h>
#include <fpvm/fpvm_fenv.h>
#include <fpvm/fpvm_math.h>
#include <fpvm/fpvm_common.h>
#include <stdio.h>
#include <fpvm/gc.h>
#include <assert.h>
#include <unistd.h>
#include <math.h>

#include <mpfr.h>

#define RFLAGS_CF 0x1UL
#define RFLAGS_PF 0x4UL
#define RFLAGS_AF 0x10UL
#define RFLAGS_ZF 0x40UL
#define RFLAGS_SF 0x80UL
#define RFLAGS_OF 0x800UL

#define RESET "\e[0m"

// #define MPFR_DO_DEBUG
// RNDN: -1.416797517585610      -0.665436589132111
// RNDD: -1.416797517585610      -0.665436589132111
#define ROUNDING_MODE MPFR_RNDN

#ifdef MPFR_DO_DEBUG
#define MPFR_ERROR(...) mpfr_fprintf(stderr, "\e[0;31m[MPFR]\e[0m " __VA_ARGS__)
#define MPFR_DEBUG(...) mpfr_fprintf(stderr, "\e[0;32m[MPFR]\e[0m " __VA_ARGS__)
#else
#define MPFR_ERROR(...)
#define MPFR_DEBUG(...)
#endif



static int mpfr_bits(void) {
    static int bits = 0;
    if (bits != 0) {
        return bits;
    }

    const char *env = getenv("FPVM_MPFR_BITS");
    bits = (env != NULL) ? atoi(env) : CONFIG_MPFR_PRECISION;
    return bits;
}



void fpvm_number_init(void *ptr) {
	(void)ptr;
}


void fpvm_number_deinit(void *ptr) {
    mpfr_t *m = (mpfr_t*)ptr;
    mpfr_clear(*m);
	(void)ptr;
}





mpfr_t *allocate_mpfr(double initial_value = 0.0) {
    mpfr_t *val = (mpfr_t*)fpvm_gc_alloc(sizeof(*val));
    mpfr_init2(*val, mpfr_bits());
    mpfr_set_d(*val, initial_value, ROUNDING_MODE);
    return val;
}


// if ptr points to a valid double, return that. If it points to a boxed value, 
// convert it to a double. Designed for debugging
static double decode_to_double(void *ptr) {
    double value = *(double*)ptr;
    mpfr_t *mpfr_value = (mpfr_t*)fpvm_gc_unbox(value);
    uint64_t sign_bit = (!!((*(uint64_t*)ptr) >> 63));
    if (mpfr_value != NULL) {
        value = mpfr_get_d(*mpfr_value, ROUNDING_MODE);
        // invert if the sign is different.
        if (sign_bit != mpfr_signbit(*mpfr_value)) {
            value *= -1;
        }
        mpfr_fprintf(stdout, "Decode %32.16R to %lf\n", mpfr_value, value);
    }

    return value;
}


// if the value being boxed is negative, state that in the NaN.
static double mpfr_box(mpfr_t *ptr) {
    double value = fpvm_gc_box((void*)ptr);
    if (mpfr_signbit(*ptr)) {
        *(uint64_t*)&value |= (1LLU << 63);
    }
    return value;
}


// Decode an mpfr pointer from a pointer to a double, or construct a new one
static mpfr_t *mpfr_unbox(void *double_ptr) {
    double value = *(double*)double_ptr;
    uint64_t sign_bit = (!!((*(uint64_t*)double_ptr) >> 63));
    auto *mpfr_value = (mpfr_t*)fpvm_gc_unbox(value);

    if (mpfr_value == NULL) {
        // allocate the value
        mpfr_value = allocate_mpfr(value);
    } else if (true) {
        // If the value was boxed, but the sign of the NaN doesn't match the sign
        // of the mpfr_t, we need to copy the mpfr_t as a negated copy, as simply
        // updating the sign would change the sign on all other boxes that share
        // a reference to this mpfr_t
        // MPFR_DEBUG("sign bits: %lx %lx\n", sign_bit, mpfr_signbit(*mpfr_value));
        if (sign_bit != mpfr_signbit(*mpfr_value)) {
            auto *new_value = allocate_mpfr();
            mpfr_neg(*new_value, *mpfr_value, ROUNDING_MODE);
            mpfr_value = new_value;
            MPFR_ERROR("invert number!\n");
        }
    }

    assert(mpfr_value != nullptr);

   
    return mpfr_value;
}





static void fpvm_mpfr_debug_binary_op(const char *name, mpfr_t *src1, mpfr_t *src2) {
    // decode_to_double(src1);
    // decode_to_double(src2);

    MPFR_DEBUG("%s \t%.32RNf\t%.32RNf\n", name, src1, src2);
}



#define MPFR_BINARY_OP(NAME, TYPE)                                      \
    FPVM_MATH_DECL(NAME, TYPE) {                                        \
        mpfr_t *mpfr_dst = allocate_mpfr();                             \
        mpfr_t *mpfr_src1 = mpfr_unbox(src1);                           \
        mpfr_t *mpfr_src2 = mpfr_unbox(src2);                           \
        fpvm_mpfr_debug_binary_op(#NAME, mpfr_src1, mpfr_src2);         \
        mpfr_##NAME(*mpfr_dst, *mpfr_src1, *mpfr_src2, ROUNDING_MODE);      \
        *(double*)dest = mpfr_box(mpfr_dst);                            \
        return 0;                                                       \
    }







MPFR_BINARY_OP(add, double);
MPFR_BINARY_OP(sub, double);
MPFR_BINARY_OP(mul, double);
MPFR_BINARY_OP(div, double);
MPFR_BINARY_OP(max, double);
MPFR_BINARY_OP(min, double);



// fused multiply and add
FPVM_MATH_DECL(madd, double) {
    auto a = mpfr_unbox(src1);
    auto b = mpfr_unbox(src2);
    auto c = mpfr_unbox(src3);

    mpfr_t *dst = allocate_mpfr();
    // +a * b + c
    // dst <- a * b
    mpfr_mul(*dst, *a, *b, ROUNDING_MODE);
    // dst <- dst + c
    mpfr_add(*dst, *dst, *c, ROUNDING_MODE);
    *(double*)dest = mpfr_box(dst);
    return 0;
}

// fused negate multiply and add
FPVM_MATH_DECL(nmadd, double) {
    auto a = mpfr_unbox(src1);
    auto b = mpfr_unbox(src2);
    auto c = mpfr_unbox(src3);

    mpfr_t *dst = allocate_mpfr();
    // -a * b + c
    // invert a
    // dst <- -a
    mpfr_neg(*dst, *a, ROUNDING_MODE);
    // do the math.
    // dst <- dst * b
    mpfr_mul(*dst, *dst, *b, ROUNDING_MODE);
    // dst <- dst + c
    mpfr_add(*dst, *dst, *c, ROUNDING_MODE);

    *(double*)dest = mpfr_box(dst);
    return 0;
}




// fused multiply and sub
FPVM_MATH_DECL(msub, double) {
    auto a = mpfr_unbox(src1);
    auto b = mpfr_unbox(src2);
    auto c = mpfr_unbox(src3);

    mpfr_t *dst = allocate_mpfr();
    // +a * b - c
    // dst <- a * b
    mpfr_mul(*dst, *a, *b, ROUNDING_MODE);
    // dst <- dst - c
    mpfr_sub(*dst, *dst, *c, ROUNDING_MODE);
    *(double*)dest = mpfr_box(dst);
    return 0;
}

// fused negate multiply and sub
FPVM_MATH_DECL(nmsub, double) {
    auto a = mpfr_unbox(src1);
    auto b = mpfr_unbox(src2);
    auto c = mpfr_unbox(src3);

    mpfr_t *dst = allocate_mpfr();
    // -a * b - c
    // invert a
    // dst <- -a
    mpfr_neg(*dst, *a, ROUNDING_MODE);
    // do the math.
    // dst <- dst * b
    mpfr_mul(*dst, *dst, *b, ROUNDING_MODE);
    // dst <- dst - c
    mpfr_sub(*dst, *dst, *c, ROUNDING_MODE);

    *(double*)dest = mpfr_box(dst);
    return 0;
}


FPVM_MATH_DECL(f2i, double) {
    double value = decode_to_double(src1);
    switch (special->byte_width) {
        case 1: *(int8_t*)dest = value; break;
        case 2: *(int16_t*)dest = value; break;
        case 4: *(int32_t*)dest = value; break;
        case 8: *(int64_t*)dest = value; break;
        default:
        ERROR("Cannot handle double->signed(%d)\n",special->byte_width);
        return -1;
        break;
    }
    return 0;
}

FPVM_MATH_DECL(f2u, double) {
    double value = decode_to_double(src1);
    switch (special->byte_width) {
        case 1: *(uint8_t*)dest = value; break;
        case 2: *(uint16_t*)dest = value; break;
        case 4: *(uint32_t*)dest = value; break;
        case 8: *(uint64_t*)dest = value; break;
        default:
        ERROR("Cannot handle double->signed(%d)\n",special->byte_width);
        return -1;
        break;
    }
    return 0;
}

int f2f_double(op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) {
    double value = decode_to_double(src1);
    switch (special->byte_width) {
        case 4: *(float*)dest = value; break;
        case 8: *(double*)dest = value; break;
        default:
            ERROR("Cannot handle double->float(%d)\n",special->byte_width);
            return -1;
            break;
    }
    return 0;
}



FPVM_MATH_DECL(i2f, double) {
    MPFR_ERROR("unhandled operation i2f\n");
    return 0;
}
FPVM_MATH_DECL(u2f, double) {
    MPFR_ERROR("unhandled operation i2f\n");
    return 0;
}


int sqrt_double(op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) {
    mpfr_t *mpfr_src1 = mpfr_unbox(src1);
    mpfr_t *dst = allocate_mpfr();
    mpfr_sqrt(*dst, *mpfr_src1, ROUNDING_MODE);
    *(double*)dest = mpfr_box(dst);
    return 0;
}


int cmp_double(op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) {

    // double a = decode_to_double(src1);
    // double b = decode_to_double(src2);
    mpfr_t *a = mpfr_unbox(src1);
    mpfr_t *b = mpfr_unbox(src2);

    fpvm_mpfr_debug_binary_op("cmp", a, b);

    // compare_result < 0 - src1 < src2
    // compare_result > 0 - src1 > src2
    // compare_result = 0 - src1 = src2
    int compare_result = mpfr_cmp(*a, *b);
    uint64_t *rflags = special->rflags;
    *rflags &= ~(RFLAGS_OF | RFLAGS_AF | RFLAGS_SF | RFLAGS_ZF | RFLAGS_PF | RFLAGS_CF);

    if (mpfr_nan_p(*a) || mpfr_nan_p(*b)) {
        *rflags |= (RFLAGS_ZF | RFLAGS_PF | RFLAGS_CF);
    } else {
        if (compare_result < 0) {
            *rflags |= (RFLAGS_CF);
        } else if ( compare_result == 0 ) {
            *rflags |= (RFLAGS_ZF);
        } else if (compare_result > 0) { // a>b
            // set nothing
        }
    }
    return 0;
}

// void demoted_count(void* a, void* b, int* counter){
//   if (*(uint64_t*) a != *(uint64_t*) b)
//     *counter += 1; 
// }

int restore_double(op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) {
    MPFR_DEBUG("restore_double %016lx  %016lx\n", *(uint64_t*) src1,  *(uint64_t*) src2);
    void * allsrc[4] = {src1, src2, src3, src4};
    // int counter = 0;
    for(int i=0; i < 4; i++) {
        if (allsrc[i] != NULL) {
            *(double*)allsrc[i] = decode_to_double((void*)allsrc[i]);
        }
    }
    return 0;
}

int restore_float(op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) {
    MPFR_ERROR("restore_float %016lx  %016lx\n", *(uint64_t*) src1,  *(uint64_t*) src2);
    //skip float 
    return 0;
} 

int restore_xmm(void *xmm_ptr) {
    // MPFR_DEBUG("restore_xmm %p\n", xmm_ptr);
    double *regs = (double*)xmm_ptr;
    for (int i = 0; i < 2; i++) {
        regs[i] = decode_to_double((void*)&regs[i]);
    }
    return 0;
}

extern "C" {
    
#define ORIG_IF_CAN(func,...) if (orig_##func) { if (!DEBUG_OUTPUT) { orig_##func(__VA_ARGS__); } else { DEBUG("orig_"#func" returns 0x%x\n",orig_##func(__VA_ARGS__)); } } else { DEBUG("cannot call orig_" #func " - skipping\n"); }

    #define MATH_STUB_ONE(NAME, TYPE, RET) \
    RET NAME(TYPE a) \
    {   \
        ORIG_IF_CAN(fedisableexcept,FE_ALL_EXCEPT);\
        auto src1 = mpfr_unbox((void*)&a); \
        mpfr_t *dst = allocate_mpfr();\
        mpfr_##NAME(*dst, *src1, MPFR_RNDD); \
        ORIG_IF_CAN(feenableexcept,FE_ALL_EXCEPT);\
        ORIG_IF_CAN(feclearexcept,FE_ALL_EXCEPT);\
        return mpfr_box(dst);\
    }

    // #define MATH_STUB_ONE_DEMOTE(NAME, TYPE, RET) \
    // RET NAME(TYPE a) \
    // {   \
    //     ORIG_IF_CAN(fedisableexcept,FE_ALL_EXCEPT);\
    //     auto src1 = mpfr_unbox((void*)&a); \
    //     mpfr_t *dst = allocate_mpfr();\
    //     mpfr_##NAME(*dst, *src1); \
    //     RET res = decode_to_double((void*)dst); \
    //     ORIG_IF_CAN(feenableexcept,FE_ALL_EXCEPT);\
    //     ORIG_IF_CAN(feclearexcept,FE_ALL_EXCEPT);\
    //     return res;\
    // }

    #define MATH_STUB_ONE_DEMOTE(NAME, TYPE, RET) \
    RET NAME(TYPE a) \
    {   \
        ORIG_IF_CAN(fedisableexcept,FE_ALL_EXCEPT);\
        double decoded = decode_to_double((void*)&a); \
        double res = orig_##NAME(decoded); \
        ORIG_IF_CAN(feenableexcept,FE_ALL_EXCEPT);\
        ORIG_IF_CAN(feclearexcept,FE_ALL_EXCEPT);\
        return res;\
    }

    // this segfault for ceil/floor/round
    // #define MATH_STUB_ONE_DEMOTE(NAME, TYPE, RET) \
    // RET NAME(TYPE a) \
    // {   \
    //     ORIG_IF_CAN(fedisableexcept,FE_ALL_EXCEPT);\       
    //     auto src1 = mpfr_unbox((void*)&a); \
    //     mpfr_t *dst = allocate_mpfr();\
    //     mpfr_##NAME(*dst, *src1); \
    //     RET res = decode_to_double((void*)dst); \
    //     ORIG_IF_CAN(feenableexcept,FE_ALL_EXCEPT);\
    //     ORIG_IF_CAN(feclearexcept,FE_ALL_EXCEPT);\
    //     return res;\
    // }


    #define MATH_STUB_TWO(NAME, TYPE, RET) \
    RET NAME(TYPE a, TYPE b) \
    {   \
        ORIG_IF_CAN(fedisableexcept,FE_ALL_EXCEPT);\
        auto src1 = mpfr_unbox((void*)&a); \
        auto src2 = mpfr_unbox((void*)&b); \
        mpfr_t *dst = allocate_mpfr();\
        mpfr_##NAME(*dst, *src1, *src2, MPFR_RNDD); \
        ORIG_IF_CAN(feenableexcept,FE_ALL_EXCEPT);\
        ORIG_IF_CAN(feclearexcept,FE_ALL_EXCEPT);\
        return mpfr_box(dst);\
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

    double ldexp(double a, int b){
        ORIG_IF_CAN(fedisableexcept,FE_ALL_EXCEPT);
        auto src1 = mpfr_unbox((void*)&a);
        double two = 2.0;
        double b_alt = (double) b;
        auto tmp1 = mpfr_unbox((void*)&two);
        auto tmp2 = mpfr_unbox((void*)&b_alt);
        mpfr_t *src2 = allocate_mpfr();
        mpfr_pow(*src2, *tmp1, *tmp2, MPFR_RNDD);
        mpfr_t *dst = allocate_mpfr();
        mpfr_mul(*dst, *src1, *src2, MPFR_RNDD);
        ORIG_IF_CAN(feenableexcept,FE_ALL_EXCEPT);
        ORIG_IF_CAN(feclearexcept,FE_ALL_EXCEPT);
        return mpfr_box(dst);
    }

    long int lround(double a){
        ORIG_IF_CAN(fedisableexcept,FE_ALL_EXCEPT);
        auto src = mpfr_unbox((void*)&a);
        mpfr_t *dst = allocate_mpfr();
        mpfr_round(*dst, *src);
        long int res = (long int) decode_to_double((void*)dst);
        ORIG_IF_CAN(feenableexcept,FE_ALL_EXCEPT);
        ORIG_IF_CAN(feclearexcept,FE_ALL_EXCEPT);
        return res;
    }
    
    double __powidf2(double a, int b){
        ORIG_IF_CAN(fedisableexcept,FE_ALL_EXCEPT);
        double src1 = decode_to_double((void*)&a);
        double res = orig___powidf2(src1, b);
        ORIG_IF_CAN(feenableexcept,FE_ALL_EXCEPT);
        ORIG_IF_CAN(feclearexcept,FE_ALL_EXCEPT);
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
    void sincos(double a, double *sin_dst, double *cos_dst){
        *sin_dst = sin(a);
        *cos_dst = cos(a);
    }
}


// ignored float implementations
FPVM_MATH_DECL(add, float) { fprintf(stderr, "mpfr should not be invoked with floats"); return 0;}
FPVM_MATH_DECL(sub, float) { fprintf(stderr, "mpfr should not be invoked with floats"); return 0;}
FPVM_MATH_DECL(nmsub, float) { fprintf(stderr, "mpfr should not be invoked with floats"); return 0;}
FPVM_MATH_DECL(msub, float) { fprintf(stderr, "mpfr should not be invoked with floats"); return 0;}
FPVM_MATH_DECL(mul, float) { fprintf(stderr, "mpfr should not be invoked with floats"); return 0;}
FPVM_MATH_DECL(div, float) { fprintf(stderr, "mpfr should not be invoked with floats"); return 0;}
FPVM_MATH_DECL(max, float) { fprintf(stderr, "mpfr should not be invoked with floats"); return 0;}
FPVM_MATH_DECL(min, float) { fprintf(stderr, "mpfr should not be invoked with floats"); return 0;}
FPVM_MATH_DECL(sqrt, float) { fprintf(stderr, "mpfr should not be invoked with floats"); return 0;}
FPVM_MATH_DECL(madd, float) { fprintf(stderr, "mpfr should not be invoked with floats"); return 0;}
FPVM_MATH_DECL(nmadd, float) { fprintf(stderr, "mpfr should not be invoked with floats"); return 0;}
FPVM_MATH_DECL(f2i, float) { fprintf(stderr, "mpfr should not be invoked with floats"); return 0;}
FPVM_MATH_DECL(f2u, float) { fprintf(stderr, "mpfr should not be invoked with floats"); return 0;}
FPVM_MATH_DECL(i2f, float) { fprintf(stderr, "mpfr should not be invoked with floats"); return 0;}
FPVM_MATH_DECL(u2f, float) { fprintf(stderr, "mpfr should not be invoked with floats"); return 0;}
FPVM_MATH_DECL(f2f, float) { fprintf(stderr, "mpfr should not be invoked with floats"); return 0;}
FPVM_MATH_DECL(cmp, float) { fprintf(stderr, "mpfr should not be invoked with floats"); return 0;}


#endif
