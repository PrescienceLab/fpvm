#include <stdint.h>

#define NANBOX_MASK_CLEAR (~0xfffc000000000000UL)
// #define NANBOX_MASK_CLEAR (~0xffff000000000000UL)
#define NANBOX_MASK (0xfffc000000000000UL)
// #define NANBOX_MASK (0xffff000000000000UL)
#define NANBOX_MASK_SET_FF 0xfff4000000000000UL
#define NANBOX_MASK_SET_7F 0x7ff4000000000000UL

#define CORECASEXOR_MASK_SET 0xfff4000000000000UL
// #define NANBOX_MASK_SET 0x7ff5000000000000UL
#define DOUBLE_ZERO_BITS 50

#define ISNAN(p) ({ \
   ( (( (p >> DOUBLE_ZERO_BITS << DOUBLE_ZERO_BITS) & NANBOX_MASK) == NANBOX_MASK_SET_FF) \
   ||\
     (( (p >> DOUBLE_ZERO_BITS << DOUBLE_ZERO_BITS) & NANBOX_MASK) == NANBOX_MASK_SET_7F)\
   ); \
})

#define SIGN(val) (!!(val >> 63))

#define CORRUPTED(p, val) ({ \
    ( ISNAN(p) && (( (p >> DOUBLE_ZERO_BITS << DOUBLE_ZERO_BITS) & NANBOX_MASK) != (SIGN(val) ? NANBOX_MASK_SET_FF:NANBOX_MASK_SET_7F))); \
})

#define NANBOX_ENCODE(p, val) ({ \
    /*
     * @p (an MPFR value) is not a NaN (i.e. this
     * library did not generate a NaN)
     */ \
    \
    \
    /*
     * Encode
     */ \
	uint64_t ep = (((((uint64_t)(p))&(NANBOX_MASK_CLEAR))| \
       ( SIGN(val)? NANBOX_MASK_SET_FF: NANBOX_MASK_SET_7F )\
     )) ; \
    \
    \
    /*
     * Increment counter for number of boxings (
     * encode or decode)
     */ \
    \
    \
    /*
     * Send back the encoded pointer
     */ \
	ep ; \
})


#define NANBOX_DECODE(p) ({ \
    /*
     * Decode 
     */ \
	void* dp = ((void*)(((((uint64_t)(p))&(NANBOX_MASK_CLEAR))))); \
    \
    \
    /*
     * @p (an MPFR value) is NOT a NaN when it
     * is decoded (i.e. into 'dp')
     */ \
/*ASSERT_MPFR_NOT_NAN(((mpfr_ptr) dp), "NANBOX_DECODE: Decoded a NaN MPFR value!") */ \
    \
    \
    /*
     * Increment counter for number of boxings (
     * encode or decode)
     */ \
    \
    \
    /*
     * Send back the decoded pointer
     */ \
	dp ; \
})

#define FPVM_WRITE(f,p) (f)=*((((double *)(&(p)))))
#define FPVM_READ(p,f) (p)=*((((uint64_t *)(&(f)))))

#define FPVM_DOUBLE_TO_UINT(p) (*(uint64_t *)&(p))
#define FPVM_FLOAT_TO_UINT(p) (*(uint32_t *)&(p))
