#include <stdint.h>


// Intel: high order bit of mantissa is the qnan/snan bit
// Intel: qnan/snan bit = 1 means it is a qnan, 0 means it is an snan

// When we encode a pointer and sign, we do it like this:
// 1 11            48
// s 1111 1111 111 0ppppppppppppppppppppppppppp
//    where
//       p is the 47 bit pointer (that cannot be null)
//       s is the sign of the value pointed to
//       0 in mantissa means this is an signally nan

// When we decode a value to a pointer and sign, we do it like this:
// 1 11            48
// S 1111 1111 111 ?ppppppppppppppppppppppppppp
//    where
//       p is the 47 bit pointer (that cannot be null)
//       S is the interpretted sign of the value being pointed to
//       ? in mantissa means this is either a qnan or an snan

//
// On decode
//  s S  do   
//  0 0  nothing
//  0 1  negate temp   *** temporary only ?   
//  1 0  negate temp
//  1 1  nothing
//


#define PTR_MASK    0x7fffffffffffUL
#define EXP_MASK    (0x7ffUL<<52)
#define SIGN_MASK   (0x1UL<<63)


#define GET_SIGN(u)     (!!(((uint64_t)(u)) & SIGN_MASK))
#define APPLY_SIGN(u,s) ((((uint64_t)(u)) & (~SIGN_MASK)) | (((uint64_t)(s))<<63))
#define FLIP_SIGN(u) (((uint64_t)(u)) ^ SIGN_MASK)

#define COULD_BE_OUR_NAN(u) ((((u) & EXP_MASK) == EXP_MASK) && ((u) & PTR_MASK))



// an encode produces an SNaN wrapped around the pointer that
// has the sign given
//
// p ptr, s=sign
//
#define NANBOX_ENCODE(p,s)    APPLY_SIGN(((((uint64_t)(p)) & PTR_MASK) | EXP_MASK),(s))

// given x which can be an SNaN or QNaN, return the boxed pointer, and the sign
// encoded in x
//
// x = uint, p = ptr, s = int
#define NANBOX_DECODE(x,p,s)  (p) = (void*)(((uint64_t)(x)) & PTR_MASK); (s) = GET_SIGN((uint64_t)(x));


#if 0
#define NANBOX_MASK_CLEAR (~0xfffc000000000000UL)
// #define NANBOX_MASK_CLEAR (~0xffff000000000000UL)
#define NANBOX_MASK (0xfffc000000000000UL)
// #define NANBOX_MASK (0xffff000000000000UL)
#define NANBOX_MASK_SET_FF 0xfff4000000000000UL
#define NANBOX_MASK_SET_7F 0x7ff4000000000000UL

#define CORECASEXOR_MASK_SET 0xfff4000000000000UL
// #define NANBOX_MASK_SET 0x7ff5000000000000UL
#define DOUBLE_ZERO_BITS 50

  ({                                                                                          \
    ((((p >> DOUBLE_ZERO_BITS << DOUBLE_ZERO_BITS) & NANBOX_MASK) == NANBOX_MASK_SET_FF) ||   \
        (((p >> DOUBLE_ZERO_BITS << DOUBLE_ZERO_BITS) & NANBOX_MASK) == NANBOX_MASK_SET_7F)); \
  })

#define SIGN(val) (!!(val >> 63))

// this means a nan that has the top mantissa bits
// set to something other than 01 => 0=>signaling, 1=> force nan
#define CORRUPTED(p, val)                                                        \
  ({                                                                             \
    (ISNAN(p) && (((p >> DOUBLE_ZERO_BITS << DOUBLE_ZERO_BITS) & NANBOX_MASK) != \
                     (SIGN(val) ? NANBOX_MASK_SET_FF : NANBOX_MASK_SET_7F)));    \
  })


#define NANBOX_ENCODE(p, val)						\
  ({                                                                         \
    /*                                                                       \
     * @p (an MPFR value) is not a NaN (i.e. this                            \
     * library did not generate a NaN)                                       \
     */                                                                      \
                                                                             \
                                                                             \
    /*                                                                       \
     * Encode                                                                \
     */                                                                      \
    uint64_t ep = (((((uint64_t)(p)) & (NANBOX_MASK_CLEAR)) |                \
                    (SIGN(val) ? NANBOX_MASK_SET_FF : NANBOX_MASK_SET_7F))); \
                                                                             \
                                                                             \
    /*                                                                       \
     * Increment counter for number of boxings (                             \
     * encode or decode)                                                     \
     */                                                                      \
                                                                             \
                                                                             \
    /*                                                                       \
     * Send back the encoded pointer                                         \
     */                                                                      \
    ep;                                                                      \
  })


#define NANBOX_DECODE(p)                                                                  \
  ({                                                                                      \
    /*                                                                                    \
     * Decode                                                                             \
     */                                                                                   \
    void *dp = ((void *)(((((uint64_t)(p)) & (NANBOX_MASK_CLEAR)))));                     \
                                                                                          \
                                                                                          \
    /*                                                                                    \
     * @p (an MPFR value) is NOT a NaN when it                                            \
     * is decoded (i.e. into 'dp')                                                        \
     */                                                                                   \
    /*ASSERT_MPFR_NOT_NAN(((mpfr_ptr) dp), "NANBOX_DECODE: Decoded a NaN MPFR value!") */ \
                                                                                          \
                                                                                          \
    /*                                                                                    \
     * Increment counter for number of boxings (                                          \
     * encode or decode)                                                                  \
     */                                                                                   \
                                                                                          \
                                                                                          \
    /*                                                                                    \
     * Send back the decoded pointer                                                      \
     */                                                                                   \
    dp;                                                                                   \
  })

#define FPVM_WRITE(f, p) (f) = *((((double *)(&(p)))))
#define FPVM_READ(p, f) (p) = *((((uint64_t *)(&(f)))))
#define FPVM_READ_FROM_PTR(p, fp) (p) = *((((uint64_t *)((fp)))))

#define FPVM_DOUBLE_TO_UINT(p) (*(uint64_t *)&(p))
#define FPVM_FLOAT_TO_UINT(p) (*(uint32_t *)&(p))

#endif
