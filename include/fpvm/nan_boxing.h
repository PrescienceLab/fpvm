#include <stdint.h>


// Intel: high order bit of mantissa is the qnan/snan bit
// Intel: qnan/snan bit = 1 means it is a qnan, 0 means it is an snan

// When we encode a pointer and sign, we do it like this:
// 1 11            52
// s 1111 1111 111 0ppppppppppppppppppppppppppp
//    where
//       p is the 51 bit pointer (that cannot be null)
//       s is the sign of the value pointed to
//       0 in mantissa means this is an signaling nan

// When we decode a value to a pointer and sign, we do it like this:
// 1 11            52
// S 1111 1111 111 ?ppppppppppppppppppppppppppp
//    where
//       p is the 51 bit pointer (that cannot be null)
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


// PTR Mask is 51 bits
#define PTR_MASK    0x7ffffffffffffUL
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


