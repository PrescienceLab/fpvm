/* mov_bridge_test.c : verify MOVQ2DQ and MOVDQ2Q */

#include <emmintrin.h>   /* SSE2 intrinsics      */
#include <mmintrin.h>    /* MMX intrinsics       */
#include <stdio.h>
#include <stdint.h>

int main(void)
{
    /* ----- set up the sources --------------------------------------- */

    /* 1) put a recognisable value in %mm0 */
    const uint64_t mm_val = 0xAABBCCDDEEFF0011ULL;
    __m64 mm0 = _mm_cvtsi64_m64((long long)mm_val); /* movq mm0, imm64 */

    /* 2) put another value in %xmm0 (low‐64 bits only) */
    const uint64_t xmm_lo = 0x1122334455667788ULL;
    __m128i xmm0 = _mm_cvtsi64_si128((long long)xmm_lo); /* movq xmm0, imm64 */

    /* ----- MOVQ2DQ:  mm0 → xmm1  ------------------------------------ */
    __m128i xmm1;
    asm volatile ("movq2dq  %q[mm], %x[xdst]"   /* XMM ← MMX */
                  : [xdst]"=x"(xmm1)            /* %x == SSE register constraint */
                  : [mm]"y"(mm0));              /* %y == MMX register constraint */

    /* ----- MOVDQ2Q:  xmm0 → mm1  ------------------------------------ */
    __m64 mm1;
    asm volatile ("movdq2q  %x[xsrc], %y[mdst]" /* MMX ← XMM */
                  : [mdst]"=y"(mm1)
                  : [xsrc]"x"(xmm0));

    /* ----- print results -------------------------------------------- */
    printf("after MOVQ2DQ : xmm1 = %016llx_%016llx\n",
           (unsigned long long)_mm_extract_epi64(xmm1,1),
           (unsigned long long)_mm_extract_epi64(xmm1,0));

    printf("after MOVDQ2Q :  mm1  = %016llx\n",
           (unsigned long long)_mm_cvtm64_si64(mm1));

    /* retire MMX state or later SSE ops will fault */
    _mm_empty();
    return 0;
}
