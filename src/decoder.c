#define _GNU_SOURCE
#include <signal.h>
#include <ucontext.h>

// to allow access to fs base and gs base
#include <asm/prctl.h>  
#include <sys/syscall.h>
#include <unistd.h>

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include <fpvm/decoder.h>
#include <fpvm/fpvm_common.h>
#include <fpvm/vm.h>

#include <capstone/capstone.h>


static csh handle;






//
// This contains the mapping to our high-level
// interface
//
fpvm_inst_common_t capstone_to_common[X86_INS_ENDING] = {
    [0 ... X86_INS_ENDING - 1] = {FPVM_OP_UNKNOWN, 0, 0, 0},

    [X86_INS_ADDPD] = {FPVM_OP_ADD, 1, 0, 8, 0},
    [X86_INS_ADDPS] = {FPVM_OP_ADD, 1, 0, 4, 0},
    [X86_INS_ADDSD] = {FPVM_OP_ADD, 0, 0, 8, 0},
    [X86_INS_ADDSS] = {FPVM_OP_ADD, 0, 0, 4, 0},

    [X86_INS_SUBPD] = {FPVM_OP_SUB, 1, 0, 8, 0},
    [X86_INS_SUBPS] = {FPVM_OP_SUB, 1, 0, 4, 0},
    [X86_INS_SUBSD] = {FPVM_OP_SUB, 0, 0, 8, 0},
    [X86_INS_SUBSS] = {FPVM_OP_SUB, 0, 0, 4, 0},

    [X86_INS_MULPD] = {FPVM_OP_MUL, 1, 0, 8, 0},
    [X86_INS_MULPS] = {FPVM_OP_MUL, 1, 0, 4, 0},
    [X86_INS_MULSD] = {FPVM_OP_MUL, 0, 0, 8, 0},
    [X86_INS_MULSS] = {FPVM_OP_MUL, 0, 0, 4, 0},

    [X86_INS_DIVPD] = {FPVM_OP_DIV, 1, 0, 8, 0},
    [X86_INS_DIVPS] = {FPVM_OP_DIV, 1, 0, 4, 0},
    [X86_INS_DIVSD] = {FPVM_OP_DIV, 0, 0, 8, 0},
    [X86_INS_DIVSS] = {FPVM_OP_DIV, 0, 0, 4, 0},

    [X86_INS_VADDPD] = {FPVM_OP_ADD, 1, 0, 8, 0},
    [X86_INS_VADDPS] = {FPVM_OP_ADD, 1, 0, 4, 0},
    [X86_INS_VADDSD] = {FPVM_OP_ADD, 0, 0, 8, 0},
    [X86_INS_VADDSS] = {FPVM_OP_ADD, 0, 0, 4, 0},

    [X86_INS_VSUBPD] = {FPVM_OP_SUB, 1, 0, 8, 0},
    [X86_INS_VSUBPS] = {FPVM_OP_SUB, 1, 0, 4, 0},
    [X86_INS_VSUBSD] = {FPVM_OP_SUB, 0, 0, 8, 0},
    [X86_INS_VSUBSS] = {FPVM_OP_SUB, 0, 0, 4, 0},

    [X86_INS_VMULPD] = {FPVM_OP_MUL, 1, 0, 8, 0},
    [X86_INS_VMULPS] = {FPVM_OP_MUL, 1, 0, 4, 0},
    [X86_INS_VMULSD] = {FPVM_OP_MUL, 0, 0, 8, 0},
    [X86_INS_VMULSS] = {FPVM_OP_MUL, 0, 0, 4, 0},

    [X86_INS_VDIVPD] = {FPVM_OP_DIV, 1, 0, 8, 0},
    [X86_INS_VDIVPS] = {FPVM_OP_DIV, 1, 0, 4, 0},
    [X86_INS_VDIVSD] = {FPVM_OP_DIV, 0, 0, 8, 0},
    [X86_INS_VDIVSS] = {FPVM_OP_DIV, 0, 0, 4, 0},

    [X86_INS_SQRTPD] = {FPVM_OP_SQRT, 1, 0, 8, 0},
    [X86_INS_SQRTPS] = {FPVM_OP_SQRT, 1, 0, 4, 0},
    [X86_INS_SQRTSD] = {FPVM_OP_SQRT, 0, 0, 8, 0},
    [X86_INS_SQRTSS] = {FPVM_OP_SQRT, 0, 0, 4, 0},

    // note that FMA3 (Intel) allows various orderings
    // like VFMADD213PD...
    // Hopefully capstone does the operand ordering...

    // these are FMA4 (AMD)
    [X86_INS_VFMADDPD] = {FPVM_OP_MADD, 1, 0, 8, 0},
    [X86_INS_VFMADDPS] = {FPVM_OP_MADD, 1, 0, 4, 0},
    [X86_INS_VFMADDSD] = {FPVM_OP_MADD, 0, 0, 8, 0},
    [X86_INS_VFMADDSS] = {FPVM_OP_MADD, 0, 0, 4, 0},

    [X86_INS_VFNMADDPD] = {FPVM_OP_NMADD, 1, 0, 8, 0},
    [X86_INS_VFNMADDPS] = {FPVM_OP_NMADD, 1, 0, 4, 0},
    [X86_INS_VFNMADDSD] = {FPVM_OP_NMADD, 0, 0, 8, 0},
    [X86_INS_VFNMADDSS] = {FPVM_OP_NMADD, 0, 0, 4, 0},

    [X86_INS_VFMSUBPD] = {FPVM_OP_MSUB, 1, 0, 8, 0},
    [X86_INS_VFMSUBPS] = {FPVM_OP_MSUB, 1, 0, 4, 0},
    [X86_INS_VFMSUBSD] = {FPVM_OP_MSUB, 0, 0, 8, 0},
    [X86_INS_VFMSUBSS] = {FPVM_OP_MSUB, 0, 0, 4, 0},

    [X86_INS_VFNMSUBPD] = {FPVM_OP_NMSUB, 1, 0, 8, 0},
    [X86_INS_VFNMSUBPS] = {FPVM_OP_NMSUB, 1, 0, 4, 0},
    [X86_INS_VFNMSUBSD] = {FPVM_OP_NMSUB, 0, 0, 8, 0},
    [X86_INS_VFNMSUBSS] = {FPVM_OP_NMSUB, 0, 0, 4, 0},

    // min+max
    [X86_INS_MAXPD] = {FPVM_OP_MAX, 1, 0, 8, 0},
    [X86_INS_MAXPS] = {FPVM_OP_MAX, 1, 0, 4, 0},
    [X86_INS_MAXSD] = {FPVM_OP_MAX, 0, 0, 8, 0},
    [X86_INS_MAXSS] = {FPVM_OP_MAX, 0, 0, 4, 0},
    [X86_INS_MINPD] = {FPVM_OP_MIN, 1, 0, 8, 0},
    [X86_INS_MINPS] = {FPVM_OP_MIN, 1, 0, 4, 0},
    [X86_INS_MINSD] = {FPVM_OP_MIN, 0, 0, 8, 0},
    [X86_INS_MINSS] = {FPVM_OP_MIN, 0, 0, 4, 0},

    // comparisons

    [X86_INS_COMISD] = {FPVM_OP_CMP, 0, 0, 8, 0},
    [X86_INS_COMISS] = {FPVM_OP_CMP, 0, 0, 4, 0},

    [X86_INS_UCOMISD] = {FPVM_OP_UCMP, 0, 0, 8, 0},
    [X86_INS_UCOMISS] = {FPVM_OP_UCMP, 0, 0, 4, 0},

    [X86_INS_VCOMISD] = {FPVM_OP_CMP, 0, 0, 8, 0},
    [X86_INS_VCOMISS] = {FPVM_OP_CMP, 0, 0, 4, 0},

    [X86_INS_VUCOMISD] = {FPVM_OP_UCMP, 0, 0, 8, 0},
    [X86_INS_VUCOMISS] = {FPVM_OP_UCMP, 0, 0, 4, 0},

    /// vector, mask, opsize,destsize

    // CMPXX - write result into dest
    // scalar double
    [X86_INS_CMPSD] = {FPVM_OP_CMPXX, 0, 0, 8, 0},
    [X86_INS_CMPEQSD] = {FPVM_OP_CMPXX, 0, 0, 8, 0},
    [X86_INS_CMPLTSD] = {FPVM_OP_CMPXX, 0, 0, 8, 0},
    [X86_INS_CMPLESD] = {FPVM_OP_CMPXX, 0, 0, 8, 0},
    [X86_INS_CMPUNORDSD] = {FPVM_OP_CMPXX, 0, 0, 8, 0},
    [X86_INS_CMPNEQSD] = {FPVM_OP_CMPXX, 0, 0, 8, 0},
    [X86_INS_CMPNLTSD] = {FPVM_OP_CMPXX, 0, 0, 8, 0},
    [X86_INS_CMPNLESD] = {FPVM_OP_CMPXX, 0, 0, 8, 0},
    [X86_INS_CMPORDSD] = {FPVM_OP_CMPXX, 0, 0, 8, 0},

    // packed doubles
    [X86_INS_CMPPD] = {FPVM_OP_CMPXX, 1, 0, 8, 0},
    [X86_INS_CMPEQPD] = {FPVM_OP_CMPXX, 1, 0, 8, 0},
    [X86_INS_CMPLTPD] = {FPVM_OP_CMPXX, 1, 0, 8, 0},
    [X86_INS_CMPLEPD] = {FPVM_OP_CMPXX, 1, 0, 8, 0},
    [X86_INS_CMPUNORDPD] = {FPVM_OP_CMPXX, 1, 0, 8, 0},
    [X86_INS_CMPNEQPD] = {FPVM_OP_CMPXX, 1, 0, 8, 0},
    [X86_INS_CMPNLTPD] = {FPVM_OP_CMPXX, 1, 0, 8, 0},
    [X86_INS_CMPNLEPD] = {FPVM_OP_CMPXX, 1, 0, 8, 0},
    [X86_INS_CMPORDPD] = {FPVM_OP_CMPXX, 1, 0, 8, 0},

    // scalar single
    [X86_INS_CMPSS] = {FPVM_OP_CMPXX, 0, 0, 4, 0},
    [X86_INS_CMPEQSS] = {FPVM_OP_CMPXX, 0, 0, 4, 0},
    [X86_INS_CMPLTSS] = {FPVM_OP_CMPXX, 0, 0, 4, 0},
    [X86_INS_CMPLESS] = {FPVM_OP_CMPXX, 0, 0, 4, 0},
    [X86_INS_CMPUNORDSS] = {FPVM_OP_CMPXX, 0, 0, 4, 0},
    [X86_INS_CMPNEQSS] = {FPVM_OP_CMPXX, 0, 0, 4, 0},
    [X86_INS_CMPNLTSS] = {FPVM_OP_CMPXX, 0, 0, 4, 0},
    [X86_INS_CMPNLESS] = {FPVM_OP_CMPXX, 0, 0, 4, 0},
    [X86_INS_CMPORDSS] = {FPVM_OP_CMPXX, 0, 0, 4, 0},

    // packed singles
    [X86_INS_CMPPS] = {FPVM_OP_CMPXX, 1, 0, 4, 0},
    [X86_INS_CMPEQPS] = {FPVM_OP_CMPXX, 1, 0, 4, 0},
    [X86_INS_CMPLTPS] = {FPVM_OP_CMPXX, 1, 0, 4, 0},
    [X86_INS_CMPLEPS] = {FPVM_OP_CMPXX, 1, 0, 4, 0},
    [X86_INS_CMPUNORDPS] = {FPVM_OP_CMPXX, 1, 0, 4, 0},
    [X86_INS_CMPNEQPS] = {FPVM_OP_CMPXX, 1, 0, 4, 0},
    [X86_INS_CMPNLTPS] = {FPVM_OP_CMPXX, 1, 0, 4, 0},
    [X86_INS_CMPNLEPS] = {FPVM_OP_CMPXX, 1, 0, 4, 0},
    [X86_INS_CMPORDPS] = {FPVM_OP_CMPXX, 1, 0, 4, 0},

    // VEX.128 encoded scalar doubles
    [X86_INS_VCMPSD] = {FPVM_OP_CMPXX, 0, 0, 8, 0},
    [X86_INS_VCMPEQSD] = {FPVM_OP_CMPXX, 0, 0, 8, 0},
    [X86_INS_VCMPLTSD] = {FPVM_OP_CMPXX, 0, 0, 8, 0},
    [X86_INS_VCMPLESD] = {FPVM_OP_CMPXX, 0, 0, 8, 0},
    [X86_INS_VCMPUNORDSD] = {FPVM_OP_CMPXX, 0, 0, 8, 0},
    [X86_INS_VCMPNEQSD] = {FPVM_OP_CMPXX, 0, 0, 8, 0},
    [X86_INS_VCMPNLTSD] = {FPVM_OP_CMPXX, 0, 0, 8, 0},
    [X86_INS_VCMPNLESD] = {FPVM_OP_CMPXX, 0, 0, 8, 0},
    [X86_INS_VCMPORDSD] = {FPVM_OP_CMPXX, 0, 0, 8, 0},
    [X86_INS_VCMPEQ_UQSD] = {FPVM_OP_CMPXX, 0, 0, 8, 0},
    [X86_INS_VCMPNGESD] = {FPVM_OP_CMPXX, 0, 0, 8, 0},
    [X86_INS_VCMPNGTSD] = {FPVM_OP_CMPXX, 0, 0, 8, 0},
    [X86_INS_VCMPFALSESD] = {FPVM_OP_CMPXX, 0, 0, 8, 0},
    [X86_INS_VCMPNEQ_OQSD] = {FPVM_OP_CMPXX, 0, 0, 8, 0},
    [X86_INS_VCMPGESD] = {FPVM_OP_CMPXX, 0, 0, 8, 0},
    [X86_INS_VCMPGTSD] = {FPVM_OP_CMPXX, 0, 0, 8, 0},
    [X86_INS_VCMPTRUESD] = {FPVM_OP_CMPXX, 0, 0, 8, 0},
    [X86_INS_VCMPEQ_OSSD] = {FPVM_OP_CMPXX, 0, 0, 8, 0},
    [X86_INS_VCMPLT_OQSD] = {FPVM_OP_CMPXX, 0, 0, 8, 0},
    [X86_INS_VCMPLE_OQSD] = {FPVM_OP_CMPXX, 0, 0, 8, 0},
    [X86_INS_VCMPUNORD_SSD] = {FPVM_OP_CMPXX, 0, 0, 8, 0},
    [X86_INS_VCMPNEQ_USSD] = {FPVM_OP_CMPXX, 0, 0, 8, 0},
    [X86_INS_VCMPNLT_UQSD] = {FPVM_OP_CMPXX, 0, 0, 8, 0},
    [X86_INS_VCMPNLE_UQSD] = {FPVM_OP_CMPXX, 0, 0, 8, 0},
    [X86_INS_VCMPORD_SSD] = {FPVM_OP_CMPXX, 0, 0, 8, 0},
    [X86_INS_VCMPEQ_USSD] = {FPVM_OP_CMPXX, 0, 0, 8, 0},
    [X86_INS_VCMPNGE_UQSD] = {FPVM_OP_CMPXX, 0, 0, 8, 0},
    [X86_INS_VCMPNGT_UQSD] = {FPVM_OP_CMPXX, 0, 0, 8, 0},
    [X86_INS_VCMPFALSE_OSSD] = {FPVM_OP_CMPXX, 0, 0, 8, 0},
    [X86_INS_VCMPNEQ_OSSD] = {FPVM_OP_CMPXX, 0, 0, 8, 0},
    [X86_INS_VCMPGE_OQSD] = {FPVM_OP_CMPXX, 0, 0, 8, 0},
    [X86_INS_VCMPGT_OQSD] = {FPVM_OP_CMPXX, 0, 0, 8, 0},
    [X86_INS_VCMPTRUE_USSD] = {FPVM_OP_CMPXX, 0, 0, 8, 0},

    // VEX.128 encoded packed doubles
    [X86_INS_VCMPPD] = {FPVM_OP_CMPXX, 1, 0, 8, 0},
    [X86_INS_VCMPEQPD] = {FPVM_OP_CMPXX, 1, 0, 8, 0},
    [X86_INS_VCMPLTPD] = {FPVM_OP_CMPXX, 1, 0, 8, 0},
    [X86_INS_VCMPLEPD] = {FPVM_OP_CMPXX, 1, 0, 8, 0},
    [X86_INS_VCMPUNORDPD] = {FPVM_OP_CMPXX, 1, 0, 8, 0},
    [X86_INS_VCMPNEQPD] = {FPVM_OP_CMPXX, 1, 0, 8, 0},
    [X86_INS_VCMPNLTPD] = {FPVM_OP_CMPXX, 1, 0, 8, 0},
    [X86_INS_VCMPNLEPD] = {FPVM_OP_CMPXX, 1, 0, 8, 0},
    [X86_INS_VCMPORDPD] = {FPVM_OP_CMPXX, 1, 0, 8, 0},
    [X86_INS_VCMPEQ_UQPD] = {FPVM_OP_CMPXX, 1, 0, 8, 0},
    [X86_INS_VCMPNGEPD] = {FPVM_OP_CMPXX, 1, 0, 8, 0},
    [X86_INS_VCMPNGTPD] = {FPVM_OP_CMPXX, 1, 0, 8, 0},
    [X86_INS_VCMPFALSEPD] = {FPVM_OP_CMPXX, 1, 0, 8, 0},
    [X86_INS_VCMPNEQ_OQPD] = {FPVM_OP_CMPXX, 1, 0, 8, 0},
    [X86_INS_VCMPGEPD] = {FPVM_OP_CMPXX, 1, 0, 8, 0},
    [X86_INS_VCMPGTPD] = {FPVM_OP_CMPXX, 1, 0, 8, 0},
    [X86_INS_VCMPTRUEPD] = {FPVM_OP_CMPXX, 1, 0, 8, 0},
    [X86_INS_VCMPEQ_OSPD] = {FPVM_OP_CMPXX, 1, 0, 8, 0},
    [X86_INS_VCMPLT_OQPD] = {FPVM_OP_CMPXX, 1, 0, 8, 0},
    [X86_INS_VCMPLE_OQPD] = {FPVM_OP_CMPXX, 1, 0, 8, 0},
    [X86_INS_VCMPUNORD_SPD] = {FPVM_OP_CMPXX, 1, 0, 8, 0},
    [X86_INS_VCMPNEQ_USPD] = {FPVM_OP_CMPXX, 1, 0, 8, 0},
    [X86_INS_VCMPNLT_UQPD] = {FPVM_OP_CMPXX, 1, 0, 8, 0},
    [X86_INS_VCMPNLE_UQPD] = {FPVM_OP_CMPXX, 1, 0, 8, 0},
    [X86_INS_VCMPORD_SPD] = {FPVM_OP_CMPXX, 1, 0, 8, 0},
    [X86_INS_VCMPEQ_USPD] = {FPVM_OP_CMPXX, 1, 0, 8, 0},
    [X86_INS_VCMPNGE_UQPD] = {FPVM_OP_CMPXX, 1, 0, 8, 0},
    [X86_INS_VCMPNGT_UQPD] = {FPVM_OP_CMPXX, 1, 0, 8, 0},
    [X86_INS_VCMPFALSE_OSPD] = {FPVM_OP_CMPXX, 1, 0, 8, 0},
    [X86_INS_VCMPNEQ_OSPD] = {FPVM_OP_CMPXX, 1, 0, 8, 0},
    [X86_INS_VCMPGE_OQPD] = {FPVM_OP_CMPXX, 1, 0, 8, 0},
    [X86_INS_VCMPGT_OQPD] = {FPVM_OP_CMPXX, 1, 0, 8, 0},
    [X86_INS_VCMPTRUE_USPD] = {FPVM_OP_CMPXX, 1, 0, 8, 0},
    
    /*
      Additional comparison instructions we can consider -PAD

	X86_INS_VCMPSS,
	X86_INS_VCMPEQSS,
	X86_INS_VCMPLTSS,
	X86_INS_VCMPLESS,
	X86_INS_VCMPUNORDSS,
	X86_INS_VCMPNEQSS,
	X86_INS_VCMPNLTSS,
	X86_INS_VCMPNLESS,
	X86_INS_VCMPORDSS,
	X86_INS_VCMPEQ_UQSS,
	X86_INS_VCMPNGESS,
	X86_INS_VCMPNGTSS,
	X86_INS_VCMPFALSESS,
	X86_INS_VCMPNEQ_OQSS,
	X86_INS_VCMPGESS,
	X86_INS_VCMPGTSS,
	X86_INS_VCMPTRUESS,
	X86_INS_VCMPEQ_OSSS,
	X86_INS_VCMPLT_OQSS,
	X86_INS_VCMPLE_OQSS,
	X86_INS_VCMPUNORD_SSS,
	X86_INS_VCMPNEQ_USSS,
	X86_INS_VCMPNLT_UQSS,
	X86_INS_VCMPNLE_UQSS,
	X86_INS_VCMPORD_SSS,
	X86_INS_VCMPEQ_USSS,
	X86_INS_VCMPNGE_UQSS,
	X86_INS_VCMPNGT_UQSS,
	X86_INS_VCMPFALSE_OSSS,
	X86_INS_VCMPNEQ_OSSS,
	X86_INS_VCMPGE_OQSS,
	X86_INS_VCMPGT_OQSS,
	X86_INS_VCMPTRUE_USSS,


	X86_INS_VCMPPS,
	X86_INS_VCMPEQPS,
	X86_INS_VCMPLTPS,
	X86_INS_VCMPLEPS,
	X86_INS_VCMPUNORDPS,
	X86_INS_VCMPNEQPS,
	X86_INS_VCMPNLTPS,
	X86_INS_VCMPNLEPS,
	X86_INS_VCMPORDPS,
	X86_INS_VCMPEQ_UQPS,
	X86_INS_VCMPNGEPS,
	X86_INS_VCMPNGTPS,
	X86_INS_VCMPFALSEPS,
	X86_INS_VCMPNEQ_OQPS,
	X86_INS_VCMPGEPS,
	X86_INS_VCMPGTPS,
	X86_INS_VCMPTRUEPS,
	X86_INS_VCMPEQ_OSPS,
	X86_INS_VCMPLT_OQPS,
	X86_INS_VCMPLE_OQPS,
	X86_INS_VCMPUNORD_SPS,
	X86_INS_VCMPNEQ_USPS,
	X86_INS_VCMPNLT_UQPS,
	X86_INS_VCMPNLE_UQPS,
	X86_INS_VCMPORD_SPS,
	X86_INS_VCMPEQ_USPS,
	X86_INS_VCMPNGE_UQPS,
	X86_INS_VCMPNGT_UQPS,
	X86_INS_VCMPFALSE_OSPS,
	X86_INS_VCMPNEQ_OSPS,
	X86_INS_VCMPGE_OQPS,
	X86_INS_VCMPGT_OQPS,
	X86_INS_VCMPTRUE_USPS,

    */
    
    // float to integer conversion

    [X86_INS_CVTSD2SI] = {FPVM_OP_F2I, 0, 0, 8, 4},
    [X86_INS_VCVTSD2SI] = {FPVM_OP_F2I, 0, 0, 8, 4},   // rounding mode changed as side effect?
    [X86_INS_VCVTSD2USI] = {FPVM_OP_F2U, 0, 0, 8, 4},  // rounding mode changed as side effect?
    [X86_INS_CVTSS2SI] = {FPVM_OP_F2I, 0, 0, 4, 4},
    [X86_INS_VCVTSS2SI] = {FPVM_OP_F2I, 0, 0, 4, 4},   // rounding mode?
    [X86_INS_VCVTSS2USI] = {FPVM_OP_F2U, 0, 0, 4, 4},  // rounding mode?
    [X86_INS_CVTSD2SI] = {FPVM_OP_F2I, 0, 0, 8, 4},
    [X86_INS_CVTSS2SI] = {FPVM_OP_F2I, 0, 0, 4, 4},

    [X86_INS_CVTPD2PI] = {FPVM_OP_F2I, 1, 0, 8, 4},
    [X86_INS_CVTPS2PI] = {FPVM_OP_F2I, 1, 0, 4, 4},

    [X86_INS_CVTPD2DQ] = {FPVM_OP_F2I, 1, 0, 8, 8},
    [X86_INS_VCVTPD2DQ] = {FPVM_OP_F2I, 1, 1, 8, 8},
    [X86_INS_VCVTPD2UDQ] = {FPVM_OP_F2U, 1, 1, 8, 8},
    // X86_INS_VCVTPD2DQX   ????

    [X86_INS_CVTPS2DQ] = {FPVM_OP_F2I, 1, 0, 4, 8},
    [X86_INS_VCVTPS2DQ] = {FPVM_OP_F2I, 1, 1, 4, 8},
    [X86_INS_VCVTPS2UDQ] = {FPVM_OP_F2U, 1, 1, 4, 8},

    [X86_INS_CVTTSD2SI] = {FPVM_OP_F2IT, 0, 0, 8, 4},
    [X86_INS_CVTTSS2SI] = {FPVM_OP_F2IT, 0, 0, 4, 4},

    [X86_INS_CVTTPS2PI] = {FPVM_OP_F2IT, 1, 0, 4, 4},
    [X86_INS_CVTTPD2PI] = {FPVM_OP_F2IT, 1, 0, 8, 4},

    [X86_INS_CVTTPD2DQ] = {FPVM_OP_F2IT, 1, 0, 8, 8},
    [X86_INS_VCVTTPD2DQ] = {FPVM_OP_F2IT, 1, 1, 8, 8},
    // X86_INS_VCVTTPD2DQX ????
    [X86_INS_CVTTPS2DQ] = {FPVM_OP_F2IT, 1, 0, 4, 8},
    [X86_INS_VCVTTPS2DQ] = {FPVM_OP_F2IT, 1, 1, 4, 8},
    [X86_INS_VCVTTPS2UDQ] = {FPVM_OP_F2UT, 1, 1, 4, 8},

    [X86_INS_VCVTTSD2SI] = {FPVM_OP_F2IT, 0, 0, 8, 4},
    [X86_INS_VCVTTSD2USI] = {FPVM_OP_F2UT, 0, 0, 8, 4},

    [X86_INS_VCVTTSS2SI] = {FPVM_OP_F2IT, 0, 0, 4, 4},
    [X86_INS_VCVTTSS2USI] = {FPVM_OP_F2UT, 0, 0, 4, 4},

    // AVX
    [X86_INS_VCVTTSD2SI] = {FPVM_OP_F2I, 0, 0, 8, 4},
    [X86_INS_VCVTTSS2SI] = {FPVM_OP_F2I, 0, 0, 4, 4},
    [X86_INS_VCVTTSD2USI] = {FPVM_OP_F2U, 0, 0, 8, 4},
    [X86_INS_VCVTTSS2USI] = {FPVM_OP_F2U, 0, 0, 4, 4},

    // integer to float conversion

    [X86_INS_CVTSI2SD] = {FPVM_OP_I2F, 0, 0, 4, 8},
    [X86_INS_CVTSI2SS] = {FPVM_OP_I2F, 0, 0, 4, 4},

    [X86_INS_CVTPI2PD] = {FPVM_OP_I2F, 0, 0, 4, 8},
    [X86_INS_CVTPI2PS] = {FPVM_OP_I2F, 0, 0, 4, 4},

    [X86_INS_CVTDQ2PD] = {FPVM_OP_I2F, 1, 0, 8, 8},
    [X86_INS_VCVTDQ2PD] = {FPVM_OP_I2F, 1, 1, 8, 8},
    [X86_INS_VCVTUDQ2PD] = {FPVM_OP_U2F, 1, 1, 8, 8},
    [X86_INS_CVTDQ2PS] = {FPVM_OP_I2F, 1, 0, 8, 4},
    [X86_INS_VCVTDQ2PS] = {FPVM_OP_I2F, 1, 1, 8, 4},
    [X86_INS_VCVTUDQ2PS] = {FPVM_OP_U2F, 1, 1, 8, 4},

    [X86_INS_VCVTSI2SD] = {FPVM_OP_I2F, 0, 0, 4, 8},
    [X86_INS_VCVTSI2SS] = {FPVM_OP_I2F, 0, 0, 4, 4},

    [X86_INS_VCVTUSI2SD] = {FPVM_OP_U2F, 0, 0, 4, 8},
    [X86_INS_VCVTUSI2SS] = {FPVM_OP_U2F, 0, 0, 4, 4},

    // float to float conversion
    [X86_INS_CVTSS2SD] = {FPVM_OP_F2F, 0, 0, 4, 8},
    [X86_INS_CVTPS2PD] = {FPVM_OP_F2F, 1, 0, 4, 8},
    [X86_INS_VCVTPS2PD] = {FPVM_OP_F2F, 1, 1, 4, 8},
    [X86_INS_CVTSD2SS] = {FPVM_OP_F2F, 0, 0, 8, 4},
    [X86_INS_CVTPD2PS] = {FPVM_OP_F2F, 1, 0, 8, 4},
    [X86_INS_VCVTPD2PS] = {FPVM_OP_F2F, 1, 1, 8, 4},
    // X86_INS_VCVTPD2PSX ????

    [X86_INS_VCVTSS2SD] = {FPVM_OP_F2F, 0, 0, 4, 8},
    [X86_INS_VCVTSD2SS] = {FPVM_OP_F2F, 0, 0, 8, 4},

    // half float conversions
    [X86_INS_VCVTPH2PS] = {FPVM_OP_F2F, 1, 1, 2, 4},
    [X86_INS_VCVTPS2PH] = {FPVM_OP_F2F, 1, 1, 4, 2},

    // New

    // Bit operations
    //  [X86_INS_PSRLDQ] = {FPVM_OP_SHIFT_RIGHT_BYTE, 0, 0, 8, 8},
    //  [X86_INS_PSLLDQ] = {FPVM_OP_SHIFT_LEFT_BYTE, 0, 0, 8, 8},

    // integer move operations
    // moves are handled during sequence emulation to lengthen sequence length
    // they are also needed for correctness traps
    [X86_INS_MOV] = {FPVM_OP_MOVE, 0, 0, 8, 8},  // is this right? - PAD
    [X86_INS_MOVD] = {FPVM_OP_MOVE, 0, 0, 4, 4},
    [X86_INS_MOVQ] = {FPVM_OP_MOVE, 0, 0, 8, 8},
    [X86_INS_MOVNTQ] = {FPVM_OP_MOVE, 0, 0, 8, 8},
    [X86_INS_MOVSX] = {FPVM_OP_MOVE, 0, 0, 2, 8}, // depends on a lot
    [X86_INS_MOVSXD] = {FPVM_OP_MOVE, 0, 0, 4, 8}, // depends on a lot
    [X86_INS_MOVZX] = {FPVM_OP_MOVE, 0, 0, 2, 8}, // depends on a lot    

    [X86_INS_VMOVD] = {FPVM_OP_MOVE, 0, 0, 4, 4},
    [X86_INS_VMOVQ] = {FPVM_OP_MOVE, 0, 0, 8, 8},
    
    
    // FP moves
    
    [X86_INS_MOVSS] = {FPVM_OP_MOVE, 0, 0, 4, 4},
    [X86_INS_MOVSD] = {FPVM_OP_MOVE, 0, 0, 8, 8},
    [X86_INS_MOVAPS] = {FPVM_OP_MOVE, 1, 0, 4, 4},
    [X86_INS_MOVAPD] = {FPVM_OP_MOVE, 1, 0, 8, 8},
    [X86_INS_MOVUPS] = {FPVM_OP_MOVE, 1, 0, 4, 4},
    [X86_INS_MOVUPD] = {FPVM_OP_MOVE, 1, 0, 8, 8},
    [X86_INS_MOVNTPD] = {FPVM_OP_MOVE, 1, 0, 8, 8},
    [X86_INS_MOVNTPS] = {FPVM_OP_MOVE, 1, 0, 4, 4},
    [X86_INS_MOVNTSD] = {FPVM_OP_MOVE, 0, 0, 8, 8},
    [X86_INS_MOVNTSS] = {FPVM_OP_MOVE, 0, 0, 4, 4},

    [X86_INS_VMOVSS] = {FPVM_OP_MOVE, 0, 0, 4, 4},
    [X86_INS_VMOVSD] = {FPVM_OP_MOVE, 0, 0, 8, 8},
    [X86_INS_VMOVAPS] = {FPVM_OP_MOVE, 1, 0, 4, 4},
    [X86_INS_VMOVAPD] = {FPVM_OP_MOVE, 1, 0, 8, 8},
    [X86_INS_VMOVUPS] = {FPVM_OP_MOVE, 1, 0, 4, 4},
    [X86_INS_VMOVUPD] = {FPVM_OP_MOVE, 1, 0, 8, 8},
    [X86_INS_VMOVNTPD] = {FPVM_OP_MOVE, 1, 0, 8, 8},
    [X86_INS_VMOVNTPS] = {FPVM_OP_MOVE, 1, 0, 4, 4},

    // full vector instructions for integer
    [X86_INS_MOVDQA] = {FPVM_OP_MOVE, 0, 0, 16, 16},
    [X86_INS_MOVDQU] = {FPVM_OP_MOVE, 0, 0, 16, 16},
    [X86_INS_MOVNTDQA] = {FPVM_OP_MOVE, 0, 0, 16, 16},
    [X86_INS_MOVNTDQ] = {FPVM_OP_MOVE, 0, 0, 16, 16},

    /*
      Additional MOV ops we can look through - PAD
	X86_INS_MOVDQ2Q,
    	X86_INS_MOVQ2DQ,
	X86_INS_MOVABS,
	X86_INS_MOVBE,
	X86_INS_MOVDDUP,
	X86_INS_MOVHLPS,
	X86_INS_MOVHPD,
	X86_INS_MOVHPS,
	X86_INS_MOVLHPS,
	X86_INS_MOVLPD,
	X86_INS_MOVLPS,
	X86_INS_MOVMSKPD,
	X86_INS_MOVMSKPS,
	X86_INS_MOVNTI,
	X86_INS_MOVSB,
	X86_INS_MOVSD,
	X86_INS_MOVSHDUP,
	X86_INS_MOVSLDUP,
	X86_INS_MOVSQ,
	X86_INS_MOVSS,
	X86_INS_MOVSW,
	X86_INS_PMOVSXBD,
	X86_INS_PMOVSXBQ,
	X86_INS_PMOVSXBW,
	X86_INS_PMOVSXDQ,
	X86_INS_PMOVSXWD,
	X86_INS_PMOVSXWQ,
	X86_INS_PMOVZXBD,
	X86_INS_PMOVZXBQ,
	X86_INS_PMOVZXBW,
	X86_INS_PMOVZXDQ,
	X86_INS_PMOVZXWD,
	X86_INS_PMOVZXWQ,
	X86_INS_VMASKMOVDQU,
	X86_INS_VMASKMOVPD,
	X86_INS_VMASKMOVPS,
	X86_INS_VMOVDDUP,
	X86_INS_VMOVDQA32,
	X86_INS_VMOVDQA64,
	X86_INS_VMOVDQA,
	X86_INS_VMOVDQU16,
	X86_INS_VMOVDQU32,
	X86_INS_VMOVDQU64,
	X86_INS_VMOVDQU8,
	X86_INS_VMOVDQU,
	X86_INS_VMOVHLPS,
	X86_INS_VMOVHPD,
	X86_INS_VMOVHPS,
	X86_INS_VMOVLHPS,
	X86_INS_VMOVLPD,
	X86_INS_VMOVLPS,
	X86_INS_VMOVMSKPD,
	X86_INS_VMOVMSKPS,
	X86_INS_VMOVNTDQA,
	X86_INS_VMOVNTDQ,
	X86_INS_VMOVSD,
	X86_INS_VMOVSHDUP,
	X86_INS_VMOVSLDUP,
	X86_INS_VPCMOV,
	X86_INS_VPMASKMOVD,
	X86_INS_VPMASKMOVQ,
	X86_INS_VPMOVDB,
	X86_INS_VPMOVDW,
	X86_INS_VPMOVM2B,
	X86_INS_VPMOVM2D,
	X86_INS_VPMOVM2Q,
	X86_INS_VPMOVM2W,
	X86_INS_VPMOVMSKB,
	X86_INS_VPMOVQB,
	X86_INS_VPMOVQD,
	X86_INS_VPMOVQW,
	X86_INS_VPMOVSDB,
	X86_INS_VPMOVSDW,
	X86_INS_VPMOVSQB,
	X86_INS_VPMOVSQD,
	X86_INS_VPMOVSQW,
	X86_INS_VPMOVSXBD,
	X86_INS_VPMOVSXBQ,
	X86_INS_VPMOVSXBW,
	X86_INS_VPMOVSXDQ,
	X86_INS_VPMOVSXWD,
	X86_INS_VPMOVSXWQ,
	X86_INS_VPMOVUSDB,
	X86_INS_VPMOVUSDW,
	X86_INS_VPMOVUSQB,
	X86_INS_VPMOVUSQD,
	X86_INS_VPMOVUSQW,
	X86_INS_VPMOVZXBD,
	X86_INS_VPMOVZXBQ,
	X86_INS_VPMOVZXBW,
	X86_INS_VPMOVZXDQ,
	X86_INS_VPMOVZXWD,
	X86_INS_VPMOVZXWQ,
	X86_INS_CMOVA,
	X86_INS_CMOVAE,
	X86_INS_CMOVB,
	X86_INS_CMOVBE,
	X86_INS_FCMOVBE,
	X86_INS_FCMOVB,
	X86_INS_CMOVE,
	X86_INS_FCMOVE,
	X86_INS_CMOVG,
	X86_INS_CMOVGE,
	X86_INS_CMOVL,
	X86_INS_CMOVLE,
	X86_INS_FCMOVNBE,
	X86_INS_FCMOVNB,
	X86_INS_CMOVNE,
	X86_INS_FCMOVNE,
	X86_INS_CMOVNO,
	X86_INS_CMOVNP,
	X86_INS_FCMOVNU,
	X86_INS_CMOVNS,
	X86_INS_CMOVO,
	X86_INS_CMOVP,
	X86_INS_FCMOVU,
	X86_INS_CMOVS,
	X86_INS_KMOVB,
	X86_INS_KMOVD,
	X86_INS_KMOVQ,
	X86_INS_KMOVW,
	X86_INS_MASKMOVDQU,
	X86_INS_MASKMOVQ,

    */

    // operations to handle for correctness traps
    [X86_INS_MOVDDUP] = {FPVM_OP_WARN, 1, 0, 8, 8},
    [X86_INS_SHUFPD] = {FPVM_OP_WARN, 1, 0, 8, 8},
    [X86_INS_UNPCKHPD] = {FPVM_OP_WARN, 1, 0, 8, 8},

    // call instructions and related
    // by "call instructions", we mean instructions that
    // are identifed by fpvm_patch.sh as being departures
    // from the patched codebase (i.e., foreign calls)
    // such departures can come due to calls, jumps, and
    // conditional jumps.  
    // push is also included here because that is
    // instruction that the patcher marks, instead of
    // the call following it
    [X86_INS_CALL] = {FPVM_OP_CALL, 0, 0, 0, 0},
    [X86_INS_PUSH] = {FPVM_OP_CALL, 0, 0, 0, 0},
    // or we might tail-call to foreign function
    [X86_INS_JMP] = {FPVM_OP_CALL, 0, 0, 0, 0},
    [X86_INS_LJMP] = {FPVM_OP_CALL, 0, 0, 0, 0},
    // a foreign function tail-call might involve a conditional jump as well
    [X86_INS_JA] = {FPVM_OP_CALL, 0, 0, 0, 0},
    [X86_INS_JAE] = {FPVM_OP_CALL, 0, 0, 0, 0},
    [X86_INS_JB] = {FPVM_OP_CALL, 0, 0, 0, 0},
    [X86_INS_JBE] = {FPVM_OP_CALL, 0, 0, 0, 0},
    // 1[X86_INS_JC] = {FPVM_OP_CALL, 0, 0, 0, 0}, // synonymed to JB
    [X86_INS_JCXZ] = {FPVM_OP_CALL, 0, 0, 0, 0},
    [X86_INS_JECXZ] = {FPVM_OP_CALL, 0, 0, 0, 0},
    [X86_INS_JRCXZ] = {FPVM_OP_CALL, 0, 0, 0, 0},
    [X86_INS_JE] = {FPVM_OP_CALL, 0, 0, 0, 0}, // JZ
    [X86_INS_JG] = {FPVM_OP_CALL, 0, 0, 0, 0},
    [X86_INS_JGE] = {FPVM_OP_CALL, 0, 0, 0, 0},
    [X86_INS_JL] = {FPVM_OP_CALL, 0, 0, 0, 0},
    [X86_INS_JLE] = {FPVM_OP_CALL, 0, 0, 0, 0},
    // [X86_INS_JNA] = {FPVM_OP_CALL, 0, 0, 0, 0}, // synonymed to JBE
    // [X86_INS_JNAE] = {FPVM_OP_CALL, 0, 0, 0, 0}, // synonymed to JB
    // [X86_INS_JNB] = {FPVM_OP_CALL, 0, 0, 0, 0}, // synonymed to JAE
    // [X86_INS_JNBE] = {FPVM_OP_CALL, 0, 0, 0, 0}, // synonymed to JA
    // [X86_INS_JNC] = {FPVM_OP_CALL, 0, 0, 0, 0}, // synonymed to JAE
    [X86_INS_JNE] = {FPVM_OP_CALL, 0, 0, 0, 0},
    // [X86_INS_JNG] = {FPVM_OP_CALL, 0, 0, 0, 0}, // synonymed to JLE
    // [X86_INS_JNGE] = {FPVM_OP_CALL, 0, 0, 0, 0}, // synonymed to JL
    // [X86_INS_JNL] = {FPVM_OP_CALL, 0, 0, 0, 0}, // synonymed to JGE
    // [X86_INS_JNLE] = {FPVM_OP_CALL, 0, 0, 0, 0}, // synonymed to JG
    [X86_INS_JNO] = {FPVM_OP_CALL, 0, 0, 0, 0},
    [X86_INS_JNP] = {FPVM_OP_CALL, 0, 0, 0, 0},
    [X86_INS_JNS] = {FPVM_OP_CALL, 0, 0, 0, 0},
    // [X86_INS_JNZ] = {FPVM_OP_CALL, 0, 0, 0, 0}, // synonymed to JNE
    [X86_INS_JO] = {FPVM_OP_CALL, 0, 0, 0, 0},
    [X86_INS_JP] = {FPVM_OP_CALL, 0, 0, 0, 0},
    // [X86_INS_JPE] = {FPVM_OP_CALL, 0, 0, 0, 0}, // synonymed to JP "parity even"
    //[X86_INS_JPO] = {FPVM_OP_CALL, 0, 0, 0, 0}, // synonymed to JNP "parity odd"
    [X86_INS_JS] = {FPVM_OP_CALL, 0, 0, 0, 0},
    // [X86_INS_JZ] = {FPVM_OP_CALL, 0, 0, 0, 0}, // synonymed to JE

    // rounding
    // [X86_INS_ROUNDSD] = {FPVM_OP_ROUND, 0, 0, 8, 8},

};

static int decode_to_common(fpvm_inst_t *fi) {
  cs_insn *inst = (cs_insn *)fi->internal;

  fi->addr = (void *)inst->address;
  fi->length = inst->size;

  fi->common = &capstone_to_common[inst->id];

  if (fi->common->op_type == FPVM_OP_UNKNOWN) {
    // not an error, since this could be a sequence-ending instruction
    DEBUG("instruction decodes to unknown common op type\n");
    return -1;
  }

  return 0;
}

static int decode_move(fpvm_inst_t *fi) {
  cs_insn *inst = (cs_insn *)fi->internal;
  fi->is_simple_mov = 0;
  fi->is_gpr_mov = 0;

  // simple_mov means scalar, perhaps with sign extension
  switch (inst->id) {
  // integer moves
  case X86_INS_MOV:
  case X86_INS_MOVD:
  case X86_INS_MOVQ:
  case X86_INS_MOVNTQ:
  case X86_INS_VMOVD:
  case X86_INS_VMOVQ:
    fi->is_simple_mov = 1;
    fi->is_gpr_mov = 1;
    fi->extend = FPVM_INST_ZERO_EXTEND;
    break;
    
  case X86_INS_MOVZX:
    fi->is_simple_mov = 1;
    fi->is_gpr_mov = 1;
    fi->extend = FPVM_INST_ZERO_EXTEND;
    break;

  case X86_INS_MOVSX:
  case X86_INS_MOVSXD:
    //ERROR("see movsx/sxd\n");
    //fpvm_decoder_decode_and_print_any_inst(fi->addr,stderr,"movsx(d): ");
    fi->is_simple_mov = 1;
    fi->is_gpr_mov = 0;   // but this really is a simple gpr move..
    fi->extend = FPVM_INST_SIGN_EXTEND;
    break;

  // floating point moves
  case X86_INS_MOVSS:
  case X86_INS_MOVSD:
  case X86_INS_MOVNTSD:
  case X86_INS_MOVNTSS:
  case X86_INS_VMOVSS:
  case X86_INS_VMOVSD:
    fi->is_simple_mov = 1;
    fi->is_gpr_mov = 0;
    fi->extend = FPVM_INST_ZERO_EXTEND;
    break;
  default:
    fi->is_simple_mov = 0;
    fi->is_gpr_mov = 0;
    fi->extend = FPVM_INST_ZERO_EXTEND;
    break;
  }
  return 0;
}

static int decode_comparison(fpvm_inst_t *fi)
{
  if (fi->common->op_type!=FPVM_OP_CMPXX) {
    return 0;
  }
  
  cs_insn *inst = (cs_insn *)fi->internal;
 
  // first try AVX CCs
  if (inst->detail->x86.avx_cc != X86_AVX_CC_INVALID) {
    DEBUG("avx comparison encoding:  %d\n", inst->detail->x86.avx_cc);
    fi->compare = inst->detail->x86.avx_cc;
    return 0;
  }
    
  if (inst->detail->x86.sse_cc != X86_SSE_CC_INVALID) {
    DEBUG("sse comparison encoding:  %d\n", inst->detail->x86.sse_cc);
    fi->compare = inst->detail->x86.sse_cc;
    return 0;
  }
    
  ERROR("cmpxx operation but has no valid comparison type\n");
  return -1;
}

int fpvm_decoder_init(void) {
  if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
    ERROR("Failed to open decoder\n");
    return -1;
  }
  if (cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK) {
    ERROR("Cannot enable detailed decode\n");
    return -1;
  }
  DEBUG("decoder initialized\n");
  return 0;
}

void fpvm_decoder_deinit(void) {
  DEBUG("decoder deinit\n");
  cs_close(&handle);
}

void fpvm_decoder_free_inst(fpvm_inst_t *fi) {
  DEBUG("decoder free inst at %p\n", fi);
  cs_free(fi->internal, 1);
  free(fi);
}

fpvm_inst_t *fpvm_decoder_decode_inst(void *addr) {
  cs_insn *inst;

  DEBUG("Decoding instruction at %p\n", addr);

  size_t count = cs_disasm(handle, addr, 16, (uint64_t)addr, 1, &inst);

  if (count != 1) {
    ERROR("Failed to decode instruction (return=%lu, errno=%d)\n", count, cs_errno(handle));
    return 0;
  }

  fpvm_inst_t *fi = malloc(sizeof(fpvm_inst_t));
  if (!fi) {
    ERROR("Can't allocate instruciton\n");
    return 0;
  }
  memset(fi, 0, sizeof(*fi));
  fi->addr = addr;
  fi->internal = inst;

  if (decode_to_common(fi)) {
    DEBUG("Can't decode to common representation\n");
    fpvm_decoder_free_inst(fi);
    return 0;
  }

  if (decode_move(fi)) {
    DEBUG("Can't decode move info\n");
    fpvm_decoder_free_inst(fi);
    return 0;
  }

  if (decode_comparison(fi)) {
    DEBUG("Can't decode comparison info\n");
    fpvm_decoder_free_inst(fi);
    return 0;
  }


  fpvm_vm_compile(fi);

  return fi;
}

int  fpvm_decoder_decode_and_print_any_inst(void *addr, FILE *out, char *prefix)
{
  cs_insn *inst;
  int len;

  //  DEBUG("Decoding instruction for print at %p\n", addr);

  size_t count = cs_disasm(handle, addr, 16, (uint64_t)addr, 1, &inst);

  if (count != 1) {
    ERROR("Failed to decode instruction for print (return=%lu, errno=%d)\n", count, cs_errno(handle));
    return -1;
  }

  fprintf(out, "%s%s\t\t%s (%u bytes)\n", prefix, inst->mnemonic, inst->op_str, inst->size);

  len = inst->size;
  
  cs_free(inst, 1);
  
  return len;
  
}


static char *group_name(uint8_t group);
static char *prefix_name(uint8_t reg);
static char *inst_name(x86_insn inst);
static char *reg_name(x86_reg reg);

void fpvm_decoder_get_inst_str(fpvm_inst_t *fi, char *buf, int len) {
  cs_insn *inst = (cs_insn *)fi->internal;

  snprintf(buf, len, "%s %s", inst->mnemonic, inst->op_str);
}

void fpvm_decoder_print_inst(fpvm_inst_t *fi, FILE *out) {
  cs_insn *inst = (cs_insn *)fi->internal;
  int i;

  fprintf(out, "0x%" PRIx64 ":\t%s\t\t%s (%u bytes)\n", inst->address, inst->mnemonic, inst->op_str,
      inst->size);
  return;

  fprintf(out, " instruction: %x (%s)\n", inst->id, inst_name(inst->id));

  fprintf(out, " op_type=%d is_vector=%d has_mask=%d op_size=%d\n", fi->common->op_type,
      fi->common->is_vector, fi->common->has_mask, fi->common->op_size);

  fprintf(out, " %d bound operands:\n", fi->operand_count);
  for (i = 0; i < fi->operand_count; i++) {
    fprintf(out, "  %d -> (%p, %u)\n", i, fi->operand_addrs[i], fi->operand_sizes[i]);
  }

  cs_detail *det = inst->detail;
  cs_x86 *x86 = &det->x86;

  fprintf(out,
      " %u implicit regs read %u implict regs written, instruction in %u "
      "groups\n",
      det->regs_read_count, det->regs_write_count, det->groups_count);
  if (det->regs_read_count > 0) {
    for (i = 0; i < det->regs_read_count; i++) {
      fprintf(out, "  implicit read %02x - %s\n", det->regs_read[i], reg_name(det->regs_read[i]));
    }
  }
  if (det->regs_write_count > 0) {
    for (i = 0; i < det->regs_write_count; i++) {
      fprintf(
          out, "  implicit write %02x - %s\n", det->regs_write[i], reg_name(det->regs_write[i]));
    }
  }
  if (det->groups_count > 0) {
    for (i = 0; i < det->groups_count; i++) {
      fprintf(out, "  group %02x - %s \n", det->groups[i], group_name(det->groups[i]));
    }
  }
  fprintf(out,
      " prefixes: %02x (%s) %02x (%s) %02x (%s) %02x (%s) rex: %02x  "
      "baseaddrsize: %02x\n",
      x86->prefix[0], prefix_name(x86->prefix[0]), x86->prefix[1], prefix_name(x86->prefix[1]),
      x86->prefix[2], prefix_name(x86->prefix[2]), x86->prefix[3], prefix_name(x86->prefix[3]),
      x86->rex, x86->addr_size);
  fprintf(out, " opcode: %02x %02x %02x %02x\n", x86->opcode[0], x86->opcode[1], x86->opcode[2],
      x86->opcode[3]);
  fprintf(out, " modrm: %02x sib: %02x (base=%u index=%u scale=%u)  disp: %016lx\n", x86->modrm,
      x86->sib, x86->sib_base, x86->sib_index, x86->sib_scale, x86->disp);

  fprintf(out, " operands: %02x\n", x86->op_count);
  for (i = 0; i < x86->op_count; i++) {
    cs_x86_op *o = &x86->operands[i];
    switch (o->type) {
      case X86_OP_REG:
        fprintf(out, "  %d: register %d (%s)\n", i, o->reg, reg_name(o->reg));
        break;
      case X86_OP_IMM:
        fprintf(out, "  %d: immediate %016lx\n", i, o->imm);
        break;
      // case X86_OP_FP:
      //   fprintf(out,"  %d: float immediate %lf (%016lx)\n", i, o->fp,
      //   *(uint64_t*)&o->fp); break;
      case X86_OP_MEM:
        fprintf(out,
            "  %d: memory (seg=%d (%s) base=%d (%s) index=%d (%s), scale=%d, "
            "disp=016%lx)\n",
            i, o->mem.segment, reg_name(o->mem.segment), o->mem.base, reg_name(o->mem.base),
            o->mem.index, reg_name(o->mem.index), o->mem.scale, o->mem.disp);
        break;
      default:
        fprintf(out, "  %d: UNKNOWN\n", i);
        break;
    }
  }
}

// original FP
#define IS_X87(r) ((r) >= X86_REG_ST0 && (r) <= X86_REG_ST7)
// internal 80 bit x87 register access
#define IS_X87_80(r) ((r) >= X86_REG_FP0 && (r) <= X86_REG_FP7)
// first vector featureset, overloading x87
#define IS_MMX(r) ((r) >= X86_REG_MM0 && (r) <= X86_REG_MM7)
// second vector featureset (SSE+)
#define IS_XMM(r) ((r) >= X86_REG_XMM0 && (r) <= X86_REG_XMM31)
#define IS_YMM(r) ((r) >= X86_REG_YMM0 && (r) <= X86_REG_YMM31)
#define IS_ZMM(r) ((r) >= X86_REG_ZMM0 && (r) <= X86_REG_ZMM31)
// these registers allow masking of individual vector elements
// in AVX512 instructions
#define IS_AVX512_MASK(r) ((r) >= X86_REG_K0 && (r) <= X86_REG_K7)

#define IS_NORMAL_FPR(r) (IS_XMM(r) || IS_YMM(r) || IS_ZMM(r))

#define IS_FPR(r) (IS_NORMAL_FPR(r) || IS_AVX512_MASK(r) || IS_X87(r) || IS_X87_80(r) || IS_MMX(r))

// the map is from capstone regnum to mcontext gpr, offset (assuming
// little endian), size
typedef int reg_map_entry_t[3];

static reg_map_entry_t capstone_to_mcontext[X86_REG_ENDING] = {

#define REG_ZERO -1
#define REG_NONE -2

    // base (undefined)
    [0 ... X86_REG_ENDING - 1] = {REG_NONE, 0, 0},

    [X86_REG_AH] = {REG_RAX, 1, 1},
    [X86_REG_AL] = {REG_RAX, 0, 1},
    [X86_REG_AX] = {REG_RAX, 0, 2},
    [X86_REG_EAX] = {REG_RAX, 0, 4},
    [X86_REG_RAX] = {REG_RAX, 0, 8},

    [X86_REG_BH] = {REG_RBX, 1, 1},
    [X86_REG_BL] = {REG_RBX, 0, 1},
    [X86_REG_BX] = {REG_RBX, 0, 2},
    [X86_REG_EBX] = {REG_RBX, 0, 4},
    [X86_REG_RBX] = {REG_RBX, 0, 8},

    [X86_REG_CH] = {REG_RCX, 1, 1},
    [X86_REG_CL] = {REG_RCX, 0, 1},
    [X86_REG_CX] = {REG_RCX, 0, 2},
    [X86_REG_ECX] = {REG_RCX, 0, 4},
    [X86_REG_RCX] = {REG_RCX, 0, 8},

    [X86_REG_DH] = {REG_RDX, 1, 1},
    [X86_REG_DL] = {REG_RDX, 0, 1},
    [X86_REG_DX] = {REG_RDX, 0, 2},
    [X86_REG_EDX] = {REG_RDX, 0, 4},
    [X86_REG_RDX] = {REG_RDX, 0, 8},

    [X86_REG_SIL] = {REG_RSI, 0, 1},
    [X86_REG_SI] = {REG_RSI, 0, 2},
    [X86_REG_ESI] = {REG_RSI, 0, 4},
    [X86_REG_RSI] = {REG_RSI, 0, 8},

    [X86_REG_DIL] = {REG_RDI, 0, 1},
    [X86_REG_DI] = {REG_RDI, 0, 2},
    [X86_REG_EDI] = {REG_RDI, 0, 4},
    [X86_REG_RDI] = {REG_RDI, 0, 8},

    [X86_REG_SPL] = {REG_RSP, 0, 1},
    [X86_REG_SP] = {REG_RSP, 0, 2},
    [X86_REG_ESP] = {REG_RSP, 0, 4},
    [X86_REG_RSP] = {REG_RSP, 0, 8},

    [X86_REG_BPL] = {REG_RBP, 0, 1},
    [X86_REG_BP] = {REG_RBP, 0, 2},
    [X86_REG_EBP] = {REG_RBP, 0, 4},
    [X86_REG_RBP] = {REG_RBP, 0, 8},

#define SANE_GPR(x)                                                       \
  [X86_REG_##x##B] = {REG_##x, 0, 1}, [X86_REG_##x##W] = {REG_##x, 0, 2}, \
  [X86_REG_##x##D] = {REG_##x, 0, 4}, [X86_REG_##x] = {REG_##x, 0, 8}

    SANE_GPR(R8),
    SANE_GPR(R9),
    SANE_GPR(R10),
    SANE_GPR(R11),
    SANE_GPR(R12),
    SANE_GPR(R13),
    SANE_GPR(R14),
    SANE_GPR(R15),

    [X86_REG_IP] = {REG_RIP, 0, 2},
    [X86_REG_EIP] = {REG_RIP, 0, 4},
    [X86_REG_RIP] = {REG_RIP, 0, 8},

    [X86_REG_FS] = {REG_CSGSFS, 4, 2},
    [X86_REG_GS] = {REG_CSGSFS, 2, 2},

    [X86_REG_EFLAGS] = {REG_EFL, 0, 4},

    // pseudo reg that is zero
    [X86_REG_EIZ] = {REG_ZERO, 0, 4},
    [X86_REG_RIZ] = {REG_ZERO, 0, 8},

};

#define CAPSTONE_TO_MCONTEXT(r) (&(capstone_to_mcontext[r]))

#define MCREG(m) ((*m)[0])
#define MCOFF(m) ((*m)[1])
#define MCSIZE(m) ((*m)[2])

//   DO_REG(	X86_REG_FPSW);
//      DO_REG( X86_REG_SS);

// after this function is complete, every operand pointer in
// fi will be pointing to the relavent memory location or a
// a field (register snapshot) in fr.
int fpvm_decoder_bind_operands(fpvm_inst_t *fi, fpvm_regs_t *fr) {
  cs_insn *inst = (cs_insn *)fi->internal;
  cs_detail *det = inst->detail;
  cs_x86 *x86 = &det->x86;
  
  // operand sizes for memory operands cannot be determined
  // trivially, so the idea here is to make memory operands
  // correspond to the largest operand size we encounter
  // in the instruction.   This is done in two passes
  uint8_t max_operand_size=0;
#define UPDATE_MAX_OPERAND_SIZE(s) max_operand_size = ((s)>max_operand_size) ? (s) : max_operand_size;
  
  int i;

  DEBUG("binding instruction to mcontext=%p fprs=%p fpr_size=%u\n", fr->mcontext, fr->fprs,
      fr->fpr_size);

  if (fi->common->op_type == FPVM_OP_CMP || fi->common->op_type == FPVM_OP_UCMP) {
    fi->side_effect_addrs[0] = (void *)(uint64_t *)&fr->mcontext->gregs[REG_EFL];
    // PAD: DO WE HANDLE SIDE EFFECTS IN COMPARES CORRECTLY?
    // CMP/UCMP put their result in the rflags register
    // WHAT ABOUT OTEHR SIDE EFFECTING INSTRUCTIONS?
    //
    // PAD: WE DO NOT CURRENTLY HAVE THE EMULATED INSTRUCTION
    // TOUCH THE MXCSR register (these are the condition codes for floating
    // point We must eventually emulate these, but note that we must mask out
    // any manipulation of the control bits since we use those to invoke FPVM
    // handle MXCSR LATER FIX FIX FIX
    //   fi->side_effect_addrs[1] = &fr->mcontext->gregs[REG_MXCSR];
  }

  fi->operand_count = 0;

  for (i = 0; i < x86->op_count; i++) {
    cs_x86_op *o = &x86->operands[i];
    switch (o->type) {
      case X86_OP_REG:

        if (IS_FPR(o->reg)) {
          // PAD: how FPRs beyond the classic x87 and 16 xmm registers are
          // conveyed to a signal handler is a bit of a mystery, hence this
          // assertion see /usr/include/x86_64-linux-gnu/sys/ucontext.h for why
          // this is confusing that's the system-specific defn of an mcontext. it
          // may be that we have to explicitly handle FPRs beyond these by a dump
          // and restore chunk of assembly
          ASSERT(IS_NORMAL_FPR(o->reg) && IS_XMM(o->reg) && ((o->reg - X86_REG_XMM0) < 16) &&
                 ((o->reg - X86_REG_XMM0) >= 0));

          if (IS_NORMAL_FPR(o->reg)) {
            if (IS_XMM(o->reg)) {
              // PAD: probably wrong for > xmm15
              fi->operand_addrs[fi->operand_count] =
                  fr->fprs + fr->fpr_size * (o->reg - X86_REG_XMM0);
              if (fr->fpr_size >= 16) {
                fi->operand_sizes[fi->operand_count] = 16;
		UPDATE_MAX_OPERAND_SIZE(fi->operand_sizes[fi->operand_count]);
              } else {
                ERROR("incompatable fpr size for xmm\n");
                return -1;
              }
            } else if (IS_YMM(o->reg)) {
              // PAD: THIS IS PROBABLY BOGUS - unclear where the signal delivery
              // stashes these contents
              fi->operand_addrs[fi->operand_count] =
                  fr->fprs + fr->fpr_size * (o->reg - X86_REG_YMM0);
              if (fr->fpr_size >= 32) {
                fi->operand_sizes[fi->operand_count] = 32;
		UPDATE_MAX_OPERAND_SIZE(fi->operand_sizes[fi->operand_count]);
              } else {
                ERROR("incompatable fpr size for ymm\n");
                return -1;
              }
              fi->operand_sizes[fi->operand_count] = 32;
            } else if (IS_ZMM(o->reg)) {
              // PAD: THIS IS PROBABLY BOGUS - unclear where the signal delivery
              // stashes these contents
              fi->operand_addrs[fi->operand_count] =
                  fr->fprs + fr->fpr_size * (o->reg - X86_REG_ZMM0);
              if (fr->fpr_size >= 64) {
                fi->operand_sizes[fi->operand_count] = 64;
		UPDATE_MAX_OPERAND_SIZE(fi->operand_sizes[fi->operand_count]);
              } else {
                ERROR("incompatable fpr size for zmm\n");
                return -1;
              }
            } else {
              // PAD: Should catch
              ERROR("unsupported normal fpr\n");
              ASSERT(0);
              return -1;
            }
          } else {
            ERROR("unsupported whacko fpr %s\n", reg_name(o->reg));
            ASSERT(0);
            return -1;
          }
          DEBUG("Mapped FPR %d (%s) to %p (%d)\n", o->reg, reg_name(o->reg),
              fi->operand_addrs[fi->operand_count], fi->operand_sizes[fi->operand_count]);

        } else {  // GPR

          // PAD: if we are handling a GPR, it should really only be because of a
          // float<->int conversion

          // PAD: it is possible the capstone->mcontext mapping is wrong (see
          // capstone_to_mcontext array)

          reg_map_entry_t *m = CAPSTONE_TO_MCONTEXT(o->reg);

          if (MCREG(m) == REG_NONE || MCREG(m) == REG_ZERO) {
            ERROR("No mapping of %s!\n", reg_name(o->reg));
            ASSERT(0);
            return -1;
          }

          // PAD: the following should be sanity checked.   The idea is to
          // generate addresses within the mcontext that correspond to the
          // capstone register
          fi->operand_addrs[fi->operand_count] =
              (void *)(((uint64_t)(&(fr->mcontext->gregs[MCREG(m)]))) + MCOFF(m));
          fi->operand_sizes[fi->operand_count] = MCSIZE(m);
	  UPDATE_MAX_OPERAND_SIZE(fi->operand_sizes[fi->operand_count]);

          DEBUG("Mapped GPR %d (%s) to %p (%d)\n", o->reg, reg_name(o->reg),
              fi->operand_addrs[fi->operand_count], fi->operand_sizes[fi->operand_count]);
        }

        fi->operand_count++;

        break;

      case X86_OP_IMM:
        // PAD: I don't think any of the instructions we will see in SSE2 will
        // include an immediate, so this is here to handle integer instruction
	// immediates, which we will use later, for example, in sequence emulation
	// of moves
        fi->operand_addrs[fi->operand_count] = &o->imm;
        fi->operand_sizes[fi->operand_count] = o->size;
	UPDATE_MAX_OPERAND_SIZE(fi->operand_sizes[fi->operand_count]);
	//	fpvm_decoder_decode_and_print_any_inst(fi->addr, stderr, "immediate using inst: ");
        DEBUG("Mapped immediate %016lx at %p (%u) (pc = %p)\n",
	      o->imm, fi->operand_addrs[fi->operand_count],
	      fi->operand_sizes[fi->operand_count], fi->addr);
        fi->operand_count++;

        break;

        //
        // PAD: I don't know what this operand type in capstone is supposed to
        // represent My guess is that it's an FP immediate in some new encoding
        // (probably after SSE2)
        //    case X86_OP_FP:
        // ERROR("X86_OP_FP\n");
        // ASSERT(0);
        /// return -1;
        /// break;
        //   fi->operand_addrs[fi->operand_count] = &o->imm;
        //   fi->operand_sizes[fi->operand_count] = 8;
        //   DEBUG("Mapped FP immediate %016lx (%lf) at %p
        //   (%u)\n",*(uint64_t*)(double*)&(o->fp),o->fp,
        //   fi->operand_addrs[fi->operand_count],fi->operand_sizes[fi->operand_count]);
        //   fi->operand_count++;

        //   break;

      case X86_OP_MEM: {
        // PAD: We must handle memory operands, and in SSE2, these appear to only
        // be generated in the traditional x86 manner (scaled base index
        // diplacement mode), including the use of rip as the base This code
        // computes the memory address and size.   if it gets it wrong any
        // resulting read/write could corrupt memory
        x86_op_mem *mo = &o->mem;

        DEBUG(
            "Decoding seg=%d (%s) disp=%016lx base=%d (%s) index=%d (%s) "
            "scale=%d\n",
            mo->segment, reg_name(mo->segment), mo->disp, mo->base, reg_name(mo->base), mo->index,
            reg_name(mo->index), mo->scale);

	uint64_t segbase = 0;

        if (mo->segment == X86_REG_FS || mo->segment == X86_REG_GS) {
	  // PAD: This is thread-local storage
	  // Note that all other segment overrides are ignored because
	  // other segments are all base 0 in 64 bit mode.   It could be that
          // the segment descriptor can override the default size, though, but
          // I don't believe that's the case
	  if (syscall(SYS_arch_prctl,
		      mo->segment == X86_REG_FS ?  ARCH_GET_FS: ARCH_GET_GS,
		      &segbase)) {
	    ERROR("cannot read %sbase from kernel\n",
		  mo->segment == X86_REG_FS ?  "fs" : "gs");
	    fpvm_decoder_decode_and_print_any_inst(fi->addr, stderr, "fs/gs-base using inst: ");
	    return -1;
	  }
	  DEBUG("read %sbase from kernel as %016lx\n",
		mo->segment == X86_REG_FS ?  "fs" : "gs",
		segbase);
          return -1;
        }

        // Now we ignore the segment assuming we are in 64 bit mode

        // Now process in the usual order disp(base, index, scale)
        uint64_t addr = segbase + mo->disp;

        if (mo->base != X86_REG_INVALID) {
          //
          // PAD: again these mappings into the mcontext must be correct
          // for this to work.
          // and capstone better not use some out of range psuedoregister
          reg_map_entry_t *m = CAPSTONE_TO_MCONTEXT(mo->base);
          addr += fr->mcontext->gregs[MCREG(m)];
          // in rip-relative mode, rip is the address of the next instruction
          // rip can only used for the base register, which is why this code
          // does not exist elsewhere
          if (MCREG(m) == REG_RIP) {
            addr += fi->length;
          }
        } else {
          // PAD: this is probably OK, it just means there is no base register
        }

        if (mo->index != X86_REG_INVALID) {
          // PAD: again, assuming the mapping to mcontext are correct and no
          // surprise pseudoregister
          reg_map_entry_t *m = CAPSTONE_TO_MCONTEXT(mo->index);
          addr += fr->mcontext->gregs[MCREG(m)] * mo->scale;  // assuming scale is not shift amount
        } else {
          // PAD: this is probably OK, it just means there is no index regiser
        }

        fi->operand_addrs[fi->operand_count] = (void *)addr;
        ;
        // PAD: the following assumes there is no operand size override for
        // integer and it assumes that for FP we are always talking about 8 byte
        // quantities
        fi->operand_sizes[fi->operand_count] = 0;  // to be filled in later
	UPDATE_MAX_OPERAND_SIZE(fi->operand_sizes[fi->operand_count]);

        DEBUG("Mapped memory operand to %p (size TBD)\n",
	      fi->operand_addrs[fi->operand_count]);
        fi->operand_count++;
      } break;

      default:
        ERROR("WTF? \n");
        ASSERT(0);
        return -1;
        break;
    }
  }

  // update memory operand sizes
  for (i = 0; i < fi->operand_count; i++) {
    if (!fi->operand_sizes[i]) {
      fi->operand_sizes[i] = max_operand_size;
      void    *addr=fi->operand_addrs[i];
      uint64_t size=fi->operand_sizes[i];
      switch (size) {
      case 1:
	DEBUG("Mapped memory operand to %p (%lu) data %02x\n",
	      addr,
	      size,
	      *(uint8_t *)addr);
	break;
      case 2:
	DEBUG("Mapped memory operand to %p (%lu) data %04x\n",
	      addr,
	      size,
	      *(uint16_t *)addr);
	break;
      case 4:
	DEBUG("Mapped memory operand to %p (%lu) data %08x (%f)\n",
	      addr,
	      size,
	      *(uint32_t *)addr, *(float *)addr);
	break;
      case 8:
	DEBUG("Mapped memory operand to %p (%lu) data %016lx (%lf)\n",
	      addr,
	      size,
	      *(uint64_t *)addr, *(double *)addr);
	break;
      case 16:
	DEBUG("Mapped memory operand to %p (%lu) data %016lx %016lx (%lf %lf)\n",
	      addr,
	      size,
	      *(uint64_t *)addr, *(uint64_t*)(addr+8),
	      *(double *)addr, *(double*)(addr+8));
	break;
      case 32:
	DEBUG("Mapped memory operand to %p (%lu) data %016lx %016lx %016lx %016lx (%lf %lf %lf %lf)\n",
	      addr,
	      size,
	      *(uint64_t *)addr, *(uint64_t*)(addr+8),
	      *(uint64_t*)(addr+16), *(uint64_t*)(addr+24),
	      *(double *)addr, *(double*)(addr+8),
	      *(double *)(addr+16), *(double*)(addr+24));
      case 64:
	DEBUG("Mapped memory operand to %p (%lu) data %016lx %016lx %016lx %016lx %016lx %016lx %016lx %016lx (%lf %lf %lf %lf %lf %lf %lf %lf)\n",
	      addr,
	      size,
	      *(uint64_t *)addr, *(uint64_t*)(addr+8),
	      *(uint64_t*)(addr+16), *(uint64_t*)(addr+24),
	      *(uint64_t*)(addr+32), *(uint64_t*)(addr+40),
	      *(uint64_t*)(addr+48), *(uint64_t*)(addr+56),
	      *(double *)addr, *(double*)(addr+8),
	      *(double *)(addr+16), *(double*)(addr+24),
	      *(double *)(addr+32), *(double*)(addr+40),
	      *(double *)(addr+48), *(double*)(addr+56));
	break;
      default:
	DEBUG("Mapped memory operand to %p (%lu [weird]) data ?\n",
	      addr,
	      size);
	
	break;
      }
    }
  }
  return 0;
}

static char *group_name(uint8_t group) {
#define DO_GROUP(x) \
  case x:           \
    return #x;      \
    break;

  switch (group) {
    DO_GROUP(X86_GRP_INVALID);
    DO_GROUP(X86_GRP_JUMP);
    DO_GROUP(X86_GRP_CALL);
    DO_GROUP(X86_GRP_RET);
    DO_GROUP(X86_GRP_INT);
    DO_GROUP(X86_GRP_IRET);
    DO_GROUP(X86_GRP_VM);
    DO_GROUP(X86_GRP_3DNOW);
    DO_GROUP(X86_GRP_AES);
    DO_GROUP(X86_GRP_ADX);
    DO_GROUP(X86_GRP_AVX);
    DO_GROUP(X86_GRP_AVX2);
    DO_GROUP(X86_GRP_AVX512);
    DO_GROUP(X86_GRP_BMI);
    DO_GROUP(X86_GRP_BMI2);
    DO_GROUP(X86_GRP_CMOV);
    DO_GROUP(X86_GRP_F16C);
    DO_GROUP(X86_GRP_FMA);
    DO_GROUP(X86_GRP_FMA4);
    DO_GROUP(X86_GRP_FSGSBASE);
    DO_GROUP(X86_GRP_HLE);
    DO_GROUP(X86_GRP_MMX);
    DO_GROUP(X86_GRP_MODE32);
    DO_GROUP(X86_GRP_MODE64);
    DO_GROUP(X86_GRP_RTM);
    DO_GROUP(X86_GRP_SHA);
    DO_GROUP(X86_GRP_SSE1);
    DO_GROUP(X86_GRP_SSE2);
    DO_GROUP(X86_GRP_SSE3);
    DO_GROUP(X86_GRP_SSE41);
    DO_GROUP(X86_GRP_SSE42);
    DO_GROUP(X86_GRP_SSE4A);
    DO_GROUP(X86_GRP_SSSE3);
    DO_GROUP(X86_GRP_PCLMUL);
    DO_GROUP(X86_GRP_XOP);
    DO_GROUP(X86_GRP_CDI);
    DO_GROUP(X86_GRP_ERI);
    DO_GROUP(X86_GRP_TBM);
    DO_GROUP(X86_GRP_16BITMODE);
    DO_GROUP(X86_GRP_NOT64BITMODE);
    DO_GROUP(X86_GRP_SGX);
    DO_GROUP(X86_GRP_DQI);
    DO_GROUP(X86_GRP_BWI);
    DO_GROUP(X86_GRP_PFI);
    DO_GROUP(X86_GRP_VLX);
    DO_GROUP(X86_GRP_SMAP);
    DO_GROUP(X86_GRP_NOVLX);
    default:
      return "UNKNOWN";
  }
}

static char *prefix_name(uint8_t prefix) {
  switch (prefix) {
    case X86_PREFIX_LOCK:
      return "LOCK";
      break;
    case X86_PREFIX_REP:
      return "REP";
      break;
    case X86_PREFIX_REPNE:
      return "REPNE";
      break;
    case X86_PREFIX_CS:
      return "CS";
      break;
    case X86_PREFIX_SS:
      return "SS";
      break;
    case X86_PREFIX_DS:
      return "DS";
      break;
    case X86_PREFIX_ES:
      return "ES";
      break;
    case X86_PREFIX_FS:
      return "FS";
      break;
    case X86_PREFIX_GS:
      return "GS";
      break;
    case X86_PREFIX_OPSIZE:
      return "OPSIZE";
      break;
    case X86_PREFIX_ADDRSIZE:
      return "ADDRSIZE";
      break;
    case 0:
      return "none";
      break;
    default:
      return "UNKNOWN";
      break;
  }
}

static char *reg_name(x86_reg reg) {
#define DO_REG(x) \
  case x:         \
    return #x;    \
    break;
  switch (reg) {
    DO_REG(X86_REG_AH);
    DO_REG(X86_REG_AL);
    DO_REG(X86_REG_AX);
    DO_REG(X86_REG_BH);
    DO_REG(X86_REG_BL);
    DO_REG(X86_REG_BP);
    DO_REG(X86_REG_BPL);
    DO_REG(X86_REG_BX);
    DO_REG(X86_REG_CH);
    DO_REG(X86_REG_CL);
    DO_REG(X86_REG_CS);
    DO_REG(X86_REG_CX);
    DO_REG(X86_REG_DH);
    DO_REG(X86_REG_DI);
    DO_REG(X86_REG_DIL);
    DO_REG(X86_REG_DL);
    DO_REG(X86_REG_DS);
    DO_REG(X86_REG_DX);
    DO_REG(X86_REG_EAX);
    DO_REG(X86_REG_EBP);
    DO_REG(X86_REG_EBX);
    DO_REG(X86_REG_ECX);
    DO_REG(X86_REG_EDI);
    DO_REG(X86_REG_EDX);
    DO_REG(X86_REG_EFLAGS);
    DO_REG(X86_REG_EIP);
    DO_REG(X86_REG_EIZ);
    DO_REG(X86_REG_ES);
    DO_REG(X86_REG_ESI);
    DO_REG(X86_REG_ESP);
    DO_REG(X86_REG_FPSW);
    DO_REG(X86_REG_FS);
    DO_REG(X86_REG_GS);
    DO_REG(X86_REG_IP);
    DO_REG(X86_REG_RAX);
    DO_REG(X86_REG_RBP);
    DO_REG(X86_REG_RBX);
    DO_REG(X86_REG_RCX);
    DO_REG(X86_REG_RDI);
    DO_REG(X86_REG_RDX);
    DO_REG(X86_REG_RIP);
    DO_REG(X86_REG_RIZ);
    DO_REG(X86_REG_RSI);
    DO_REG(X86_REG_RSP);
    DO_REG(X86_REG_SI);
    DO_REG(X86_REG_SIL);
    DO_REG(X86_REG_SP);
    DO_REG(X86_REG_SPL);
    DO_REG(X86_REG_SS);
    DO_REG(X86_REG_CR0);
    DO_REG(X86_REG_CR1);
    DO_REG(X86_REG_CR2);
    DO_REG(X86_REG_CR3);
    DO_REG(X86_REG_CR4);
    DO_REG(X86_REG_CR5);
    DO_REG(X86_REG_CR6);
    DO_REG(X86_REG_CR7);
    DO_REG(X86_REG_CR8);
    DO_REG(X86_REG_CR9);
    DO_REG(X86_REG_CR10);
    DO_REG(X86_REG_CR11);
    DO_REG(X86_REG_CR12);
    DO_REG(X86_REG_CR13);
    DO_REG(X86_REG_CR14);
    DO_REG(X86_REG_CR15);
    DO_REG(X86_REG_DR0);
    DO_REG(X86_REG_DR1);
    DO_REG(X86_REG_DR2);
    DO_REG(X86_REG_DR3);
    DO_REG(X86_REG_DR4);
    DO_REG(X86_REG_DR5);
    DO_REG(X86_REG_DR6);
    DO_REG(X86_REG_DR7);
    DO_REG(X86_REG_FP0);
    DO_REG(X86_REG_FP1);
    DO_REG(X86_REG_FP2);
    DO_REG(X86_REG_FP3);
    DO_REG(X86_REG_FP4);
    DO_REG(X86_REG_FP5);
    DO_REG(X86_REG_FP6);
    DO_REG(X86_REG_FP7);
    DO_REG(X86_REG_K0);
    DO_REG(X86_REG_K1);
    DO_REG(X86_REG_K2);
    DO_REG(X86_REG_K3);
    DO_REG(X86_REG_K4);
    DO_REG(X86_REG_K5);
    DO_REG(X86_REG_K6);
    DO_REG(X86_REG_K7);
    DO_REG(X86_REG_MM0);
    DO_REG(X86_REG_MM1);
    DO_REG(X86_REG_MM2);
    DO_REG(X86_REG_MM3);
    DO_REG(X86_REG_MM4);
    DO_REG(X86_REG_MM5);
    DO_REG(X86_REG_MM6);
    DO_REG(X86_REG_MM7);
    DO_REG(X86_REG_R8);
    DO_REG(X86_REG_R9);
    DO_REG(X86_REG_R10);
    DO_REG(X86_REG_R11);
    DO_REG(X86_REG_R12);
    DO_REG(X86_REG_R13);
    DO_REG(X86_REG_R14);
    DO_REG(X86_REG_R15);
    DO_REG(X86_REG_ST0);
    DO_REG(X86_REG_ST1);
    DO_REG(X86_REG_ST2);
    DO_REG(X86_REG_ST3);
    DO_REG(X86_REG_ST4);
    DO_REG(X86_REG_ST5);
    DO_REG(X86_REG_ST6);
    DO_REG(X86_REG_ST7);
    DO_REG(X86_REG_XMM0);
    DO_REG(X86_REG_XMM1);
    DO_REG(X86_REG_XMM2);
    DO_REG(X86_REG_XMM3);
    DO_REG(X86_REG_XMM4);
    DO_REG(X86_REG_XMM5);
    DO_REG(X86_REG_XMM6);
    DO_REG(X86_REG_XMM7);
    DO_REG(X86_REG_XMM8);
    DO_REG(X86_REG_XMM9);
    DO_REG(X86_REG_XMM10);
    DO_REG(X86_REG_XMM11);
    DO_REG(X86_REG_XMM12);
    DO_REG(X86_REG_XMM13);
    DO_REG(X86_REG_XMM14);
    DO_REG(X86_REG_XMM15);
    DO_REG(X86_REG_XMM16);
    DO_REG(X86_REG_XMM17);
    DO_REG(X86_REG_XMM18);
    DO_REG(X86_REG_XMM19);
    DO_REG(X86_REG_XMM20);
    DO_REG(X86_REG_XMM21);
    DO_REG(X86_REG_XMM22);
    DO_REG(X86_REG_XMM23);
    DO_REG(X86_REG_XMM24);
    DO_REG(X86_REG_XMM25);
    DO_REG(X86_REG_XMM26);
    DO_REG(X86_REG_XMM27);
    DO_REG(X86_REG_XMM28);
    DO_REG(X86_REG_XMM29);
    DO_REG(X86_REG_XMM30);
    DO_REG(X86_REG_XMM31);
    DO_REG(X86_REG_YMM0);
    DO_REG(X86_REG_YMM1);
    DO_REG(X86_REG_YMM2);
    DO_REG(X86_REG_YMM3);
    DO_REG(X86_REG_YMM4);
    DO_REG(X86_REG_YMM5);
    DO_REG(X86_REG_YMM6);
    DO_REG(X86_REG_YMM7);
    DO_REG(X86_REG_YMM8);
    DO_REG(X86_REG_YMM9);
    DO_REG(X86_REG_YMM10);
    DO_REG(X86_REG_YMM11);
    DO_REG(X86_REG_YMM12);
    DO_REG(X86_REG_YMM13);
    DO_REG(X86_REG_YMM14);
    DO_REG(X86_REG_YMM15);
    DO_REG(X86_REG_YMM16);
    DO_REG(X86_REG_YMM17);
    DO_REG(X86_REG_YMM18);
    DO_REG(X86_REG_YMM19);
    DO_REG(X86_REG_YMM20);
    DO_REG(X86_REG_YMM21);
    DO_REG(X86_REG_YMM22);
    DO_REG(X86_REG_YMM23);
    DO_REG(X86_REG_YMM24);
    DO_REG(X86_REG_YMM25);
    DO_REG(X86_REG_YMM26);
    DO_REG(X86_REG_YMM27);
    DO_REG(X86_REG_YMM28);
    DO_REG(X86_REG_YMM29);
    DO_REG(X86_REG_YMM30);
    DO_REG(X86_REG_YMM31);
    DO_REG(X86_REG_ZMM0);
    DO_REG(X86_REG_ZMM1);
    DO_REG(X86_REG_ZMM2);
    DO_REG(X86_REG_ZMM3);
    DO_REG(X86_REG_ZMM4);
    DO_REG(X86_REG_ZMM5);
    DO_REG(X86_REG_ZMM6);
    DO_REG(X86_REG_ZMM7);
    DO_REG(X86_REG_ZMM8);
    DO_REG(X86_REG_ZMM9);
    DO_REG(X86_REG_ZMM10);
    DO_REG(X86_REG_ZMM11);
    DO_REG(X86_REG_ZMM12);
    DO_REG(X86_REG_ZMM13);
    DO_REG(X86_REG_ZMM14);
    DO_REG(X86_REG_ZMM15);
    DO_REG(X86_REG_ZMM16);
    DO_REG(X86_REG_ZMM17);
    DO_REG(X86_REG_ZMM18);
    DO_REG(X86_REG_ZMM19);
    DO_REG(X86_REG_ZMM20);
    DO_REG(X86_REG_ZMM21);
    DO_REG(X86_REG_ZMM22);
    DO_REG(X86_REG_ZMM23);
    DO_REG(X86_REG_ZMM24);
    DO_REG(X86_REG_ZMM25);
    DO_REG(X86_REG_ZMM26);
    DO_REG(X86_REG_ZMM27);
    DO_REG(X86_REG_ZMM28);
    DO_REG(X86_REG_ZMM29);
    DO_REG(X86_REG_ZMM30);
    DO_REG(X86_REG_ZMM31);
    DO_REG(X86_REG_R8B);
    DO_REG(X86_REG_R9B);
    DO_REG(X86_REG_R10B);
    DO_REG(X86_REG_R11B);
    DO_REG(X86_REG_R12B);
    DO_REG(X86_REG_R13B);
    DO_REG(X86_REG_R14B);
    DO_REG(X86_REG_R15B);
    DO_REG(X86_REG_R8D);
    DO_REG(X86_REG_R9D);
    DO_REG(X86_REG_R10D);
    DO_REG(X86_REG_R11D);
    DO_REG(X86_REG_R12D);
    DO_REG(X86_REG_R13D);
    DO_REG(X86_REG_R14D);
    DO_REG(X86_REG_R15D);
    DO_REG(X86_REG_R8W);
    DO_REG(X86_REG_R9W);
    DO_REG(X86_REG_R10W);
    DO_REG(X86_REG_R11W);
    DO_REG(X86_REG_R12W);
    DO_REG(X86_REG_R13W);
    DO_REG(X86_REG_R14W);
    DO_REG(X86_REG_R15W);
    default:
      return "UNKNOWN";
      break;
  }
}

static char *inst_name(x86_insn inst) {
#define DO_INST(x) \
  case x:          \
    return #x;     \
    break;

  switch (inst) {
    DO_INST(X86_INS_AAA);
    DO_INST(X86_INS_AAD);
    DO_INST(X86_INS_AAM);
    DO_INST(X86_INS_AAS);
    DO_INST(X86_INS_FABS);
    DO_INST(X86_INS_ADC);
    DO_INST(X86_INS_ADCX);
    DO_INST(X86_INS_ADD);
    DO_INST(X86_INS_ADDPD);
    DO_INST(X86_INS_ADDPS);
    DO_INST(X86_INS_ADDSD);
    DO_INST(X86_INS_ADDSS);
    DO_INST(X86_INS_ADDSUBPD);
    DO_INST(X86_INS_ADDSUBPS);
    DO_INST(X86_INS_FADD);
    DO_INST(X86_INS_FIADD);
    DO_INST(X86_INS_FADDP);
    DO_INST(X86_INS_ADOX);
    DO_INST(X86_INS_AESDECLAST);
    DO_INST(X86_INS_AESDEC);
    DO_INST(X86_INS_AESENCLAST);
    DO_INST(X86_INS_AESENC);
    DO_INST(X86_INS_AESIMC);
    DO_INST(X86_INS_AESKEYGENASSIST);
    DO_INST(X86_INS_AND);
    DO_INST(X86_INS_ANDN);
    DO_INST(X86_INS_ANDNPD);
    DO_INST(X86_INS_ANDNPS);
    DO_INST(X86_INS_ANDPD);
    DO_INST(X86_INS_ANDPS);
    DO_INST(X86_INS_ARPL);
    DO_INST(X86_INS_BEXTR);
    DO_INST(X86_INS_BLCFILL);
    DO_INST(X86_INS_BLCI);
    DO_INST(X86_INS_BLCIC);
    DO_INST(X86_INS_BLCMSK);
    DO_INST(X86_INS_BLCS);
    DO_INST(X86_INS_BLENDPD);
    DO_INST(X86_INS_BLENDPS);
    DO_INST(X86_INS_BLENDVPD);
    DO_INST(X86_INS_BLENDVPS);
    DO_INST(X86_INS_BLSFILL);
    DO_INST(X86_INS_BLSI);
    DO_INST(X86_INS_BLSIC);
    DO_INST(X86_INS_BLSMSK);
    DO_INST(X86_INS_BLSR);
    DO_INST(X86_INS_BOUND);
    DO_INST(X86_INS_BSF);
    DO_INST(X86_INS_BSR);
    DO_INST(X86_INS_BSWAP);
    DO_INST(X86_INS_BT);
    DO_INST(X86_INS_BTC);
    DO_INST(X86_INS_BTR);
    DO_INST(X86_INS_BTS);
    DO_INST(X86_INS_BZHI);
    DO_INST(X86_INS_CALL);
    DO_INST(X86_INS_CBW);
    DO_INST(X86_INS_CDQ);
    DO_INST(X86_INS_CDQE);
    DO_INST(X86_INS_FCHS);
    DO_INST(X86_INS_CLAC);
    DO_INST(X86_INS_CLC);
    DO_INST(X86_INS_CLD);
    DO_INST(X86_INS_CLFLUSH);
    DO_INST(X86_INS_CLGI);
    DO_INST(X86_INS_CLI);
    DO_INST(X86_INS_CLTS);
    DO_INST(X86_INS_CMC);
    DO_INST(X86_INS_CMOVA);
    DO_INST(X86_INS_CMOVAE);
    DO_INST(X86_INS_CMOVB);
    DO_INST(X86_INS_CMOVBE);
    DO_INST(X86_INS_FCMOVBE);
    DO_INST(X86_INS_FCMOVB);
    DO_INST(X86_INS_CMOVE);
    DO_INST(X86_INS_FCMOVE);
    DO_INST(X86_INS_CMOVG);
    DO_INST(X86_INS_CMOVGE);
    DO_INST(X86_INS_CMOVL);
    DO_INST(X86_INS_CMOVLE);
    DO_INST(X86_INS_FCMOVNBE);
    DO_INST(X86_INS_FCMOVNB);
    DO_INST(X86_INS_CMOVNE);
    DO_INST(X86_INS_FCMOVNE);
    DO_INST(X86_INS_CMOVNO);
    DO_INST(X86_INS_CMOVNP);
    DO_INST(X86_INS_FCMOVNU);
    DO_INST(X86_INS_CMOVNS);
    DO_INST(X86_INS_CMOVO);
    DO_INST(X86_INS_CMOVP);
    DO_INST(X86_INS_FCMOVU);
    DO_INST(X86_INS_CMOVS);
    DO_INST(X86_INS_CMP);
    DO_INST(X86_INS_CMPPD);
    DO_INST(X86_INS_CMPPS);
    DO_INST(X86_INS_CMPSB);
    DO_INST(X86_INS_CMPSD);
    DO_INST(X86_INS_CMPSQ);
    DO_INST(X86_INS_CMPSS);
    DO_INST(X86_INS_CMPSW);
    DO_INST(X86_INS_CMPXCHG16B);
    DO_INST(X86_INS_CMPXCHG);
    DO_INST(X86_INS_CMPXCHG8B);
    DO_INST(X86_INS_COMISD);
    DO_INST(X86_INS_COMISS);
    DO_INST(X86_INS_FCOMP);
    // DO_INST(X86_INS_FCOMPI);
    DO_INST(X86_INS_FCOMI);
    DO_INST(X86_INS_FCOM);
    DO_INST(X86_INS_FCOS);
    DO_INST(X86_INS_CPUID);
    DO_INST(X86_INS_CQO);
    DO_INST(X86_INS_CRC32);
    DO_INST(X86_INS_CVTDQ2PD);
    DO_INST(X86_INS_CVTDQ2PS);
    DO_INST(X86_INS_CVTPD2DQ);
    DO_INST(X86_INS_CVTPD2PS);
    DO_INST(X86_INS_CVTPS2DQ);
    DO_INST(X86_INS_CVTPS2PD);
    DO_INST(X86_INS_CVTSD2SI);
    DO_INST(X86_INS_CVTSD2SS);
    DO_INST(X86_INS_CVTSI2SD);
    DO_INST(X86_INS_CVTSI2SS);
    DO_INST(X86_INS_CVTSS2SD);
    DO_INST(X86_INS_CVTSS2SI);
    DO_INST(X86_INS_CVTTPD2DQ);
    DO_INST(X86_INS_CVTTPS2DQ);
    DO_INST(X86_INS_CVTTSD2SI);
    DO_INST(X86_INS_CVTTSS2SI);
    DO_INST(X86_INS_CWD);
    DO_INST(X86_INS_CWDE);
    DO_INST(X86_INS_DAA);
    DO_INST(X86_INS_DAS);
    DO_INST(X86_INS_DATA16);
    DO_INST(X86_INS_DEC);
    DO_INST(X86_INS_DIV);
    DO_INST(X86_INS_DIVPD);
    DO_INST(X86_INS_DIVPS);
    DO_INST(X86_INS_FDIVR);
    DO_INST(X86_INS_FIDIVR);
    DO_INST(X86_INS_FDIVRP);
    DO_INST(X86_INS_DIVSD);
    DO_INST(X86_INS_DIVSS);
    DO_INST(X86_INS_FDIV);
    DO_INST(X86_INS_FIDIV);
    DO_INST(X86_INS_FDIVP);
    DO_INST(X86_INS_DPPD);
    DO_INST(X86_INS_DPPS);
    DO_INST(X86_INS_RET);
    DO_INST(X86_INS_ENCLS);
    DO_INST(X86_INS_ENCLU);
    DO_INST(X86_INS_ENTER);
    DO_INST(X86_INS_EXTRACTPS);
    DO_INST(X86_INS_EXTRQ);
    DO_INST(X86_INS_F2XM1);
    DO_INST(X86_INS_LCALL);
    DO_INST(X86_INS_LJMP);
    DO_INST(X86_INS_FBLD);
    DO_INST(X86_INS_FBSTP);
    DO_INST(X86_INS_FCOMPP);
    DO_INST(X86_INS_FDECSTP);
    DO_INST(X86_INS_FEMMS);
    DO_INST(X86_INS_FFREE);
    DO_INST(X86_INS_FICOM);
    DO_INST(X86_INS_FICOMP);
    DO_INST(X86_INS_FINCSTP);
    DO_INST(X86_INS_FLDCW);
    DO_INST(X86_INS_FLDENV);
    DO_INST(X86_INS_FLDL2E);
    DO_INST(X86_INS_FLDL2T);
    DO_INST(X86_INS_FLDLG2);
    DO_INST(X86_INS_FLDLN2);
    DO_INST(X86_INS_FLDPI);
    DO_INST(X86_INS_FNCLEX);
    DO_INST(X86_INS_FNINIT);
    DO_INST(X86_INS_FNOP);
    DO_INST(X86_INS_FNSTCW);
    DO_INST(X86_INS_FNSTSW);
    DO_INST(X86_INS_FPATAN);
    DO_INST(X86_INS_FPREM);
    DO_INST(X86_INS_FPREM1);
    DO_INST(X86_INS_FPTAN);
    DO_INST(X86_INS_FRNDINT);
    DO_INST(X86_INS_FRSTOR);
    DO_INST(X86_INS_FNSAVE);
    DO_INST(X86_INS_FSCALE);
    DO_INST(X86_INS_FSETPM);
    DO_INST(X86_INS_FSINCOS);
    DO_INST(X86_INS_FNSTENV);
    DO_INST(X86_INS_FXAM);
    DO_INST(X86_INS_FXRSTOR);
    DO_INST(X86_INS_FXRSTOR64);
    DO_INST(X86_INS_FXSAVE);
    DO_INST(X86_INS_FXSAVE64);
    DO_INST(X86_INS_FXTRACT);
    DO_INST(X86_INS_FYL2X);
    DO_INST(X86_INS_FYL2XP1);
    DO_INST(X86_INS_MOVAPD);
    DO_INST(X86_INS_MOVAPS);
    DO_INST(X86_INS_ORPD);
    DO_INST(X86_INS_ORPS);
    DO_INST(X86_INS_VMOVAPD);
    DO_INST(X86_INS_VMOVAPS);
    DO_INST(X86_INS_XORPD);
    DO_INST(X86_INS_XORPS);
    DO_INST(X86_INS_GETSEC);
    DO_INST(X86_INS_HADDPD);
    DO_INST(X86_INS_HADDPS);
    DO_INST(X86_INS_HLT);
    DO_INST(X86_INS_HSUBPD);
    DO_INST(X86_INS_HSUBPS);
    DO_INST(X86_INS_IDIV);
    DO_INST(X86_INS_FILD);
    DO_INST(X86_INS_IMUL);
    DO_INST(X86_INS_IN);
    DO_INST(X86_INS_INC);
    DO_INST(X86_INS_INSB);
    DO_INST(X86_INS_INSERTPS);
    DO_INST(X86_INS_INSERTQ);
    DO_INST(X86_INS_INSD);
    DO_INST(X86_INS_INSW);
    DO_INST(X86_INS_INT);
    DO_INST(X86_INS_INT1);
    DO_INST(X86_INS_INT3);
    DO_INST(X86_INS_INTO);
    DO_INST(X86_INS_INVD);
    DO_INST(X86_INS_INVEPT);
    DO_INST(X86_INS_INVLPG);
    DO_INST(X86_INS_INVLPGA);
    DO_INST(X86_INS_INVPCID);
    DO_INST(X86_INS_INVVPID);
    DO_INST(X86_INS_IRET);
    DO_INST(X86_INS_IRETD);
    DO_INST(X86_INS_IRETQ);
    DO_INST(X86_INS_FISTTP);
    DO_INST(X86_INS_FIST);
    DO_INST(X86_INS_FISTP);
    DO_INST(X86_INS_UCOMISD);
    DO_INST(X86_INS_UCOMISS);
    // DO_INST(X86_INS_VCMP);
    DO_INST(X86_INS_VCOMISD);
    DO_INST(X86_INS_VCOMISS);
    DO_INST(X86_INS_VCVTSD2SS);
    DO_INST(X86_INS_VCVTSI2SD);
    DO_INST(X86_INS_VCVTSI2SS);
    DO_INST(X86_INS_VCVTSS2SD);
    DO_INST(X86_INS_VCVTTSD2SI);
    DO_INST(X86_INS_VCVTTSD2USI);
    DO_INST(X86_INS_VCVTTSS2SI);
    DO_INST(X86_INS_VCVTTSS2USI);
    DO_INST(X86_INS_VCVTUSI2SD);
    DO_INST(X86_INS_VCVTUSI2SS);
    DO_INST(X86_INS_VUCOMISD);
    DO_INST(X86_INS_VUCOMISS);
    DO_INST(X86_INS_JAE);
    DO_INST(X86_INS_JA);
    DO_INST(X86_INS_JBE);
    DO_INST(X86_INS_JB);
    DO_INST(X86_INS_JCXZ);
    DO_INST(X86_INS_JECXZ);
    DO_INST(X86_INS_JE);
    DO_INST(X86_INS_JGE);
    DO_INST(X86_INS_JG);
    DO_INST(X86_INS_JLE);
    DO_INST(X86_INS_JL);
    DO_INST(X86_INS_JMP);
    DO_INST(X86_INS_JNE);
    DO_INST(X86_INS_JNO);
    DO_INST(X86_INS_JNP);
    DO_INST(X86_INS_JNS);
    DO_INST(X86_INS_JO);
    DO_INST(X86_INS_JP);
    DO_INST(X86_INS_JRCXZ);
    DO_INST(X86_INS_JS);
    DO_INST(X86_INS_KANDB);
    DO_INST(X86_INS_KANDD);
    DO_INST(X86_INS_KANDNB);
    DO_INST(X86_INS_KANDND);
    DO_INST(X86_INS_KANDNQ);
    DO_INST(X86_INS_KANDNW);
    DO_INST(X86_INS_KANDQ);
    DO_INST(X86_INS_KANDW);
    DO_INST(X86_INS_KMOVB);
    DO_INST(X86_INS_KMOVD);
    DO_INST(X86_INS_KMOVQ);
    DO_INST(X86_INS_KMOVW);
    DO_INST(X86_INS_KNOTB);
    DO_INST(X86_INS_KNOTD);
    DO_INST(X86_INS_KNOTQ);
    DO_INST(X86_INS_KNOTW);
    DO_INST(X86_INS_KORB);
    DO_INST(X86_INS_KORD);
    DO_INST(X86_INS_KORQ);
    DO_INST(X86_INS_KORTESTW);
    DO_INST(X86_INS_KORW);
    DO_INST(X86_INS_KSHIFTLW);
    DO_INST(X86_INS_KSHIFTRW);
    DO_INST(X86_INS_KUNPCKBW);
    DO_INST(X86_INS_KXNORB);
    DO_INST(X86_INS_KXNORD);
    DO_INST(X86_INS_KXNORQ);
    DO_INST(X86_INS_KXNORW);
    DO_INST(X86_INS_KXORB);
    DO_INST(X86_INS_KXORD);
    DO_INST(X86_INS_KXORQ);
    DO_INST(X86_INS_KXORW);
    DO_INST(X86_INS_LAHF);
    DO_INST(X86_INS_LAR);
    DO_INST(X86_INS_LDDQU);
    DO_INST(X86_INS_LDMXCSR);
    DO_INST(X86_INS_LDS);
    DO_INST(X86_INS_FLDZ);
    DO_INST(X86_INS_FLD1);
    DO_INST(X86_INS_FLD);
    DO_INST(X86_INS_LEA);
    DO_INST(X86_INS_LEAVE);
    DO_INST(X86_INS_LES);
    DO_INST(X86_INS_LFENCE);
    DO_INST(X86_INS_LFS);
    DO_INST(X86_INS_LGDT);
    DO_INST(X86_INS_LGS);
    DO_INST(X86_INS_LIDT);
    DO_INST(X86_INS_LLDT);
    DO_INST(X86_INS_LMSW);
    DO_INST(X86_INS_OR);
    DO_INST(X86_INS_SUB);
    DO_INST(X86_INS_XOR);
    DO_INST(X86_INS_LODSB);
    DO_INST(X86_INS_LODSD);
    DO_INST(X86_INS_LODSQ);
    DO_INST(X86_INS_LODSW);
    DO_INST(X86_INS_LOOP);
    DO_INST(X86_INS_LOOPE);
    DO_INST(X86_INS_LOOPNE);
    DO_INST(X86_INS_RETF);
    DO_INST(X86_INS_RETFQ);
    DO_INST(X86_INS_LSL);
    DO_INST(X86_INS_LSS);
    DO_INST(X86_INS_LTR);
    DO_INST(X86_INS_XADD);
    DO_INST(X86_INS_LZCNT);
    DO_INST(X86_INS_MASKMOVDQU);
    DO_INST(X86_INS_MAXPD);
    DO_INST(X86_INS_MAXPS);
    DO_INST(X86_INS_MAXSD);
    DO_INST(X86_INS_MAXSS);
    DO_INST(X86_INS_MFENCE);
    DO_INST(X86_INS_MINPD);
    DO_INST(X86_INS_MINPS);
    DO_INST(X86_INS_MINSD);
    DO_INST(X86_INS_MINSS);
    DO_INST(X86_INS_CVTPD2PI);
    DO_INST(X86_INS_CVTPI2PD);
    DO_INST(X86_INS_CVTPI2PS);
    DO_INST(X86_INS_CVTPS2PI);
    DO_INST(X86_INS_CVTTPD2PI);
    DO_INST(X86_INS_CVTTPS2PI);
    DO_INST(X86_INS_EMMS);
    DO_INST(X86_INS_MASKMOVQ);
    DO_INST(X86_INS_MOVD);
    DO_INST(X86_INS_MOVDQ2Q);
    DO_INST(X86_INS_MOVNTQ);
    DO_INST(X86_INS_MOVQ2DQ);
    DO_INST(X86_INS_MOVQ);
    DO_INST(X86_INS_PABSB);
    DO_INST(X86_INS_PABSD);
    DO_INST(X86_INS_PABSW);
    DO_INST(X86_INS_PACKSSDW);
    DO_INST(X86_INS_PACKSSWB);
    DO_INST(X86_INS_PACKUSWB);
    DO_INST(X86_INS_PADDB);
    DO_INST(X86_INS_PADDD);
    DO_INST(X86_INS_PADDQ);
    DO_INST(X86_INS_PADDSB);
    DO_INST(X86_INS_PADDSW);
    DO_INST(X86_INS_PADDUSB);
    DO_INST(X86_INS_PADDUSW);
    DO_INST(X86_INS_PADDW);
    DO_INST(X86_INS_PALIGNR);
    DO_INST(X86_INS_PANDN);
    DO_INST(X86_INS_PAND);
    DO_INST(X86_INS_PAVGB);
    DO_INST(X86_INS_PAVGW);
    DO_INST(X86_INS_PCMPEQB);
    DO_INST(X86_INS_PCMPEQD);
    DO_INST(X86_INS_PCMPEQW);
    DO_INST(X86_INS_PCMPGTB);
    DO_INST(X86_INS_PCMPGTD);
    DO_INST(X86_INS_PCMPGTW);
    DO_INST(X86_INS_PEXTRW);
    DO_INST(X86_INS_PHADDSW);
    DO_INST(X86_INS_PHADDW);
    DO_INST(X86_INS_PHADDD);
    DO_INST(X86_INS_PHSUBD);
    DO_INST(X86_INS_PHSUBSW);
    DO_INST(X86_INS_PHSUBW);
    DO_INST(X86_INS_PINSRW);
    DO_INST(X86_INS_PMADDUBSW);
    DO_INST(X86_INS_PMADDWD);
    DO_INST(X86_INS_PMAXSW);
    DO_INST(X86_INS_PMAXUB);
    DO_INST(X86_INS_PMINSW);
    DO_INST(X86_INS_PMINUB);
    DO_INST(X86_INS_PMOVMSKB);
    DO_INST(X86_INS_PMULHRSW);
    DO_INST(X86_INS_PMULHUW);
    DO_INST(X86_INS_PMULHW);
    DO_INST(X86_INS_PMULLW);
    DO_INST(X86_INS_PMULUDQ);
    DO_INST(X86_INS_POR);
    DO_INST(X86_INS_PSADBW);
    DO_INST(X86_INS_PSHUFB);
    DO_INST(X86_INS_PSHUFW);
    DO_INST(X86_INS_PSIGNB);
    DO_INST(X86_INS_PSIGND);
    DO_INST(X86_INS_PSIGNW);
    DO_INST(X86_INS_PSLLD);
    DO_INST(X86_INS_PSLLQ);
    DO_INST(X86_INS_PSLLW);
    DO_INST(X86_INS_PSRAD);
    DO_INST(X86_INS_PSRAW);
    DO_INST(X86_INS_PSRLD);
    DO_INST(X86_INS_PSRLQ);
    DO_INST(X86_INS_PSRLW);
    DO_INST(X86_INS_PSUBB);
    DO_INST(X86_INS_PSUBD);
    DO_INST(X86_INS_PSUBQ);
    DO_INST(X86_INS_PSUBSB);
    DO_INST(X86_INS_PSUBSW);
    DO_INST(X86_INS_PSUBUSB);
    DO_INST(X86_INS_PSUBUSW);
    DO_INST(X86_INS_PSUBW);
    DO_INST(X86_INS_PUNPCKHBW);
    DO_INST(X86_INS_PUNPCKHDQ);
    DO_INST(X86_INS_PUNPCKHWD);
    DO_INST(X86_INS_PUNPCKLBW);
    DO_INST(X86_INS_PUNPCKLDQ);
    DO_INST(X86_INS_PUNPCKLWD);
    DO_INST(X86_INS_PXOR);
    DO_INST(X86_INS_MONITOR);
    DO_INST(X86_INS_MONTMUL);
    DO_INST(X86_INS_MOV);
    DO_INST(X86_INS_MOVABS);
    DO_INST(X86_INS_MOVBE);
    DO_INST(X86_INS_MOVDDUP);
    DO_INST(X86_INS_MOVDQA);
    DO_INST(X86_INS_MOVDQU);
    DO_INST(X86_INS_MOVHLPS);
    DO_INST(X86_INS_MOVHPD);
    DO_INST(X86_INS_MOVHPS);
    DO_INST(X86_INS_MOVLHPS);
    DO_INST(X86_INS_MOVLPD);
    DO_INST(X86_INS_MOVLPS);
    DO_INST(X86_INS_MOVMSKPD);
    DO_INST(X86_INS_MOVMSKPS);
    DO_INST(X86_INS_MOVNTDQA);
    DO_INST(X86_INS_MOVNTDQ);
    DO_INST(X86_INS_MOVNTI);
    DO_INST(X86_INS_MOVNTPD);
    DO_INST(X86_INS_MOVNTPS);
    DO_INST(X86_INS_MOVNTSD);
    DO_INST(X86_INS_MOVNTSS);
    DO_INST(X86_INS_MOVSB);
    DO_INST(X86_INS_MOVSD);
    DO_INST(X86_INS_MOVSHDUP);
    DO_INST(X86_INS_MOVSLDUP);
    DO_INST(X86_INS_MOVSQ);
    DO_INST(X86_INS_MOVSS);
    DO_INST(X86_INS_MOVSW);
    DO_INST(X86_INS_MOVSX);
    DO_INST(X86_INS_MOVSXD);
    DO_INST(X86_INS_MOVUPD);
    DO_INST(X86_INS_MOVUPS);
    DO_INST(X86_INS_MOVZX);
    DO_INST(X86_INS_MPSADBW);
    DO_INST(X86_INS_MUL);
    DO_INST(X86_INS_MULPD);
    DO_INST(X86_INS_MULPS);
    DO_INST(X86_INS_MULSD);
    DO_INST(X86_INS_MULSS);
    DO_INST(X86_INS_MULX);
    DO_INST(X86_INS_FMUL);
    DO_INST(X86_INS_FIMUL);
    DO_INST(X86_INS_FMULP);
    DO_INST(X86_INS_MWAIT);
    DO_INST(X86_INS_NEG);
    DO_INST(X86_INS_NOP);
    DO_INST(X86_INS_NOT);
    DO_INST(X86_INS_OUT);
    DO_INST(X86_INS_OUTSB);
    DO_INST(X86_INS_OUTSD);
    DO_INST(X86_INS_OUTSW);
    DO_INST(X86_INS_PACKUSDW);
    DO_INST(X86_INS_PAUSE);
    DO_INST(X86_INS_PAVGUSB);
    DO_INST(X86_INS_PBLENDVB);
    DO_INST(X86_INS_PBLENDW);
    DO_INST(X86_INS_PCLMULQDQ);
    DO_INST(X86_INS_PCMPEQQ);
    DO_INST(X86_INS_PCMPESTRI);
    DO_INST(X86_INS_PCMPESTRM);
    DO_INST(X86_INS_PCMPGTQ);
    DO_INST(X86_INS_PCMPISTRI);
    DO_INST(X86_INS_PCMPISTRM);
    DO_INST(X86_INS_PDEP);
    DO_INST(X86_INS_PEXT);
    DO_INST(X86_INS_PEXTRB);
    DO_INST(X86_INS_PEXTRD);
    DO_INST(X86_INS_PEXTRQ);
    DO_INST(X86_INS_PF2ID);
    DO_INST(X86_INS_PF2IW);
    DO_INST(X86_INS_PFACC);
    DO_INST(X86_INS_PFADD);
    DO_INST(X86_INS_PFCMPEQ);
    DO_INST(X86_INS_PFCMPGE);
    DO_INST(X86_INS_PFCMPGT);
    DO_INST(X86_INS_PFMAX);
    DO_INST(X86_INS_PFMIN);
    DO_INST(X86_INS_PFMUL);
    DO_INST(X86_INS_PFNACC);
    DO_INST(X86_INS_PFPNACC);
    DO_INST(X86_INS_PFRCPIT1);
    DO_INST(X86_INS_PFRCPIT2);
    DO_INST(X86_INS_PFRCP);
    DO_INST(X86_INS_PFRSQIT1);
    DO_INST(X86_INS_PFRSQRT);
    DO_INST(X86_INS_PFSUBR);
    DO_INST(X86_INS_PFSUB);
    DO_INST(X86_INS_PHMINPOSUW);
    DO_INST(X86_INS_PI2FD);
    DO_INST(X86_INS_PI2FW);
    DO_INST(X86_INS_PINSRB);
    DO_INST(X86_INS_PINSRD);
    DO_INST(X86_INS_PINSRQ);
    DO_INST(X86_INS_PMAXSB);
    DO_INST(X86_INS_PMAXSD);
    DO_INST(X86_INS_PMAXUD);
    DO_INST(X86_INS_PMAXUW);
    DO_INST(X86_INS_PMINSB);
    DO_INST(X86_INS_PMINSD);
    DO_INST(X86_INS_PMINUD);
    DO_INST(X86_INS_PMINUW);
    DO_INST(X86_INS_PMOVSXBD);
    DO_INST(X86_INS_PMOVSXBQ);
    DO_INST(X86_INS_PMOVSXBW);
    DO_INST(X86_INS_PMOVSXDQ);
    DO_INST(X86_INS_PMOVSXWD);
    DO_INST(X86_INS_PMOVSXWQ);
    DO_INST(X86_INS_PMOVZXBD);
    DO_INST(X86_INS_PMOVZXBQ);
    DO_INST(X86_INS_PMOVZXBW);
    DO_INST(X86_INS_PMOVZXDQ);
    DO_INST(X86_INS_PMOVZXWD);
    DO_INST(X86_INS_PMOVZXWQ);
    DO_INST(X86_INS_PMULDQ);
    DO_INST(X86_INS_PMULHRW);
    DO_INST(X86_INS_PMULLD);
    DO_INST(X86_INS_POP);
    DO_INST(X86_INS_POPAW);
    DO_INST(X86_INS_POPAL);
    DO_INST(X86_INS_POPCNT);
    DO_INST(X86_INS_POPF);
    DO_INST(X86_INS_POPFD);
    DO_INST(X86_INS_POPFQ);
    DO_INST(X86_INS_PREFETCH);
    DO_INST(X86_INS_PREFETCHNTA);
    DO_INST(X86_INS_PREFETCHT0);
    DO_INST(X86_INS_PREFETCHT1);
    DO_INST(X86_INS_PREFETCHT2);
    DO_INST(X86_INS_PREFETCHW);
    DO_INST(X86_INS_PSHUFD);
    DO_INST(X86_INS_PSHUFHW);
    DO_INST(X86_INS_PSHUFLW);
    DO_INST(X86_INS_PSLLDQ);
    DO_INST(X86_INS_PSRLDQ);
    DO_INST(X86_INS_PSWAPD);
    DO_INST(X86_INS_PTEST);
    DO_INST(X86_INS_PUNPCKHQDQ);
    DO_INST(X86_INS_PUNPCKLQDQ);
    DO_INST(X86_INS_PUSH);
    DO_INST(X86_INS_PUSHAW);
    DO_INST(X86_INS_PUSHAL);
    DO_INST(X86_INS_PUSHF);
    DO_INST(X86_INS_PUSHFD);
    DO_INST(X86_INS_PUSHFQ);
    DO_INST(X86_INS_RCL);
    DO_INST(X86_INS_RCPPS);
    DO_INST(X86_INS_RCPSS);
    DO_INST(X86_INS_RCR);
    DO_INST(X86_INS_RDFSBASE);
    DO_INST(X86_INS_RDGSBASE);
    DO_INST(X86_INS_RDMSR);
    DO_INST(X86_INS_RDPMC);
    DO_INST(X86_INS_RDRAND);
    DO_INST(X86_INS_RDSEED);
    DO_INST(X86_INS_RDTSC);
    DO_INST(X86_INS_RDTSCP);
    DO_INST(X86_INS_ROL);
    DO_INST(X86_INS_ROR);
    DO_INST(X86_INS_RORX);
    DO_INST(X86_INS_ROUNDPD);
    DO_INST(X86_INS_ROUNDPS);
    DO_INST(X86_INS_ROUNDSD);
    DO_INST(X86_INS_ROUNDSS);
    DO_INST(X86_INS_RSM);
    DO_INST(X86_INS_RSQRTPS);
    DO_INST(X86_INS_RSQRTSS);
    DO_INST(X86_INS_SAHF);
    DO_INST(X86_INS_SAL);
    DO_INST(X86_INS_SALC);
    DO_INST(X86_INS_SAR);
    DO_INST(X86_INS_SARX);
    DO_INST(X86_INS_SBB);
    DO_INST(X86_INS_SCASB);
    DO_INST(X86_INS_SCASD);
    DO_INST(X86_INS_SCASQ);
    DO_INST(X86_INS_SCASW);
    DO_INST(X86_INS_SETAE);
    DO_INST(X86_INS_SETA);
    DO_INST(X86_INS_SETBE);
    DO_INST(X86_INS_SETB);
    DO_INST(X86_INS_SETE);
    DO_INST(X86_INS_SETGE);
    DO_INST(X86_INS_SETG);
    DO_INST(X86_INS_SETLE);
    DO_INST(X86_INS_SETL);
    DO_INST(X86_INS_SETNE);
    DO_INST(X86_INS_SETNO);
    DO_INST(X86_INS_SETNP);
    DO_INST(X86_INS_SETNS);
    DO_INST(X86_INS_SETO);
    DO_INST(X86_INS_SETP);
    DO_INST(X86_INS_SETS);
    DO_INST(X86_INS_SFENCE);
    DO_INST(X86_INS_SGDT);
    DO_INST(X86_INS_SHA1MSG1);
    DO_INST(X86_INS_SHA1MSG2);
    DO_INST(X86_INS_SHA1NEXTE);
    DO_INST(X86_INS_SHA1RNDS4);
    DO_INST(X86_INS_SHA256MSG1);
    DO_INST(X86_INS_SHA256MSG2);
    DO_INST(X86_INS_SHA256RNDS2);
    DO_INST(X86_INS_SHL);
    DO_INST(X86_INS_SHLD);
    DO_INST(X86_INS_SHLX);
    DO_INST(X86_INS_SHR);
    DO_INST(X86_INS_SHRD);
    DO_INST(X86_INS_SHRX);
    DO_INST(X86_INS_SHUFPD);
    DO_INST(X86_INS_SHUFPS);
    DO_INST(X86_INS_SIDT);
    DO_INST(X86_INS_FSIN);
    DO_INST(X86_INS_SKINIT);
    DO_INST(X86_INS_SLDT);
    DO_INST(X86_INS_SMSW);
    DO_INST(X86_INS_SQRTPD);
    DO_INST(X86_INS_SQRTPS);
    DO_INST(X86_INS_SQRTSD);
    DO_INST(X86_INS_SQRTSS);
    DO_INST(X86_INS_FSQRT);
    DO_INST(X86_INS_STAC);
    DO_INST(X86_INS_STC);
    DO_INST(X86_INS_STD);
    DO_INST(X86_INS_STGI);
    DO_INST(X86_INS_STI);
    DO_INST(X86_INS_STMXCSR);
    DO_INST(X86_INS_STOSB);
    DO_INST(X86_INS_STOSD);
    DO_INST(X86_INS_STOSQ);
    DO_INST(X86_INS_STOSW);
    DO_INST(X86_INS_STR);
    DO_INST(X86_INS_FST);
    DO_INST(X86_INS_FSTP);
    DO_INST(X86_INS_FSTPNCE);
    DO_INST(X86_INS_SUBPD);
    DO_INST(X86_INS_SUBPS);
    DO_INST(X86_INS_FSUBR);
    DO_INST(X86_INS_FISUBR);
    DO_INST(X86_INS_FSUBRP);
    DO_INST(X86_INS_SUBSD);
    DO_INST(X86_INS_SUBSS);
    DO_INST(X86_INS_FSUB);
    DO_INST(X86_INS_FISUB);
    DO_INST(X86_INS_FSUBP);
    DO_INST(X86_INS_SWAPGS);
    DO_INST(X86_INS_SYSCALL);
    DO_INST(X86_INS_SYSENTER);
    DO_INST(X86_INS_SYSEXIT);
    DO_INST(X86_INS_SYSRET);
    DO_INST(X86_INS_T1MSKC);
    DO_INST(X86_INS_TEST);
    DO_INST(X86_INS_UD2);
    DO_INST(X86_INS_FTST);
    DO_INST(X86_INS_TZCNT);
    DO_INST(X86_INS_TZMSK);
    // DO_INST(X86_INS_FUCOMPI);
    DO_INST(X86_INS_FUCOMI);
    DO_INST(X86_INS_FUCOMPP);
    DO_INST(X86_INS_FUCOMP);
    DO_INST(X86_INS_FUCOM);
    DO_INST(X86_INS_UD2B);
    DO_INST(X86_INS_UNPCKHPD);
    DO_INST(X86_INS_UNPCKHPS);
    DO_INST(X86_INS_UNPCKLPD);
    DO_INST(X86_INS_UNPCKLPS);
    DO_INST(X86_INS_VADDPD);
    DO_INST(X86_INS_VADDPS);
    DO_INST(X86_INS_VADDSD);
    DO_INST(X86_INS_VADDSS);
    DO_INST(X86_INS_VADDSUBPD);
    DO_INST(X86_INS_VADDSUBPS);
    DO_INST(X86_INS_VAESDECLAST);
    DO_INST(X86_INS_VAESDEC);
    DO_INST(X86_INS_VAESENCLAST);
    DO_INST(X86_INS_VAESENC);
    DO_INST(X86_INS_VAESIMC);
    DO_INST(X86_INS_VAESKEYGENASSIST);
    DO_INST(X86_INS_VALIGND);
    DO_INST(X86_INS_VALIGNQ);
    DO_INST(X86_INS_VANDNPD);
    DO_INST(X86_INS_VANDNPS);
    DO_INST(X86_INS_VANDPD);
    DO_INST(X86_INS_VANDPS);
    DO_INST(X86_INS_VBLENDMPD);
    DO_INST(X86_INS_VBLENDMPS);
    DO_INST(X86_INS_VBLENDPD);
    DO_INST(X86_INS_VBLENDPS);
    DO_INST(X86_INS_VBLENDVPD);
    DO_INST(X86_INS_VBLENDVPS);
    DO_INST(X86_INS_VBROADCASTF128);
    // DO_INST(X86_INS_VBROADCASTI128);
    DO_INST(X86_INS_VBROADCASTI32X4);
    DO_INST(X86_INS_VBROADCASTI64X4);
    DO_INST(X86_INS_VBROADCASTSD);
    DO_INST(X86_INS_VBROADCASTSS);
    DO_INST(X86_INS_VCMPPD);
    DO_INST(X86_INS_VCMPPS);
    DO_INST(X86_INS_VCMPSD);
    DO_INST(X86_INS_VCMPSS);
    DO_INST(X86_INS_VCVTDQ2PD);
    DO_INST(X86_INS_VCVTDQ2PS);
    DO_INST(X86_INS_VCVTPD2DQX);
    DO_INST(X86_INS_VCVTPD2DQ);
    DO_INST(X86_INS_VCVTPD2PSX);
    DO_INST(X86_INS_VCVTPD2PS);
    DO_INST(X86_INS_VCVTPD2UDQ);
    DO_INST(X86_INS_VCVTPH2PS);
    DO_INST(X86_INS_VCVTPS2DQ);
    DO_INST(X86_INS_VCVTPS2PD);
    DO_INST(X86_INS_VCVTPS2PH);
    DO_INST(X86_INS_VCVTPS2UDQ);
    DO_INST(X86_INS_VCVTSD2SI);
    DO_INST(X86_INS_VCVTSD2USI);
    DO_INST(X86_INS_VCVTSS2SI);
    DO_INST(X86_INS_VCVTSS2USI);
    DO_INST(X86_INS_VCVTTPD2DQX);
    DO_INST(X86_INS_VCVTTPD2DQ);
    DO_INST(X86_INS_VCVTTPD2UDQ);
    DO_INST(X86_INS_VCVTTPS2DQ);
    DO_INST(X86_INS_VCVTTPS2UDQ);
    DO_INST(X86_INS_VCVTUDQ2PD);
    DO_INST(X86_INS_VCVTUDQ2PS);
    DO_INST(X86_INS_VDIVPD);
    DO_INST(X86_INS_VDIVPS);
    DO_INST(X86_INS_VDIVSD);
    DO_INST(X86_INS_VDIVSS);
    DO_INST(X86_INS_VDPPD);
    DO_INST(X86_INS_VDPPS);
    DO_INST(X86_INS_VERR);
    DO_INST(X86_INS_VERW);
    DO_INST(X86_INS_VEXTRACTF128);
    DO_INST(X86_INS_VEXTRACTF32X4);
    DO_INST(X86_INS_VEXTRACTF64X4);
    DO_INST(X86_INS_VEXTRACTI128);
    DO_INST(X86_INS_VEXTRACTI32X4);
    DO_INST(X86_INS_VEXTRACTI64X4);
    DO_INST(X86_INS_VEXTRACTPS);
    DO_INST(X86_INS_VFMADD132PD);
    DO_INST(X86_INS_VFMADD132PS);
    DO_INST(X86_INS_VFMADD213PD);
    DO_INST(X86_INS_VFMADD213PS);
    DO_INST(X86_INS_VFMADDPD);
    DO_INST(X86_INS_VFMADD231PD);
    DO_INST(X86_INS_VFMADDPS);
    DO_INST(X86_INS_VFMADD231PS);
    DO_INST(X86_INS_VFMADDSD);
    DO_INST(X86_INS_VFMADD213SD);
    DO_INST(X86_INS_VFMADD132SD);
    DO_INST(X86_INS_VFMADD231SD);
    DO_INST(X86_INS_VFMADDSS);
    DO_INST(X86_INS_VFMADD213SS);
    DO_INST(X86_INS_VFMADD132SS);
    DO_INST(X86_INS_VFMADD231SS);
    DO_INST(X86_INS_VFMADDSUB132PD);
    DO_INST(X86_INS_VFMADDSUB132PS);
    DO_INST(X86_INS_VFMADDSUB213PD);
    DO_INST(X86_INS_VFMADDSUB213PS);
    DO_INST(X86_INS_VFMADDSUBPD);
    DO_INST(X86_INS_VFMADDSUB231PD);
    DO_INST(X86_INS_VFMADDSUBPS);
    DO_INST(X86_INS_VFMADDSUB231PS);
    DO_INST(X86_INS_VFMSUB132PD);
    DO_INST(X86_INS_VFMSUB132PS);
    DO_INST(X86_INS_VFMSUB213PD);
    DO_INST(X86_INS_VFMSUB213PS);
    DO_INST(X86_INS_VFMSUBADD132PD);
    DO_INST(X86_INS_VFMSUBADD132PS);
    DO_INST(X86_INS_VFMSUBADD213PD);
    DO_INST(X86_INS_VFMSUBADD213PS);
    DO_INST(X86_INS_VFMSUBADDPD);
    DO_INST(X86_INS_VFMSUBADD231PD);
    DO_INST(X86_INS_VFMSUBADDPS);
    DO_INST(X86_INS_VFMSUBADD231PS);
    DO_INST(X86_INS_VFMSUBPD);
    DO_INST(X86_INS_VFMSUB231PD);
    DO_INST(X86_INS_VFMSUBPS);
    DO_INST(X86_INS_VFMSUB231PS);
    DO_INST(X86_INS_VFMSUBSD);
    DO_INST(X86_INS_VFMSUB213SD);
    DO_INST(X86_INS_VFMSUB132SD);
    DO_INST(X86_INS_VFMSUB231SD);
    DO_INST(X86_INS_VFMSUBSS);
    DO_INST(X86_INS_VFMSUB213SS);
    DO_INST(X86_INS_VFMSUB132SS);
    DO_INST(X86_INS_VFMSUB231SS);
    DO_INST(X86_INS_VFNMADD132PD);
    DO_INST(X86_INS_VFNMADD132PS);
    DO_INST(X86_INS_VFNMADD213PD);
    DO_INST(X86_INS_VFNMADD213PS);
    DO_INST(X86_INS_VFNMADDPD);
    DO_INST(X86_INS_VFNMADD231PD);
    DO_INST(X86_INS_VFNMADDPS);
    DO_INST(X86_INS_VFNMADD231PS);
    DO_INST(X86_INS_VFNMADDSD);
    DO_INST(X86_INS_VFNMADD213SD);
    DO_INST(X86_INS_VFNMADD132SD);
    DO_INST(X86_INS_VFNMADD231SD);
    DO_INST(X86_INS_VFNMADDSS);
    DO_INST(X86_INS_VFNMADD213SS);
    DO_INST(X86_INS_VFNMADD132SS);
    DO_INST(X86_INS_VFNMADD231SS);
    DO_INST(X86_INS_VFNMSUB132PD);
    DO_INST(X86_INS_VFNMSUB132PS);
    DO_INST(X86_INS_VFNMSUB213PD);
    DO_INST(X86_INS_VFNMSUB213PS);
    DO_INST(X86_INS_VFNMSUBPD);
    DO_INST(X86_INS_VFNMSUB231PD);
    DO_INST(X86_INS_VFNMSUBPS);
    DO_INST(X86_INS_VFNMSUB231PS);
    DO_INST(X86_INS_VFNMSUBSD);
    DO_INST(X86_INS_VFNMSUB213SD);
    DO_INST(X86_INS_VFNMSUB132SD);
    DO_INST(X86_INS_VFNMSUB231SD);
    DO_INST(X86_INS_VFNMSUBSS);
    DO_INST(X86_INS_VFNMSUB213SS);
    DO_INST(X86_INS_VFNMSUB132SS);
    DO_INST(X86_INS_VFNMSUB231SS);
    DO_INST(X86_INS_VFRCZPD);
    DO_INST(X86_INS_VFRCZPS);
    DO_INST(X86_INS_VFRCZSD);
    DO_INST(X86_INS_VFRCZSS);
    DO_INST(X86_INS_VORPD);
    DO_INST(X86_INS_VORPS);
    DO_INST(X86_INS_VXORPD);
    DO_INST(X86_INS_VXORPS);
    DO_INST(X86_INS_VGATHERDPD);
    DO_INST(X86_INS_VGATHERDPS);
    DO_INST(X86_INS_VGATHERPF0DPD);
    DO_INST(X86_INS_VGATHERPF0DPS);
    DO_INST(X86_INS_VGATHERPF0QPD);
    DO_INST(X86_INS_VGATHERPF0QPS);
    DO_INST(X86_INS_VGATHERPF1DPD);
    DO_INST(X86_INS_VGATHERPF1DPS);
    DO_INST(X86_INS_VGATHERPF1QPD);
    DO_INST(X86_INS_VGATHERPF1QPS);
    DO_INST(X86_INS_VGATHERQPD);
    DO_INST(X86_INS_VGATHERQPS);
    DO_INST(X86_INS_VHADDPD);
    DO_INST(X86_INS_VHADDPS);
    DO_INST(X86_INS_VHSUBPD);
    DO_INST(X86_INS_VHSUBPS);
    DO_INST(X86_INS_VINSERTF128);
    DO_INST(X86_INS_VINSERTF32X4);
    DO_INST(X86_INS_VINSERTF64X4);
    DO_INST(X86_INS_VINSERTI128);
    DO_INST(X86_INS_VINSERTI32X4);
    DO_INST(X86_INS_VINSERTI64X4);
    DO_INST(X86_INS_VINSERTPS);
    DO_INST(X86_INS_VLDDQU);
    DO_INST(X86_INS_VLDMXCSR);
    DO_INST(X86_INS_VMASKMOVDQU);
    DO_INST(X86_INS_VMASKMOVPD);
    DO_INST(X86_INS_VMASKMOVPS);
    DO_INST(X86_INS_VMAXPD);
    DO_INST(X86_INS_VMAXPS);
    DO_INST(X86_INS_VMAXSD);
    DO_INST(X86_INS_VMAXSS);
    DO_INST(X86_INS_VMCALL);
    DO_INST(X86_INS_VMCLEAR);
    DO_INST(X86_INS_VMFUNC);
    DO_INST(X86_INS_VMINPD);
    DO_INST(X86_INS_VMINPS);
    DO_INST(X86_INS_VMINSD);
    DO_INST(X86_INS_VMINSS);
    DO_INST(X86_INS_VMLAUNCH);
    DO_INST(X86_INS_VMLOAD);
    DO_INST(X86_INS_VMMCALL);
    DO_INST(X86_INS_VMOVQ);
    DO_INST(X86_INS_VMOVDDUP);
    DO_INST(X86_INS_VMOVD);
    DO_INST(X86_INS_VMOVDQA32);
    DO_INST(X86_INS_VMOVDQA64);
    DO_INST(X86_INS_VMOVDQA);
    DO_INST(X86_INS_VMOVDQU16);
    DO_INST(X86_INS_VMOVDQU32);
    DO_INST(X86_INS_VMOVDQU64);
    DO_INST(X86_INS_VMOVDQU8);
    DO_INST(X86_INS_VMOVDQU);
    DO_INST(X86_INS_VMOVHLPS);
    DO_INST(X86_INS_VMOVHPD);
    DO_INST(X86_INS_VMOVHPS);
    DO_INST(X86_INS_VMOVLHPS);
    DO_INST(X86_INS_VMOVLPD);
    DO_INST(X86_INS_VMOVLPS);
    DO_INST(X86_INS_VMOVMSKPD);
    DO_INST(X86_INS_VMOVMSKPS);
    DO_INST(X86_INS_VMOVNTDQA);
    DO_INST(X86_INS_VMOVNTDQ);
    DO_INST(X86_INS_VMOVNTPD);
    DO_INST(X86_INS_VMOVNTPS);
    DO_INST(X86_INS_VMOVSD);
    DO_INST(X86_INS_VMOVSHDUP);
    DO_INST(X86_INS_VMOVSLDUP);
    DO_INST(X86_INS_VMOVSS);
    DO_INST(X86_INS_VMOVUPD);
    DO_INST(X86_INS_VMOVUPS);
    DO_INST(X86_INS_VMPSADBW);
    DO_INST(X86_INS_VMPTRLD);
    DO_INST(X86_INS_VMPTRST);
    DO_INST(X86_INS_VMREAD);
    DO_INST(X86_INS_VMRESUME);
    DO_INST(X86_INS_VMRUN);
    DO_INST(X86_INS_VMSAVE);
    DO_INST(X86_INS_VMULPD);
    DO_INST(X86_INS_VMULPS);
    DO_INST(X86_INS_VMULSD);
    DO_INST(X86_INS_VMULSS);
    DO_INST(X86_INS_VMWRITE);
    DO_INST(X86_INS_VMXOFF);
    DO_INST(X86_INS_VMXON);
    DO_INST(X86_INS_VPABSB);
    DO_INST(X86_INS_VPABSD);
    DO_INST(X86_INS_VPABSQ);
    DO_INST(X86_INS_VPABSW);
    DO_INST(X86_INS_VPACKSSDW);
    DO_INST(X86_INS_VPACKSSWB);
    DO_INST(X86_INS_VPACKUSDW);
    DO_INST(X86_INS_VPACKUSWB);
    DO_INST(X86_INS_VPADDB);
    DO_INST(X86_INS_VPADDD);
    DO_INST(X86_INS_VPADDQ);
    DO_INST(X86_INS_VPADDSB);
    DO_INST(X86_INS_VPADDSW);
    DO_INST(X86_INS_VPADDUSB);
    DO_INST(X86_INS_VPADDUSW);
    DO_INST(X86_INS_VPADDW);
    DO_INST(X86_INS_VPALIGNR);
    DO_INST(X86_INS_VPANDD);
    DO_INST(X86_INS_VPANDND);
    DO_INST(X86_INS_VPANDNQ);
    DO_INST(X86_INS_VPANDN);
    DO_INST(X86_INS_VPANDQ);
    DO_INST(X86_INS_VPAND);
    DO_INST(X86_INS_VPAVGB);
    DO_INST(X86_INS_VPAVGW);
    DO_INST(X86_INS_VPBLENDD);
    DO_INST(X86_INS_VPBLENDMD);
    DO_INST(X86_INS_VPBLENDMQ);
    DO_INST(X86_INS_VPBLENDVB);
    DO_INST(X86_INS_VPBLENDW);
    DO_INST(X86_INS_VPBROADCASTB);
    DO_INST(X86_INS_VPBROADCASTD);
    DO_INST(X86_INS_VPBROADCASTMB2Q);
    DO_INST(X86_INS_VPBROADCASTMW2D);
    DO_INST(X86_INS_VPBROADCASTQ);
    DO_INST(X86_INS_VPBROADCASTW);
    DO_INST(X86_INS_VPCLMULQDQ);
    DO_INST(X86_INS_VPCMOV);
    // DO_INST(X86_INS_VPCMP);
    DO_INST(X86_INS_VPCMPD);
    DO_INST(X86_INS_VPCMPEQB);
    DO_INST(X86_INS_VPCMPEQD);
    DO_INST(X86_INS_VPCMPEQQ);
    DO_INST(X86_INS_VPCMPEQW);
    DO_INST(X86_INS_VPCMPESTRI);
    DO_INST(X86_INS_VPCMPESTRM);
    DO_INST(X86_INS_VPCMPGTB);
    DO_INST(X86_INS_VPCMPGTD);
    DO_INST(X86_INS_VPCMPGTQ);
    DO_INST(X86_INS_VPCMPGTW);
    DO_INST(X86_INS_VPCMPISTRI);
    DO_INST(X86_INS_VPCMPISTRM);
    DO_INST(X86_INS_VPCMPQ);
    DO_INST(X86_INS_VPCMPUD);
    DO_INST(X86_INS_VPCMPUQ);
    DO_INST(X86_INS_VPCOMB);
    DO_INST(X86_INS_VPCOMD);
    DO_INST(X86_INS_VPCOMQ);
    DO_INST(X86_INS_VPCOMUB);
    DO_INST(X86_INS_VPCOMUD);
    DO_INST(X86_INS_VPCOMUQ);
    DO_INST(X86_INS_VPCOMUW);
    DO_INST(X86_INS_VPCOMW);
    DO_INST(X86_INS_VPCONFLICTD);
    DO_INST(X86_INS_VPCONFLICTQ);
    DO_INST(X86_INS_VPERM2F128);
    DO_INST(X86_INS_VPERM2I128);
    DO_INST(X86_INS_VPERMD);
    DO_INST(X86_INS_VPERMI2D);
    DO_INST(X86_INS_VPERMI2PD);
    DO_INST(X86_INS_VPERMI2PS);
    DO_INST(X86_INS_VPERMI2Q);
    DO_INST(X86_INS_VPERMIL2PD);
    DO_INST(X86_INS_VPERMIL2PS);
    DO_INST(X86_INS_VPERMILPD);
    DO_INST(X86_INS_VPERMILPS);
    DO_INST(X86_INS_VPERMPD);
    DO_INST(X86_INS_VPERMPS);
    DO_INST(X86_INS_VPERMQ);
    DO_INST(X86_INS_VPERMT2D);
    DO_INST(X86_INS_VPERMT2PD);
    DO_INST(X86_INS_VPERMT2PS);
    DO_INST(X86_INS_VPERMT2Q);
    DO_INST(X86_INS_VPEXTRB);
    DO_INST(X86_INS_VPEXTRD);
    DO_INST(X86_INS_VPEXTRQ);
    DO_INST(X86_INS_VPEXTRW);
    DO_INST(X86_INS_VPGATHERDD);
    DO_INST(X86_INS_VPGATHERDQ);
    DO_INST(X86_INS_VPGATHERQD);
    DO_INST(X86_INS_VPGATHERQQ);
    DO_INST(X86_INS_VPHADDBD);
    DO_INST(X86_INS_VPHADDBQ);
    DO_INST(X86_INS_VPHADDBW);
    DO_INST(X86_INS_VPHADDDQ);
    DO_INST(X86_INS_VPHADDD);
    DO_INST(X86_INS_VPHADDSW);
    DO_INST(X86_INS_VPHADDUBD);
    DO_INST(X86_INS_VPHADDUBQ);
    DO_INST(X86_INS_VPHADDUBW);
    DO_INST(X86_INS_VPHADDUDQ);
    DO_INST(X86_INS_VPHADDUWD);
    DO_INST(X86_INS_VPHADDUWQ);
    DO_INST(X86_INS_VPHADDWD);
    DO_INST(X86_INS_VPHADDWQ);
    DO_INST(X86_INS_VPHADDW);
    DO_INST(X86_INS_VPHMINPOSUW);
    DO_INST(X86_INS_VPHSUBBW);
    DO_INST(X86_INS_VPHSUBDQ);
    DO_INST(X86_INS_VPHSUBD);
    DO_INST(X86_INS_VPHSUBSW);
    DO_INST(X86_INS_VPHSUBWD);
    DO_INST(X86_INS_VPHSUBW);
    DO_INST(X86_INS_VPINSRB);
    DO_INST(X86_INS_VPINSRD);
    DO_INST(X86_INS_VPINSRQ);
    DO_INST(X86_INS_VPINSRW);
    DO_INST(X86_INS_VPLZCNTD);
    DO_INST(X86_INS_VPLZCNTQ);
    DO_INST(X86_INS_VPMACSDD);
    DO_INST(X86_INS_VPMACSDQH);
    DO_INST(X86_INS_VPMACSDQL);
    DO_INST(X86_INS_VPMACSSDD);
    DO_INST(X86_INS_VPMACSSDQH);
    DO_INST(X86_INS_VPMACSSDQL);
    DO_INST(X86_INS_VPMACSSWD);
    DO_INST(X86_INS_VPMACSSWW);
    DO_INST(X86_INS_VPMACSWD);
    DO_INST(X86_INS_VPMACSWW);
    DO_INST(X86_INS_VPMADCSSWD);
    DO_INST(X86_INS_VPMADCSWD);
    DO_INST(X86_INS_VPMADDUBSW);
    DO_INST(X86_INS_VPMADDWD);
    DO_INST(X86_INS_VPMASKMOVD);
    DO_INST(X86_INS_VPMASKMOVQ);
    DO_INST(X86_INS_VPMAXSB);
    DO_INST(X86_INS_VPMAXSD);
    DO_INST(X86_INS_VPMAXSQ);
    DO_INST(X86_INS_VPMAXSW);
    DO_INST(X86_INS_VPMAXUB);
    DO_INST(X86_INS_VPMAXUD);
    DO_INST(X86_INS_VPMAXUQ);
    DO_INST(X86_INS_VPMAXUW);
    DO_INST(X86_INS_VPMINSB);
    DO_INST(X86_INS_VPMINSD);
    DO_INST(X86_INS_VPMINSQ);
    DO_INST(X86_INS_VPMINSW);
    DO_INST(X86_INS_VPMINUB);
    DO_INST(X86_INS_VPMINUD);
    DO_INST(X86_INS_VPMINUQ);
    DO_INST(X86_INS_VPMINUW);
    DO_INST(X86_INS_VPMOVDB);
    DO_INST(X86_INS_VPMOVDW);
    DO_INST(X86_INS_VPMOVMSKB);
    DO_INST(X86_INS_VPMOVQB);
    DO_INST(X86_INS_VPMOVQD);
    DO_INST(X86_INS_VPMOVQW);
    DO_INST(X86_INS_VPMOVSDB);
    DO_INST(X86_INS_VPMOVSDW);
    DO_INST(X86_INS_VPMOVSQB);
    DO_INST(X86_INS_VPMOVSQD);
    DO_INST(X86_INS_VPMOVSQW);
    DO_INST(X86_INS_VPMOVSXBD);
    DO_INST(X86_INS_VPMOVSXBQ);
    DO_INST(X86_INS_VPMOVSXBW);
    DO_INST(X86_INS_VPMOVSXDQ);
    DO_INST(X86_INS_VPMOVSXWD);
    DO_INST(X86_INS_VPMOVSXWQ);
    DO_INST(X86_INS_VPMOVUSDB);
    DO_INST(X86_INS_VPMOVUSDW);
    DO_INST(X86_INS_VPMOVUSQB);
    DO_INST(X86_INS_VPMOVUSQD);
    DO_INST(X86_INS_VPMOVUSQW);
    DO_INST(X86_INS_VPMOVZXBD);
    DO_INST(X86_INS_VPMOVZXBQ);
    DO_INST(X86_INS_VPMOVZXBW);
    DO_INST(X86_INS_VPMOVZXDQ);
    DO_INST(X86_INS_VPMOVZXWD);
    DO_INST(X86_INS_VPMOVZXWQ);
    DO_INST(X86_INS_VPMULDQ);
    DO_INST(X86_INS_VPMULHRSW);
    DO_INST(X86_INS_VPMULHUW);
    DO_INST(X86_INS_VPMULHW);
    DO_INST(X86_INS_VPMULLD);
    DO_INST(X86_INS_VPMULLW);
    DO_INST(X86_INS_VPMULUDQ);
    DO_INST(X86_INS_VPORD);
    DO_INST(X86_INS_VPORQ);
    DO_INST(X86_INS_VPOR);
    DO_INST(X86_INS_VPPERM);
    DO_INST(X86_INS_VPROTB);
    DO_INST(X86_INS_VPROTD);
    DO_INST(X86_INS_VPROTQ);
    DO_INST(X86_INS_VPROTW);
    DO_INST(X86_INS_VPSADBW);
    DO_INST(X86_INS_VPSCATTERDD);
    DO_INST(X86_INS_VPSCATTERDQ);
    DO_INST(X86_INS_VPSCATTERQD);
    DO_INST(X86_INS_VPSCATTERQQ);
    DO_INST(X86_INS_VPSHAB);
    DO_INST(X86_INS_VPSHAD);
    DO_INST(X86_INS_VPSHAQ);
    DO_INST(X86_INS_VPSHAW);
    DO_INST(X86_INS_VPSHLB);
    DO_INST(X86_INS_VPSHLD);
    DO_INST(X86_INS_VPSHLQ);
    DO_INST(X86_INS_VPSHLW);
    DO_INST(X86_INS_VPSHUFB);
    DO_INST(X86_INS_VPSHUFD);
    DO_INST(X86_INS_VPSHUFHW);
    DO_INST(X86_INS_VPSHUFLW);
    DO_INST(X86_INS_VPSIGNB);
    DO_INST(X86_INS_VPSIGND);
    DO_INST(X86_INS_VPSIGNW);
    DO_INST(X86_INS_VPSLLDQ);
    DO_INST(X86_INS_VPSLLD);
    DO_INST(X86_INS_VPSLLQ);
    DO_INST(X86_INS_VPSLLVD);
    DO_INST(X86_INS_VPSLLVQ);
    DO_INST(X86_INS_VPSLLW);
    DO_INST(X86_INS_VPSRAD);
    DO_INST(X86_INS_VPSRAQ);
    DO_INST(X86_INS_VPSRAVD);
    DO_INST(X86_INS_VPSRAVQ);
    DO_INST(X86_INS_VPSRAW);
    DO_INST(X86_INS_VPSRLDQ);
    DO_INST(X86_INS_VPSRLD);
    DO_INST(X86_INS_VPSRLQ);
    DO_INST(X86_INS_VPSRLVD);
    DO_INST(X86_INS_VPSRLVQ);
    DO_INST(X86_INS_VPSRLW);
    DO_INST(X86_INS_VPSUBB);
    DO_INST(X86_INS_VPSUBD);
    DO_INST(X86_INS_VPSUBQ);
    DO_INST(X86_INS_VPSUBSB);
    DO_INST(X86_INS_VPSUBSW);
    DO_INST(X86_INS_VPSUBUSB);
    DO_INST(X86_INS_VPSUBUSW);
    DO_INST(X86_INS_VPSUBW);
    DO_INST(X86_INS_VPTESTMD);
    DO_INST(X86_INS_VPTESTMQ);
    DO_INST(X86_INS_VPTESTNMD);
    DO_INST(X86_INS_VPTESTNMQ);
    DO_INST(X86_INS_VPTEST);
    DO_INST(X86_INS_VPUNPCKHBW);
    DO_INST(X86_INS_VPUNPCKHDQ);
    DO_INST(X86_INS_VPUNPCKHQDQ);
    DO_INST(X86_INS_VPUNPCKHWD);
    DO_INST(X86_INS_VPUNPCKLBW);
    DO_INST(X86_INS_VPUNPCKLDQ);
    DO_INST(X86_INS_VPUNPCKLQDQ);
    DO_INST(X86_INS_VPUNPCKLWD);
    DO_INST(X86_INS_VPXORD);
    DO_INST(X86_INS_VPXORQ);
    DO_INST(X86_INS_VPXOR);
    DO_INST(X86_INS_VRCP14PD);
    DO_INST(X86_INS_VRCP14PS);
    DO_INST(X86_INS_VRCP14SD);
    DO_INST(X86_INS_VRCP14SS);
    DO_INST(X86_INS_VRCP28PD);
    DO_INST(X86_INS_VRCP28PS);
    DO_INST(X86_INS_VRCP28SD);
    DO_INST(X86_INS_VRCP28SS);
    DO_INST(X86_INS_VRCPPS);
    DO_INST(X86_INS_VRCPSS);
    DO_INST(X86_INS_VRNDSCALEPD);
    DO_INST(X86_INS_VRNDSCALEPS);
    DO_INST(X86_INS_VRNDSCALESD);
    DO_INST(X86_INS_VRNDSCALESS);
    DO_INST(X86_INS_VROUNDPD);
    DO_INST(X86_INS_VROUNDPS);
    DO_INST(X86_INS_VROUNDSD);
    DO_INST(X86_INS_VROUNDSS);
    DO_INST(X86_INS_VRSQRT14PD);
    DO_INST(X86_INS_VRSQRT14PS);
    DO_INST(X86_INS_VRSQRT14SD);
    DO_INST(X86_INS_VRSQRT14SS);
    DO_INST(X86_INS_VRSQRT28PD);
    DO_INST(X86_INS_VRSQRT28PS);
    DO_INST(X86_INS_VRSQRT28SD);
    DO_INST(X86_INS_VRSQRT28SS);
    DO_INST(X86_INS_VRSQRTPS);
    DO_INST(X86_INS_VRSQRTSS);
    DO_INST(X86_INS_VSCATTERDPD);
    DO_INST(X86_INS_VSCATTERDPS);
    DO_INST(X86_INS_VSCATTERPF0DPD);
    DO_INST(X86_INS_VSCATTERPF0DPS);
    DO_INST(X86_INS_VSCATTERPF0QPD);
    DO_INST(X86_INS_VSCATTERPF0QPS);
    DO_INST(X86_INS_VSCATTERPF1DPD);
    DO_INST(X86_INS_VSCATTERPF1DPS);
    DO_INST(X86_INS_VSCATTERPF1QPD);
    DO_INST(X86_INS_VSCATTERPF1QPS);
    DO_INST(X86_INS_VSCATTERQPD);
    DO_INST(X86_INS_VSCATTERQPS);
    DO_INST(X86_INS_VSHUFPD);
    DO_INST(X86_INS_VSHUFPS);
    DO_INST(X86_INS_VSQRTPD);
    DO_INST(X86_INS_VSQRTPS);
    DO_INST(X86_INS_VSQRTSD);
    DO_INST(X86_INS_VSQRTSS);
    DO_INST(X86_INS_VSTMXCSR);
    DO_INST(X86_INS_VSUBPD);
    DO_INST(X86_INS_VSUBPS);
    DO_INST(X86_INS_VSUBSD);
    DO_INST(X86_INS_VSUBSS);
    DO_INST(X86_INS_VTESTPD);
    DO_INST(X86_INS_VTESTPS);
    DO_INST(X86_INS_VUNPCKHPD);
    DO_INST(X86_INS_VUNPCKHPS);
    DO_INST(X86_INS_VUNPCKLPD);
    DO_INST(X86_INS_VUNPCKLPS);
    DO_INST(X86_INS_VZEROALL);
    DO_INST(X86_INS_VZEROUPPER);
    DO_INST(X86_INS_WAIT);
    DO_INST(X86_INS_WBINVD);
    DO_INST(X86_INS_WRFSBASE);
    DO_INST(X86_INS_WRGSBASE);
    DO_INST(X86_INS_WRMSR);
    DO_INST(X86_INS_XABORT);
    DO_INST(X86_INS_XACQUIRE);
    DO_INST(X86_INS_XBEGIN);
    DO_INST(X86_INS_XCHG);
    DO_INST(X86_INS_FXCH);
    DO_INST(X86_INS_XCRYPTCBC);
    DO_INST(X86_INS_XCRYPTCFB);
    DO_INST(X86_INS_XCRYPTCTR);
    DO_INST(X86_INS_XCRYPTECB);
    DO_INST(X86_INS_XCRYPTOFB);
    DO_INST(X86_INS_XEND);
    DO_INST(X86_INS_XGETBV);
    DO_INST(X86_INS_XLATB);
    DO_INST(X86_INS_XRELEASE);
    DO_INST(X86_INS_XRSTOR);
    DO_INST(X86_INS_XRSTOR64);
    DO_INST(X86_INS_XSAVE);
    DO_INST(X86_INS_XSAVE64);
    DO_INST(X86_INS_XSAVEOPT);
    DO_INST(X86_INS_XSAVEOPT64);
    DO_INST(X86_INS_XSETBV);
    DO_INST(X86_INS_XSHA1);
    DO_INST(X86_INS_XSHA256);
    DO_INST(X86_INS_XSTORE);
    DO_INST(X86_INS_XTEST);
    default:
      return "UNKNOWN";
      break;
  }
}
