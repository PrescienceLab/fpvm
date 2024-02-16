#define _GNU_SOURCE
#include <dlfcn.h>
#include <signal.h>
#include <ucontext.h>

#include <inttypes.h>
#include <math.h>
#include <stdio.h>
#include <string.h>

#include <ucontext.h>

#include <capstone/capstone.h>

#include <fpvm/decoder.h>
#include <fpvm/emulator.h>
#include <fpvm/fpvm_common.h>

#include <fpvm/fp_ops.h>
#include <fpvm/number_system.h>
#include <fpvm/nan_boxing.h>


static int bad(op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) {
  ERROR("Cannot emulate instruction\n");
  return -1;
}

// generic operation type
typedef int (*op_t)(
    op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4);

typedef op_t op_map_t[2];  // single, double

FPVM_NUMBER_SYSTEM_INIT();

// This is where we would hook in the alternative math library
//
// Interface TBD, put possibly as simple as the one for compiler-based approach

static op_map_t vanilla_op_map[FPVM_OP_LAST] = {
    [0 ... FPVM_OP_LAST - 1] = {bad, bad},
    [FPVM_OP_ADD] = {vanilla_add_float, vanilla_add_double},
    [FPVM_OP_SUB] = {vanilla_sub_float, vanilla_sub_double},
    [FPVM_OP_MUL] = {vanilla_mul_float, vanilla_mul_double},
    [FPVM_OP_DIV] = {vanilla_div_float, vanilla_div_double},
    [FPVM_OP_SQRT] = {vanilla_sqrt_float, vanilla_sqrt_double},
    [FPVM_OP_MADD] = {vanilla_madd_float, vanilla_madd_double},
    [FPVM_OP_NMADD] = {vanilla_nmadd_float, vanilla_nmadd_double},
    [FPVM_OP_MSUB] = {vanilla_msub_float, vanilla_msub_double},
    [FPVM_OP_NMSUB] = {vanilla_nmsub_float, vanilla_nmsub_double},

    [FPVM_OP_MIN] = {vanilla_min_float, vanilla_min_double},
    [FPVM_OP_MAX] = {vanilla_max_float, vanilla_max_double},
    [FPVM_OP_CMP] = {vanilla_cmp_float, vanilla_cmp_double},
    [FPVM_OP_UCMP] = {vanilla_cmp_float, vanilla_cmp_double},

    [FPVM_OP_F2I] = {vanilla_f2i_float, vanilla_f2i_double},  // PROBABLY BOGUS
    [FPVM_OP_F2U] = {vanilla_f2u_float, vanilla_f2u_double},  // PROBABLY BOGUS

    [FPVM_OP_F2IT] = {vanilla_f2i_float, vanilla_f2i_double},  // PROBABLY BOGUS
    [FPVM_OP_F2UT] = {vanilla_f2u_float, vanilla_f2u_double},  // PROBABLY BOGUS

    [FPVM_OP_I2F] = {vanilla_i2f_float, vanilla_i2f_double},  // PROBABLY BOGUS
    [FPVM_OP_U2F] = {vanilla_u2f_float, vanilla_u2f_double},  // PROBABLY BOGUS

    [FPVM_OP_I2FT] = {vanilla_i2f_float, vanilla_i2f_double},  // PROBABLY BOGUS
    [FPVM_OP_U2FT] = {vanilla_u2f_float, vanilla_u2f_double},  // PROBABLY BOGUS

    [FPVM_OP_F2F] = {vanilla_f2f_float, vanilla_f2f_double},

    [FPVM_OP_MOVE] = {vanilla_move_float, vanilla_move_double},
};


int fpvm_emulator_should_emulate_inst(fpvm_inst_t *fi)
{
  // PAD this is bogus - what this should do is interact
  // with a model of the FP that determines if any input
  // is a NaN box or if executing the instruction will
  // produce an exception that FPVM handles.   Instead,
  // it only checks the former.
  if (!fi) {
    DEBUG("should not emulate - no instruction\n");
    return 0;
  } else {

    // always allow moves
    if (fi->common->op_type == FPVM_OP_MOVE) {
      DEBUG("should emulate - is a move\n");
      return 1;
    }
    
    int i,j;
    int count = 1;
    // although src_step is not currently used, it is possible for 
    // the src_step to be different from the dest_step
    int dest_step = 0;
    void *cur;
    
    if (fi->common->op_size != 8) {
      // currently only can nanbox in doubles
      // therefore, this is not an emulatable instruction
      DEBUG("should not emulate - not a double\n");
      return 0;
    }

    if (fi->common->is_vector) {
      count = fi->operand_sizes[0] / fi->common->op_size;
      if (count<2) { 
	DEBUG("may allow emulation for suspicious vector instr count=%d\n", count);
      }
    }

    // simply scan all operands to see if there is a nanbox
    for (i=0;i<fi->operand_count;i++) {
      for (j=0, cur=fi->operand_addrs[i];
	   j<count;
	   j++, cur += dest_step) {
	uint64_t val;
	FPVM_READ_FROM_PTR(val,cur);
	if (ISNAN(val)) {
	  DEBUG("operand[%d][%d] is a NAN - should emulate\n", i,j);
	  return 1;
	}
      }
    }

    // no nans found
    DEBUG("None of the %d x %d operands are a NAN\n", fi->operand_count, count);

    return 0;
  }
}


int fpvm_emulator_emulate_inst(fpvm_inst_t *fi) {
  DEBUG("Emulating instruction\n");

  if (fi->common->has_mask) {
    // ERROR("Cannot handle masks yet\n");
    // ASSERT(0);
    return -1;
  }

  if (fi->common->op_type == FPVM_OP_UNKNOWN) {
    // ERROR("Cannot emulate instruction with unknown op type %d\n", fi->common->op_type);
    // ASSERT(0);
    return -1;
  }

  op_special_t special = {0, 0, 0};
  void *src1 = 0, *src2 = 0, *src3 = 0, *src4 = 0, *dest = 0;
  op_t func = 0;

  int count = 1;
  int dest_step = 0, src_step = 0;

  if (fi->common->is_vector) {
    count = fi->operand_sizes[0] / fi->common->op_size;
    dest_step = fi->common->op_size;
    src_step = fi->common->op_size;  // PAD: these can technically be different - FIX FIX FIX
    // ERROR("Doing vector instruction - this might break!\n");
  }

  switch (fi->common->op_type) {
      // unary
    case FPVM_OP_SQRT:
      dest = fi->operand_addrs[0];
      src1 = fi->operand_addrs[1];

      if (fi->common->op_size == 4) {
        // ERROR("Using vanilla op_map!\n");
        func = vanilla_op_map[fi->common->op_type][0];
      } else if (fi->common->op_size == 8) {
        func = op_map[fi->common->op_type][1];
      } else {
        // ERROR("Cannot handle unary instruction with op_size = %d\n", fi->common->op_size);
        // ASSERT(0);
        return -1;
      }

      break;

      // 2 or 3 operand
    case FPVM_OP_ADD:
    case FPVM_OP_SUB:
    case FPVM_OP_MUL:
    case FPVM_OP_DIV:
    case FPVM_OP_MIN:
    case FPVM_OP_MAX:
      // operands are in the intel order...
      if (fi->operand_count == 2) {
        dest = fi->operand_addrs[0];
        src1 = fi->operand_addrs[0];
        src2 = fi->operand_addrs[1];
      } else if (fi->operand_count == 3) {
        dest = fi->operand_addrs[0];
        src1 = fi->operand_addrs[1];
        src2 = fi->operand_addrs[2];
      } else {
        ERROR("Cannot handle binary instruction with %d operands\n", fi->operand_count);
        ASSERT(0);
        return -1;
      }

      if (fi->common->op_size == 4) {
        ERROR("Using vanilla op map\n");
        func = vanilla_op_map[fi->common->op_type][0];
      } else if (fi->common->op_size == 8) {
        func = op_map[fi->common->op_type][1];
      } else {
        ERROR("Cannot handle binary instruction with op_size = %d\n", fi->common->op_size);
        ASSERT(0);
        return -1;
      }

      break;

    case FPVM_OP_MADD:
    case FPVM_OP_NMADD:
    case FPVM_OP_MSUB:
    case FPVM_OP_NMSUB:
      // PAD: we may need to remap the operand order here for instructions
      // that support this (e.g. madd213 vs madd123)
      if (fi->operand_count == 4) {
        dest = fi->operand_addrs[0];
        src1 = fi->operand_addrs[1];
        src2 = fi->operand_addrs[2];
        src3 = fi->operand_addrs[3];
      } else {
        ERROR("Cannot handle trinary instruction with %d operands\n", fi->operand_count);
        ASSERT(0);
        return -1;
      }

      if (fi->common->op_size == 4) {
        ERROR("Using vanilla op map\n");
        func = vanilla_op_map[fi->common->op_type][0];
      } else if (fi->common->op_size == 8) {
        func = op_map[fi->common->op_type][1];
      } else {
        ERROR("Cannot handle trinary instruction with op_size = %d\n", fi->common->op_size);
        ASSERT(0);
        return -1;
      }

      break;

    case FPVM_OP_F2I:
    case FPVM_OP_F2U:
    case FPVM_OP_F2IT:
    case FPVM_OP_F2UT:

      // PAD: F->I conversion is currently my best guess
      // note that there are various directives that need to be handled, like
      // sizes
      dest = fi->operand_addrs[0];
      src1 = fi->operand_addrs[1];

      // PAD FIX by jiacheng, op count for dest is 0, replace
      // fi->common->dest_size with what we decoded previously

      // original
      // special.byte_width = fi->common->dest_size;
      // after change
      special.byte_width = fi->operand_sizes[0];

      special.truncate = fi->common->op_type == FPVM_OP_F2IT || fi->common->op_type == FPVM_OP_F2UT;

      if (!special.truncate) {
        ERROR("Round to nearest is not handled yet\n");
        exit(1);
      }

      if (fi->common->op_size == 4) {
        ERROR("Using vanilla op map\n");
        func = vanilla_op_map[fi->common->op_type][0];
      } else if (fi->common->op_size == 8) {
        func = op_map[fi->common->op_type][1];
      } else {
        ERROR("Cannot handle f2u or f2i instruction with op_size = %d\n", fi->common->op_size);
        ASSERT(0);
        return -1;
      }

      break;

    case FPVM_OP_I2F:
    case FPVM_OP_U2F:
    case FPVM_OP_I2FT:
    case FPVM_OP_U2FT:

      // PAD: I->F conversion is currently my best guess
      // note that there are various directives that need to be handled, like
      // sizes
      dest = fi->operand_addrs[0];
      src1 = fi->operand_addrs[1];
      special.byte_width = fi->operand_sizes[0];  // fi->common->dest_size;
      special.truncate = fi->common->op_type == FPVM_OP_I2FT || fi->common->op_type == FPVM_OP_U2FT;

      if (fi->common->op_size == 4) {
        ERROR("Using vanilla op map\n");
        func = vanilla_op_map[fi->common->op_type][0];
      } else if (fi->common->op_size == 8) {
        // PAD: IS THIS RIGHT?
        // ERROR("Using vanilla op map for 8 bytes?!\n");
        func = vanilla_op_map[fi->common->op_type][1];  // PAD: why is this vanilla?
      } else {
        ERROR("Cannot handle f2u or f2i instruction with op_size = %d\n", fi->common->op_size);
        ASSERT(0);
        return -1;
      }

      break;

    case FPVM_OP_F2F:

      // PAD: F->F conversion is currently my best guess
      // note that this should be simpler that I<->F

      dest = fi->operand_addrs[0];
      src1 = fi->operand_addrs[1];
      special.byte_width = fi->operand_sizes[0];  // fi->common->dest_size;
      special.truncate = 0;

      if (fi->common->op_size == 4) {
        ERROR("Using vanilla op map\n");
        func = vanilla_op_map[fi->common->op_type][0];
      } else if (fi->common->op_size == 8) {
        func = op_map[fi->common->op_type][1];
      } else {
        ERROR("Cannot handle f2u or f2i instruction with op_size = %d\n", fi->common->op_size);
        ASSERT(0);
        return -1;
      }

      break;

      // 2 operand comparisons
    case FPVM_OP_CMP:
    case FPVM_OP_UCMP:
      if (fi->operand_count == 2) {
        dest = fi->operand_addrs[0];
        src1 = fi->operand_addrs[0];
        src2 = fi->operand_addrs[1];
        // PAD: these comparisons must modify rflags
        special.unordered = fi->common->op_type == FPVM_OP_UCMP;
        special.rflags = fi->side_effect_addrs[0];
      } else {
        ERROR("Cannot handle binary compare with %d operands\n", fi->operand_count);
        ASSERT(0);
        return -1;
      }

      if (fi->common->op_size == 4) {
        ERROR("Using vanilla op map\n");
        func = vanilla_op_map[fi->common->op_type][0];
      } else if (fi->common->op_size == 8) {
        func = op_map[fi->common->op_type][1];
      } else {
        ERROR("Cannot handle binary compare with op_size = %d\n", fi->common->op_size);
        ASSERT(0);
        return -1;
      }

      break;

    case FPVM_OP_MOVE:
      dest = fi->operand_addrs[0];
      src1 = fi->operand_addrs[1];

      // use the vanilla operation in all cases
      // since we do not need to inspect a nanboxed value
      if (fi->common->op_size == 4) {
	DEBUG("handling 4 byte move\n");
        func = vanilla_op_map[fi->common->op_type][0];
      } else if (fi->common->op_size == 8) {
	DEBUG("handling 8 byte move\n");
        func = vanilla_op_map[fi->common->op_type][1];
      } else {
        ERROR("Cannot handle move instruction with op_size = %d\n", fi->common->op_size);
        // ASSERT(0);
        return -1;
      }

      break;
      
    default:
      // ERROR("Cannot handle unknown op type %d\n", fi->common->op_type);
      return -1;
      break;
  }

  if (!func) {
    ERROR("Weird - function lookup not run for op type %d... failing\n", fi->common->op_type);
    ASSERT(0);
    return -1;
  }

  if (func == bad) {
    ERROR("No function available for op type %d ... failing\n", fi->common->op_type);
    ASSERT(0);
    return -1;
  }

  int i;
  int rc = 0;

  // PAD: if count>1, then this is a vector instruction, and we
  // had better have the steps for all operands correct

  for (i = 0; i < count; i++, dest += dest_step, src1 += src_step, src2 += src_step,
      src3 += src_step, src4 += src_step) {
#if CONFIG_DEBUG
    Dl_info dli;
    dladdr(func,&dli);
    char buf[256];
    if (dli.dli_sname) {
      snprintf(buf,255,"%s",dli.dli_sname);
    } else {
      snprintf(buf,255,"%p",func);
    }
    DEBUG(
        "calling %s((byte_width=%d,truncate=%d,unordered=%d), "
        "%p,%p,%p,%p,%p)\n", buf, 
	special.byte_width, special.truncate, special.unordered, dest, src1, src2, src3,
        src4);
#endif
    
    // HACK(NCW): Some instructions have a 16 byte width, but that doesn't make any sense.
    //            If this begins to cause problems, we will have to fix that
    if (special.byte_width > 8) special.byte_width = 8;
    rc |= func(&special, dest, src1, src2, src3, src4);
  }

  DEBUG("Instruction emulation result: %d (%s)\n", rc, rc ? "FAIL" : "success");

  return rc;
}

//
// There are currently two reasons why this function might be invoked:
//
// patched call instruction
//     (ideally only to a function that is not subject to the static analysis)
//  
// patched memory instruction
//     (which may read an FP value that is a nanbox)
//
// For calls, we assume the Sys V cdecl calling convention on x64.
// In this convention, the first 8 FP regs are used for the first 8
// FP values.   For a varargs call, rax stores the number of FP values
// passed via registers.   In both cases, FP regs are
// caller-save/callee-clobber.   Therefore, once we are *at* the call
// we know the compiler/etc must have already saved any FP regs that
// it cannot afford to lose, and will restore them after the function
// returns.   Therefore, we simply do a wholesale translation of
// all the FPregs, converting any nanboxed values to doubles, then
// tell the correctness handler to execute the call.  When we come back
// from the call, the compiler/etc-generated code will restore the FP regs
// restoring any nanboxed values for us.
//
// For memory instructions, we need to emulate the instruction,
// downcasting any source that is a nanboxed value.
// 
//
fpvm_emulator_correctness_response_t
fpvm_emulator_handle_correctness_for_inst(fpvm_inst_t *fi, fpvm_regs_t *fr, int *demotion_count)
{
  DEBUG("handling problematic instruction of type %d (%s)\n", fi->common->op_type,
	fi->common->op_type == FPVM_OP_MOVE ? "MOVE" :
	fi->common->op_type == FPVM_OP_CALL ? "CALL" :
	fi->common->op_type == FPVM_OP_WARN ? "WARN" :
	fi->common->op_type == FPVM_OP_UNKNOWN ? "UNKNOWN" : "**SURPRISE!**");

  *demotion_count=0;
  
  if (fi->common->has_mask) {
    ERROR("Cannot handle masks yet\n");
    return -1;
  }

  if (fi->common->op_type == FPVM_OP_UNKNOWN) {
    ERROR("problematic instruction is of unknown type - simply allowing it to execute, but this is LIKELY BOGUS\n");
    return FPVM_CORRECT_CONTINUE;
  }


  if (fi->common->op_type == FPVM_OP_CALL) {
    DEBUG("handling problematic call instruction\n");
#define _XMM(id) X86_REG_XMM##id
    int allxmm[32] = {_XMM(0), _XMM(1), _XMM(2), _XMM(3), _XMM(4), _XMM(5), _XMM(6), _XMM(7),
        _XMM(8), _XMM(9), _XMM(10), _XMM(11), _XMM(12), _XMM(13), _XMM(14), _XMM(15), _XMM(16),
        _XMM(17), _XMM(18), _XMM(19), _XMM(20), _XMM(21), _XMM(22), _XMM(23), _XMM(24), _XMM(25),
        _XMM(26), _XMM(27), _XMM(28), _XMM(29), _XMM(30), _XMM(31)};
    for (int i = 0; i < 32; i++) {
      uint64_t *xmm_addr = (uint64_t *) (fr->fprs + fr->fpr_size * (allxmm[i] - X86_REG_XMM0));
      // invoke the altmath package to convert numbers back to doubles
      uint64_t old[2] = {xmm_addr[0],xmm_addr[1]};
      restore_xmm(xmm_addr);
      *demotion_count += xmm_addr[0]!= old[0];
      *demotion_count += xmm_addr[1]!= old[1];
    }
    return FPVM_CORRECT_CONTINUE;
  }

  if (fi->common->op_type == FPVM_OP_WARN) { 
    ERROR("instruction decodes to warning type - this is LIKELY BOGUS\n");
    // fall through, treat as move
  }

  // if we got to here, we are dealing with a memory instruction
  DEBUG("handling problematic memory instruction of op type %d\n",fi->common->op_type);
  
  op_special_t special = {0, 0, 0};
  void *src1 = 0, *src2 = 0, *src3 = 0, *src4 = 0, *dest = 0;

  op_t func = 0;
  special.byte_width = fi->operand_sizes[0];  // fi->common->dest_size;
  int count = 1;
  int dest_step = 0, src_step = 0;

  if (fi->common->is_vector) {
    count = fi->operand_sizes[0] / fi->common->op_size;
    dest_step = fi->common->op_size;
    src_step = fi->common->op_size;  // these can technically be different - FIX FIX FIX
    ERROR("problematic instruction is vector instruction - SKIPPING, WHICH IS BOGUS\n");
    // fpvm_decoder_print_inst(fi,stderr);
    // this would normally fall through instead of stopping here
    return FPVM_CORRECT_CONTINUE;
  }

  switch (fi->operand_count) {
  case 1:
    DEBUG("single operand instruction\n");
    dest = fi->operand_addrs[0];
    src1 = fi->operand_addrs[0];
    src1 = fi->operand_addrs[0];
    break;
  case 2:
    DEBUG("two operand instruction\n");
    dest = fi->operand_addrs[0];
    src1 = fi->operand_addrs[0];
    src2 = fi->operand_addrs[1];
    break;
  case 3:
    DEBUG("three operand instruction\n");
    dest = fi->operand_addrs[0];
    src1 = fi->operand_addrs[1];
    src2 = fi->operand_addrs[2];
    break;
  default:
    ERROR("instruction has %d operands - SKIPPING, WHICH IS BOGUS\n",fi->operand_count);
    return FPVM_CORRECT_CONTINUE;
    break;
  }

  // note that the following should consider the different
  // op types, ideally, but wer 
  switch (fi->common->op_type) {
  default:
    DEBUG("default type\n");
    if (fi->common->op_size == 4) {
      DEBUG("restore float\n");
      func = restore_float;
    } else if (fi->common->op_size == 8) {
      DEBUG("restore double\n");
      func = restore_double;
    } else {
      ERROR("cannot handle instruction trapped with op_size = %d mnemonic=%d, continuing, which is BOGUS\n",
            fi->common->op_size, fi->common->op_type);
      return FPVM_CORRECT_CONTINUE;
    }
  }

  if (fi->common->op_type==FPVM_OP_MOVE) {
    if (fi->is_simple_mov) {
      DEBUG("handling simple move\n");
      if (fi->operand_count != 2) {
	ERROR("simple move has %d operands... defaulting to complex move operation (which will demote sources!) BOGUS\n",fi->operand_count);
	goto complex_transforms_sources_yikes;
      }
      if (fi->common->op_size != 8 ) {
	ERROR("simple move with operand size %d ... defaulting to complex move operation (which will demote sources!) BOGUS\n",fi->common->op_size);
	goto complex_transforms_sources_yikes;
      }
      // now we will copy the source instead of using original value
      uint64_t temp = *(uint64_t*)src1;
      uint64_t old = temp;
      // now convert that temp via the alternative math library
      func(0,0,&temp,0,0,0);
      // and write it to the destination
      *(uint64_t*)dest = temp;
      DEBUG("completed emulation of simple mov successully\n");
      if (old!=temp) {
	DEBUG("value actually demoted (%016lx => %016lx)\n",old,temp);
	(*demotion_count)++;
      } else {
	DEBUG("value not demoted (not actually a nanbox)\n");
      }
      return FPVM_CORRECT_SKIP;
    }
  }

 complex_transforms_sources_yikes:
  
  int rc = 0;

#define increment(a, step) (void *)(a ? (char *)a + step : 0)
  
  for (int i = 0; i < count; i++, dest = increment(dest, dest_step),
           src1 = increment(src1, src_step), src2 = increment(src2, src_step),
           src3 = increment(src3, src_step), src4 = increment(src4, src_step)) {
#if CONFIG_DEBUG
    Dl_info dli;
    dladdr(func,&dli);
    char buf[256];
    if (dli.dli_sname) {
      snprintf(buf,255,"%s",dli.dli_sname);
    } else {
      snprintf(buf,255,"%p",func);
    }
    DEBUG(
        "calling %s((byte_width=%d,truncate=%d,unordered=%d), "
        "%p,%p,%p,%p,%p)\n", buf, 
	special.byte_width, special.truncate, special.unordered, dest, src1, src2, src3,
        src4);
#endif
    uint64_t s1[2]={0,0}, s2[2]={0,0}, s3[2]={0,0}, s4[2]={0,0};
    if (src1) { s1[0] = ((uint64_t*)src1)[0]; s1[1] = ((uint64_t*)src1)[1]; } 
    if (src2) { s2[0] = ((uint64_t*)src2)[0]; s2[1] = ((uint64_t*)src2)[1]; } 
    if (src3) { s3[0] = ((uint64_t*)src3)[0]; s3[1] = ((uint64_t*)src3)[1]; } 
    if (src4) { s4[0] = ((uint64_t*)src4)[0]; s4[1] = ((uint64_t*)src4)[1]; } 
    rc |= func(&special, dest, src1, src2, src3, src4);
    if (src1) { *demotion_count += (((uint64_t*)src1)[0]!=s1[0]) + (((uint64_t*)src1)[1]!=s1[1]); }
    if (src2) { *demotion_count += (((uint64_t*)src2)[0]!=s2[0]) + (((uint64_t*)src2)[1]!=s2[1]); }
    if (src3) { *demotion_count += (((uint64_t*)src3)[0]!=s3[0]) + (((uint64_t*)src3)[1]!=s3[1]); }
    if (src4) { *demotion_count += (((uint64_t*)src4)[0]!=s4[0]) + (((uint64_t*)src4)[1]!=s4[1]); }
  }

  DEBUG("Instruction emulation result: %d (%s)\n", rc, rc ? "FAIL" : "success");

  DEBUG("demotions: %d\n",*demotion_count);
  
  if (rc) {
    ERROR("source demotion failed, so trying to execute instruction (BOGUS)\n");
    return FPVM_CORRECT_CONTINUE;
  } else {
    DEBUG("source demotion succeeded, so trying to execute instruction (BOGUS)\n");
    return FPVM_CORRECT_CONTINUE;
  }
}
