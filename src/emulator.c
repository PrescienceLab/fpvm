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
#include <fpvm/gc.h>


#define IS_OUR_NAN(x) fpvm_gc_is_tracked_nan_from_uint(x)



FPVM_NUMBER_SYSTEM_INIT();

// This is where we would hook in the alternative math library
//
// Interface TBD, put possibly as simple as the one for compiler-based approach

op_map_t vanilla_op_map[FPVM_OP_LAST] = {
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

    [FPVM_OP_CMPXX] = {vanilla_cmpxx_float, vanilla_cmpxx_double},

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

static int fpvm_movb(op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) {
  *(uint8_t*)dest = *(uint8_t*)src1;
  return 0;
}

static int fpvm_movs(op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) {
  *(uint16_t*)dest = *(uint16_t*)src1;
  return 0;
}

static int fpvm_movd(op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) {
  *(uint32_t*)dest = *(uint32_t*)src1;
  return 0;
}

static int fpvm_movq(op_special_t *special, void *dest, void *src1, void *src2, void *src3, void *src4) {
  *(uint64_t*)dest = *(uint64_t*)src1;
  return 0;
}


int fpvm_emulator_should_emulate_inst(fpvm_inst_t *fi)
{
  if (CONFIG_DEBUG) {
    fpvm_decoder_decode_and_print_any_inst(fi->addr,stderr,"considering: ");
  }

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

    // always disallow op types related to correctness
    if (fi->common->op_type>=FPVM_OP_WARN) {
      DEBUG("should not emulate - is correctness based\n");
      return 0;
    }

    if (fi->common->op_size != 8) {
      // currently only can nanbox in doubles
      // therefore, this is not an emulatable instruction
      DEBUG("should not emulate - not a double\n");
      return 0;
    }

    int i,j;
    int count = 1;
    // although src_step is not currently used, it is possible for
    // the src_step to be different from the dest_step
    int dest_step = fi->common->op_size;
    void *cur;


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
	if (fpvm_gc_is_tracked_nan_from_ptr(cur)) {
	  DEBUG("should emulate - operand %d[%d] is tracked\n", i,j);
	  return 1;
	} else {
	  DEBUG("operand %d[%d]=%016lx - not tracked\n",i,j,*(uint64_t*)cur);
	}
      }
    }

    // no nans found
    DEBUG("should not emulate - none of the %d x %d (size %u) operands are tracked\n", fi->operand_count, count, fi->common->op_size);

    return 0;
  }
}

static void extend_write(fpvm_inst_t *fi, void *dest, void *src, int ds, int ss)
{
  // write it to the destination based on size
  // note that this ignores sign extension or zero extension
  // for copying small into large integer
  if (ds > ss) {
    int diff = ds - ss;
    if (fi->extend==FPVM_INST_ZERO_EXTEND) {
      //ERROR("zero extend %d to %d\n",ss,ds);
      //fpvm_decoder_decode_and_print_any_inst(fi->addr,stderr,"zero extend for: ");
      memcpy(dest,src,ss);
      memset(dest+ss,0,diff);
    } else if (fi->extend==FPVM_INST_SIGN_EXTEND) {
      int64_t it =
	ss==1 ? *(int8_t *)src :
	ss==2 ? *(int16_t *)src :
	ss==4 ? *(int32_t *)src :
	ss==8 ? *(int64_t *)src : ({ ERROR("bad source size %d in extend_write\n",ss); abort(); 99; });
      memcpy(dest,&it,ds);   // only works for little-endian
      //ERROR("sign extend %d to %d, it=0x%016lx dest=0x%016lx rip=%p\n", ss, ds, it, *(uint64_t*)dest,fi->addr);
      //fpvm_decoder_decode_and_print_any_inst(fi->addr,stderr,"sign extend for: ");
    } else if (fi->extend==FPVM_INST_IGNORE_EXTEND) {
      //ERROR("ignore extend %d to %d\n",ss,ds);
      //fpvm_decoder_decode_and_print_any_inst(fi->addr,stderr,"ignore extend for: ");
      memcpy(dest,src,ss);
    } else {
      ERROR("unknown extension %d from %d to %d\n",fi->extend,ss,ds);
    }
  } else {
    memcpy(dest,src,ds);
  }
}


int fpvm_emulator_emulate_inst(fpvm_inst_t *fi, int *promotions, int *demotions, int *clobbers, perf_stat_t *altmath_perf) {
  if (CONFIG_DEBUG) {
    fpvm_decoder_decode_and_print_any_inst(fi->addr,stderr,"emulating: ");
  }

#if CONFIG_TELEMETRY_PROMOTIONS
  // currently only promotions will be tracked
  *promotions = *demotions = *clobbers = 0;
#endif

  if (fi->common->has_mask) {
    ERROR("Cannot handle masks yet\n");
    // ASSERT(0);
    return -1;
  }

  if (fi->common->op_type == FPVM_OP_UNKNOWN) {
    DEBUG("Cannot emulate instruction with unknown op type %d\n", fi->common->op_type);
    // ASSERT(0);
    return -1;
  }

  op_special_t special = {0, 0, 0, 0};
  void *src1 = 0, *src2 = 0, *src3 = 0, *src4 = 0, *dest = 0;
  op_t func = 0;

  int count = 1;
  int dest_step = 0, src_step = 0;

  if (fi->common->is_vector) {
    count = fi->operand_sizes[0] / fi->common->op_size;
    dest_step = fi->common->op_size;
    src_step = fi->common->op_size;  // PAD: these can technically be different - FIX FIX FIX
    DEBUG("Doing vector instruction - this might break (dest operand size=%lu common operand size=%lu computed count=%lu dest_step=%lu src_step=%lu)\n",fi->operand_sizes[0],fi->common->op_size,count,dest_step,src_step);
  } else {
    dest_step = fi->common->op_size;
    src_step = fi->common->op_size;
    DEBUG("Doing scalar instruction - (common operand size=%lu)\n",fi->common->op_size);
  }

  switch (fi->common->op_type) {
      // unary
    case FPVM_OP_SQRT:
      dest = fi->operand_addrs[0];
      src1 = fi->operand_addrs[1];

      if (fi->common->op_size == 4) {
        // ERROR("Using vanilla op_map for unary instruction %d for float!\n",fi->common->op_type);
        func = vanilla_op_map[fi->common->op_type][0];
      } else if (fi->common->op_size == 8) {
        func = op_map[fi->common->op_type][1];
      } else {
        // ERROR("Cannot handle unary instruction %d with op_size = %d\n", fi->common->op_type, fi->common->op_size);
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
        ERROR("Cannot handle binary instruction %d with %d operands\n", fi->common->op_type, fi->operand_count);
        ASSERT(0);
        return -1;
      }

      if (fi->common->op_size == 4) {
        ERROR("Using vanilla op map for float binop %d\n",fi->common->op_type);
        func = vanilla_op_map[fi->common->op_type][0];
      } else if (fi->common->op_size == 8) {
        func = op_map[fi->common->op_type][1];
      } else {
        ERROR("Cannot handle binary instruction with op_size = %d for float binop %d\n", fi->common->op_size,fi->common->op_type);
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
        ERROR("Cannot handle trinary instruction %d with %d operands\n", fi->common->op_type,fi->operand_count);
        ASSERT(0);
        return -1;
      }

      if (fi->common->op_size == 4) {
        ERROR("Using vanilla op map for trinary instruction %d of floats\n",fi->common->op_type);
        func = vanilla_op_map[fi->common->op_type][0];
      } else if (fi->common->op_size == 8) {
        func = op_map[fi->common->op_type][1];
      } else {
        ERROR("Cannot handle trinary instruction %d with op_size = %d\n",fi->common->op_type,  fi->common->op_size);
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
        ERROR("Round to nearest is not handled yet (instruction %d)\n",fi->common->op_type);
        exit(1);
      }

      if (fi->common->op_size == 4) {
        ERROR("Using vanilla op map for conversion instruction %d\n",fi->common->op_type);
        func = vanilla_op_map[fi->common->op_type][0];
      } else if (fi->common->op_size == 8) {
        func = op_map[fi->common->op_type][1];
      } else {
        ERROR("Cannot handle f2u or f2i instruction %d with op_size = %d\n", fi->common->op_type, fi->common->op_size);
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
        ERROR("Using vanilla op map for conversion instruction %d\n", fi->common->op_type);
        func = vanilla_op_map[fi->common->op_type][0];
      } else if (fi->common->op_size == 8) {
        // PAD: IS THIS RIGHT?
        // ERROR("Using vanilla op map for 8 bytes conversion instruction %d?!\n",fi->common->op_type);
        func = vanilla_op_map[fi->common->op_type][1];  // PAD: why is this vanilla?
      } else {
        ERROR("Cannot handle f2u or f2i instruction %d with op_size = %d\n", fi->common->op_type, fi->common->op_size);
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
        ERROR("Using vanilla op map for conversion instruction %d\n",fi->common->op_type);
        func = vanilla_op_map[fi->common->op_type][0];
      } else if (fi->common->op_size == 8) {
        func = op_map[fi->common->op_type][1];
      } else {
        ERROR("Cannot handle f2u or f2i instruction %d with op_size = %d\n", fi->common->op_type, fi->common->op_size);
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
	// note that CMP and UCMP only differ as to whether
	// a QNAN can cause a fault, so really can be treated identically
	// from FPVM's perspective
        special.unordered = fi->common->op_type == FPVM_OP_UCMP;
        special.rflags = fi->side_effect_addrs[0];
      } else {
        ERROR("Cannot handle binary compare instruction %d with %d operands\n", fi->common->op_type, fi->operand_count);
        ASSERT(0);
        return -1;
      }

      if (fi->common->op_size == 4) {
        ERROR("Using vanilla op map for comparison instruction %d\n",fi->common->op_type);
        func = vanilla_op_map[fi->common->op_type][0];
      } else if (fi->common->op_size == 8) {
        func = op_map[fi->common->op_type][1];
      } else {
        ERROR("Cannot handle binary compare instruction %d with op_size = %d\n", fi->common->op_type, fi->common->op_size);
        ASSERT(0);
        return -1;
      }

      break;

    // 2 operand comparisons that encode a specific compare
    // that writes back to the destination (SSE)
    case FPVM_OP_CMPXX:
      if (fi->operand_count == 2) {
        dest = fi->operand_addrs[0];
        src1 = fi->operand_addrs[0];
        src2 = fi->operand_addrs[1];
        special.compare_type = fi->compare;
      } else if (fi->operand_count == 3) {
        dest = fi->operand_addrs[0];
        src1 = fi->operand_addrs[1];
        src2 = fi->operand_addrs[2];
        special.compare_type = fi->compare;
      } else {
        ERROR("Cannot handle binary compare xx instruction %d with %d operands\n", fi->common->op_type, fi->operand_count);
        ASSERT(0);
        return -1;
      }

      if (fi->common->op_size == 4) {
        ERROR("Using vanilla op map for compare xx instruction %d\n",fi->common->op_type);
        func = vanilla_op_map[fi->common->op_type][0];
      } else if (fi->common->op_size == 8) {
        func = op_map[fi->common->op_type][1];
      } else {
        ERROR("Cannot handle binary compare xx instruction %d with op_size = %d\n", fi->common->op_type, fi->common->op_size);
        ASSERT(0);
        return -1;
      }

      break;

   case FPVM_OP_MOVE:
      dest = fi->operand_addrs[0];
      src1 = fi->operand_addrs[1];

      if (fi->is_gpr_mov) {
        // NOTE: we are overriding this
        dest_step = fi->operand_sizes[0];
        src_step = fi->operand_sizes[1];
        count = 1;
        // printf("yo d:%d s:%d os:%d\n", dest_step, src_step, fi->common->op_size);
        // printf("   s: 0x%zx\n", *(uint64_t*)src1);
        switch (src_step) {
          case 1:
            func = fpvm_movb;
            break;
          case 2:
            func = fpvm_movs;
            break;
          case 4:
            func = fpvm_movd;
            break;
          case 8:
            func = fpvm_movq;
            break;
          default:
            return -1;
        }
        // ...
      } else {
        // use the vanilla operation in all cases
        // since we do not need to inspect a nanboxed value
        if (fi->common->op_size == 4) {
	  DEBUG("handling 4 byte move\n");
          func = vanilla_op_map[fi->common->op_type][0];
        } else if (fi->common->op_size == 8) {
	  DEBUG("handling 8 byte move\n");
          func = vanilla_op_map[fi->common->op_type][1];
        } else {
          DEBUG("Cannot handle move instruction %d with op_size = %d (count=%d)\n", fi->common->op_type, fi->common->op_size,count);
          return -1;
        }
      }

      break;

    default:
      DEBUG("Cannot handle unknown op type %d at %p\n", fi->common->op_type, fi->addr);
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

#if CONFIG_TELEMETRY_PROMOTIONS
  int skip_pro = (src_step!=8) || (dest_step!=8);
#endif

#define FETCH(p,s) ((uint64_t)((p) ? ((s)==8 ?*(uint64_t*)(p) : (s)==4 ? *(uint32_t*)(p) : 0) : 0))


  // PAD: if count>1, then this is a vector instruction, and we
  // had better have the steps for all operands correct

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
        "%d/%d : calling %s((byte_width=%d,truncate=%d,unordered=%d,compare_type=%d), "
        "%p (%016lx),%p (%016lx),%p (%016lx),%p (%016lx),%p (%016lx))\n",
	i+1, count, buf,
	special.byte_width, special.truncate, special.unordered, special.compare_type ,
	dest, FETCH(dest,dest_step),
	src1, FETCH(src1,src_step),
	src2, FETCH(src2,src_step),
	src3, FETCH(src3,src_step),
	src4, FETCH(src4,src_step));
#endif

    // HACK(NCW): Some instructions have a 16 byte width, but that doesn't make any sense.
    //            If this begins to cause problems, we will have to fix that
    if (special.byte_width > 8) {
      DEBUG("forcing byte width to 8 (was %lu)\n", special.byte_width);
      special.byte_width = 8;
    }

#if CONFIG_TELEMETRY_PROMOTIONS
    uint64_t d=0, s1=0, s2=0, s3=0, s4=0;
    if (!skip_pro && dest) { d  = *((uint64_t*)dest); }
    if (!skip_pro && src1) { s1 = *((uint64_t*)src1); }
    if (!skip_pro && src2) { s2 = *((uint64_t*)src2); }
    if (!skip_pro && src3) { s3 = *((uint64_t*)src3); }
    if (!skip_pro && src4) { s4 = *((uint64_t*)src4); }
#endif

    // if (fi->common->op_type==FPVM_OP_MOVE) {
    //   if (fi->is_gpr_mov) {
    //     fprintf(stderr, "\e[31m");
    //   } else {
    //     fprintf(stderr, "\e[32m");
    //   }
    //   fprintf(stderr, "%p ", fi->addr);
    //   fpvm_decoder_decode_and_print_any_inst(fi->addr,stderr,"INS_MOV: ");
    //   fprintf(stderr, "\e[0m");
    // }

#if CONFIG_PERF_STATS
    perf_stat_start(altmath_perf);
#endif
    
    rc |= func(&special, dest, src1, src2, src3, src4);
    if (fi->zero_top_half_of_dest_gpr_suffering) {
      *(uint64_t *)dest &= 0x00000000FFFFFFFFULL;
    }

#if CONFIG_PERF_STATS
    perf_stat_end(altmath_perf);
#endif

    if (fi->common->op_type==FPVM_OP_MOVE && fi->is_simple_mov && fi->is_gpr_mov && src_step != dest_step) {
      uint64_t temp = *(uint64_t*)dest;
      extend_write(fi,dest,&temp, dest_step, src_step);
    }

    // handle CMPXX writeback here because where to place the result depends on
    // the instruction set.  It is only for SSE that we overwrite the
    // whole destination with either an all 1 pattern or an all 0 pattern
    if (fi->common->op_type==FPVM_OP_CMPXX) {
      if (fi->common->op_size==8) {
	*(uint64_t*)dest = !*(uint64_t*)dest - 1UL;
      } else if (fi->common->op_size==4) {
	*(uint32_t*)dest = !*(uint32_t*)dest - 1U;
      }
    }

    DEBUG(
        "after math call, we have (%p (%016lx),%p (%016lx),%p (%016lx),%p (%016lx),%p (%016lx))\n",
	dest, FETCH(dest,dest_step),
	src1, FETCH(src1,src_step),
	src2, FETCH(src2,src_step),
	src3, FETCH(src3,src_step),
	src4, FETCH(src4,src_step));

#if CONFIG_TELEMETRY_PROMOTIONS
    // This assumes all promotions/demotions are done in place
    // it will also likely miscount when src1==dest
    // this could also probably sanity-check to see that there are no differences outside of promotions
    // destination and src1 can be the same, so only consider dest changes
    // only a destination can be clobbered
    if (!skip_pro && dest) {
	if (d  != (*(uint64_t*)dest)) {
	  if ((IS_OUR_NAN(d))) {
	    (*clobbers)++;  DEBUG("destination clobbered\n");
	  }
	  if (fi->common->op_type != FPVM_OP_MOVE) {
	    if (IS_OUR_NAN(*(uint64_t*)dest)) {
	      (*promotions)++; DEBUG("destination promoted\n");
	    } else {
	      (*demotions)++; DEBUG("destination demoted\n");
	    }
	  }
	}
    }
    if (!skip_pro && src1 && src1!=dest) {
      // only handle src1 separately if it is distinct from dest
      // source operands should only be promoted...
      if (s1  != (*(uint64_t*)src1)) {
	if ((IS_OUR_NAN(s1))) {
	  (*clobbers)++;  DEBUG("src1 clobbered\n");
	}
	if (IS_OUR_NAN(*(uint64_t*)src1)) {
	  (*promotions)++; DEBUG("src1 promoted\n");
	} else {
	  (*demotions)++; DEBUG("src1 demoted\n");
	}
      }
    }
    if (!skip_pro && src2) {
      if (s2  != (*(uint64_t*)src2)) {
	if ((IS_OUR_NAN(s2))) {
	  (*clobbers)++;  DEBUG("src2 clobbered\n");
	}
	if (IS_OUR_NAN(*(uint64_t*)src2)) {
	  (*promotions)++; DEBUG("src2 promoted\n");
	} else {
	  (*demotions)++; DEBUG("src2 demoted\n");
	}
      }
    }
    if (!skip_pro && src3) {
      if (s3  != (*(uint64_t*)src3)) {
	if ((IS_OUR_NAN(s3))) {
	  (*clobbers)++;  DEBUG("src3 clobbered\n");
	}
	if (IS_OUR_NAN(*(uint64_t*)src3)) {
	  (*promotions)++; DEBUG("src3 promoted\n");
	} else {
	  (*demotions)++; DEBUG("src3 demoted\n");
	}
      }
    }
    if (!skip_pro && src4) {
      if (s4  != (*(uint64_t*)src4)) {
	if ((IS_OUR_NAN(s4))) {
	  (*clobbers)++;  DEBUG("src4 clobbered\n");
	}
	if (IS_OUR_NAN(*(uint64_t*)src4)) {
	  (*promotions)++; DEBUG("src4 promoted\n");
	} else {
	  (*demotions)++; DEBUG("src4 demoted\n");
	}
      }
    }
#endif
  }

  DEBUG("Instruction emulation result: %d (%s)\n", rc, rc ? "FAIL" : "success");

  return rc;
}

/*
  Note
  SSE:   128 bit regs -  8 regs on 32 bit mode, 16 on 64 bit mode (16 is what we care about)
  SSE2:    SSE + extended use of the 16 128 bit registers
  SSE3:    SSE2 + more extended uses of the 16 128 bit registers
  SSSE3:   SSE3 + more extended uses of the 16 128 bit registers
  SSE4:    SSE3(?) + other more extended uses of the 16 128 bit registers
  AVX:     256 bit registers - 16 of them
  AVX2:    AVX + more extended uses of the 16 256 bit registers
  AVX512:  512 bit registers - 32 of them
  AVC512*: AVX512 + .... = PROFIT!

  run gcc -Q --help=target to see what's enabled by default
  for ubuntu-22 (roquefort), we see SSE2:

  gcc -Q --help=target | grep enabled
  -m128bit-long-double        		[enabled]
  -m64                        		[enabled]
  -m80387                     		[enabled]
  -malign-stringops           		[enabled]
  -mfancy-math-387            		[enabled]
  -mfp-ret-in-387             		[enabled]
  -mfxsr                      		[enabled]
  -mglibc                     		[enabled]
  -mhard-float                		[enabled]
  -mieee-fp                   		[enabled]
  -mlong-double-80            		[enabled]
  -mmmx                       		[enabled]
  -mno-sse4                   		[enabled]
  -mpush-args                 		[enabled]
  -mred-zone                  		[enabled]
  -msse                       		[enabled]
  -msse2                      		[enabled]
  -mstv                       		[enabled]
  -mtls-direct-seg-refs       		[enabled]
  -mvzeroupper                		[enabled]
 */

int NO_TOUCH_FLOAT fpvm_emulator_demote_registers(fpvm_regs_t *fr)
{
  int demotions=0;
  SAFE_DEBUG("handling fp register demotions\n");

  int i;
  uint64_t *addr;
  // just assume SSE2 and demote only 16 128 bit registers => 16*2 values
  for (i = 0, addr = (uint64_t *)fr->fprs;
       i < 16*2;
       i++, addr++) {
    // invoke the altmath package to convert numbers back to doubles
    uint64_t old = *addr;
    restore_double_in_place(addr);
    //    DEBUG("%d %p from %016lx to %016lx (%s)\n",i,addr,old,*addr,*addr!=old ? "DEMOTED" : "not demoted");
#if CONFIG_TELEMETRY_PROMOTIONS
    demotions += *addr!= old;
#endif
    (void)old;
  }
  SAFE_DEBUG("demotions done\n");
  return demotions;
}




//
// There are currently two reasons why this function might be invoked:
//
// patched call instruction
//     (ideally only to a function that is not subject to the static analysis)
//     Note that libm functions are internalized to the alt math package
//     and we should never see them here
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
fpvm_emulator_handle_correctness_for_inst(fpvm_inst_t *fi, fpvm_regs_t *fr, int *demotions)
{

  // fpvm_decoder_decode_and_print_any_inst(fi->addr,stderr,"patch inst: ");
  DEBUG("handling problematic instruction of type %d (%s) is_vector=%d has_mask=%d op_size=%u dest_size=%u\n",
	fi->common->op_type,
	fi->common->op_type == FPVM_OP_MOVE ? "MOVE" :
	fi->common->op_type == FPVM_OP_CALL ? "CALL" :
	fi->common->op_type == FPVM_OP_WARN ? "WARN" :
	fi->common->op_type == FPVM_OP_UNKNOWN ? "UNKNOWN" : "**SURPRISE!**",
	fi->common->is_vector, fi->common->has_mask,
	fi->common->op_size, fi->common->dest_size);

#if CONFIG_TELEMETRY_PROMOTIONS
  *demotions=0;
#endif

  if (fi->common->has_mask) {
    ERROR("Cannot handle masks yet\n");
    fpvm_decoder_decode_and_print_any_inst(fi->addr,stderr,"problematic correctness instr: ");
    return -1;
  }

  if (fi->common->op_type == FPVM_OP_UNKNOWN) {
    ERROR("problematic instruction is of unknown type - simply allowing it to execute, but this is LIKELY BOGUS\n");
    fpvm_decoder_decode_and_print_any_inst(fi->addr,stderr,"problematic correctness instr: ");
    return FPVM_CORRECT_CONTINUE;
  }


  if (fi->common->op_type == FPVM_OP_CALL) {
    DEBUG("handling problematic call instruction (SHOULD NOT HAPPEN WITH WRAPPERS)\n");
    int rc = fpvm_emulator_demote_registers(fr);
    if (rc<0) {
      ERROR("demotions failed\n");
      return FPVM_CORRECT_ERROR;
    }
#if CONFIG_TELEMETRY_PROMOTIONS
    *demotions += rc;
#endif
    return FPVM_CORRECT_CONTINUE;
  }

  if (fi->common->op_type == FPVM_OP_WARN) {
    ERROR("instruction decodes to warning type, treating as move - this is LIKELY BOGUS\n");
    fpvm_decoder_decode_and_print_any_inst(fi->addr,stderr,"problematic correctness instr: ");
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

  if (fi->common->is_vector && fi->common->op_type!=FPVM_OP_MOVE) {
    count = fi->operand_sizes[0] / fi->common->op_size;
    dest_step = fi->common->op_size;
    src_step = fi->common->op_size;  // these can technically be different - FIX FIX FIX
    ERROR("problematic instruction is non-move vector instruction - ATTEMPTING EMULATION, WHICH IS LIKELY BOGUS\n");
    fpvm_decoder_decode_and_print_any_inst(fi->addr,stderr,"problematic correctness instr: ");
    // fpvm_decoder_print_inst(fi,stderr);
    // this would normally fall through instead of stopping here
    //return FPVM_CORRECT_CONTINUE;
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
    fpvm_decoder_decode_and_print_any_inst(fi->addr,stderr,"problematic correctness instr: ");
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
      fpvm_decoder_decode_and_print_any_inst(fi->addr,stderr,"problematic correctness instr: ");
      return FPVM_CORRECT_CONTINUE;
    }
  }

  if (fi->common->op_type==FPVM_OP_MOVE) {
    if (fi->operand_count != 2) {
      ERROR("simple move has %d operands... defaulting to complex move operation (which will demote sources!) BOGUS\n",fi->operand_count);
      fpvm_decoder_decode_and_print_any_inst(fi->addr,stderr,"problematic correctness instr: ");
      goto complex_transforms_sources_yikes;
    }
    int os = fi->common->op_size;
    int ds = fi->common->dest_size;
    int os0 = fi->operand_sizes[0];
    int os1 = fi->operand_sizes[1];
    int count = 1;
    if (fi->common->is_vector) {
      count = os0/os;
    }
    // handle only up to 8 bytes, power of 2
    if (os!=1 && os!=2 && os!=4 && os!=8) {
      ERROR("move with os=%d ds=%d os0=%d os=%d - defaulting to complex move operation (which will demote sources!) BOGUS\n",os,ds,os0,os1);
      fpvm_decoder_decode_and_print_any_inst(fi->addr,stderr,"problematic correctness instr: ");
      goto complex_transforms_sources_yikes;
    }

    DEBUG("handling move count=%d os=%d ds=%d ss=%d os0=%d os1=%d\n",count,os,ds,os0,os1);

    for (int i=0;i<count;i++, dest+=ds, src2+=os) {
      // copy out entire quantity, based on size
      uint64_t temp =
	os==1 ? *(uint8_t*)src2 :
	os==2 ? *(uint16_t*)src2 :
	os==4 ? *(uint32_t*)src2 :
	os==8 ? *(uint64_t*)src2 :
	8; // should not happen

      uint64_t old = temp;
      // now convert that temp via the alternative math library
      func(0,0,&temp,0,0,0);

      extend_write(fi,dest,&temp, ds, os);

#if CONFIG_TELEMETRY_PROMOTIONS
      if (old!=temp) {
	DEBUG("value actually demoted (%016lx => %016lx)\n",old,temp);
	(*demotions)++;
      } else {
	DEBUG("value not demoted (not actually a nanbox)\n");
      }
#endif

      DEBUG("completed emulation of move successully\n");
      return FPVM_CORRECT_SKIP;
    }
  }

 complex_transforms_sources_yikes:

  fpvm_decoder_decode_and_print_any_inst(fi->addr,stderr,"problematic correctness instr (YIKES): ");

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
#if CONFIG_TELEMETRY_PROMOTIONS
    // note that promotion/demotion monitoring here is slightly different
    // than for full instruction emulation.   We only care about demotions,
    // and we are not demoting the destination
    uint64_t d=0, s1=0, s2=0, s3=0, s4=0;
    if (dest) { d  = *((uint64_t*)dest); }
    if (src1) { s1 = *((uint64_t*)src1); }
    if (src2) { s2 = *((uint64_t*)src2); }
    if (src3) { s3 = *((uint64_t*)src3); }
    if (src4) { s4 = *((uint64_t*)src4); }
#endif
    rc |= func(&special, dest, src1, src2, src3, src4);
#if CONFIG_TELEMETRY_PROMOTIONS
    if (dest) { *demotions += *((uint64_t*)dest)!=d;  DEBUG("demoted dest\n"); }
    if (src1 && src1!=dest) { *demotions += *((uint64_t*)src1)!=s1; DEBUG("demoted src1\n"); }
    if (src2) { *demotions += *((uint64_t*)src2)!=s2; DEBUG("demoted src2\n"); }
    if (src3) { *demotions += *((uint64_t*)src3)!=s3; DEBUG("demoted src3\n"); }
    if (src4) { *demotions += *((uint64_t*)src4)!=s4; DEBUG("demoted src4\n"); }
#endif
  }

  DEBUG("Instruction emulation result: %d (%s)\n", rc, rc ? "FAIL" : "success");

#if CONFIG_TELEMETRY_PROMOTIONS
  DEBUG("demotions: %d\n",*demotions);
#endif

  if (rc) {
    ERROR("source demotion failed, so trying to execute instruction (BOGUS)\n");
    return FPVM_CORRECT_CONTINUE;
  } else {
    DEBUG("source demotion succeeded, so trying to execute instruction (BOGUS)\n");
    return FPVM_CORRECT_CONTINUE;
  }
}
