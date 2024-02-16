#ifndef _FPVM_DECODER_
#define _FPVM_DECODER_

typedef enum {
  FPVM_OP_ADD = 0,
  FPVM_OP_SUB,
  FPVM_OP_MUL,
  FPVM_OP_DIV,
  FPVM_OP_MADD,
  FPVM_OP_NMADD,
  FPVM_OP_MSUB,
  FPVM_OP_NMSUB,
  FPVM_OP_SQRT,
  FPVM_OP_MIN,
  FPVM_OP_MAX,

  // comparisons
  FPVM_OP_CMP,    // ordered compare of floats
  FPVM_OP_UCMP,   //  unordered compare of floats
  FPVM_OP_LTCMP,  // write to dest of less than result

  // float to integer conversion
  FPVM_OP_F2I,
  FPVM_OP_F2IT,  // f2i with trunctation
  FPVM_OP_F2U,
  FPVM_OP_F2UT,  // f2u with trunction

  // integer to float conversion
  FPVM_OP_I2F,
  FPVM_OP_I2FT,  // do we need?
  FPVM_OP_U2F,
  FPVM_OP_U2FT,  // do we need?

  // float to float conversion
  FPVM_OP_F2F,

  // moves are handled during sequence emulation to lengthen sequence length
  // they are also needed for correctness traps
  FPVM_OP_MOVE,


  // unknown why we have these - PAD
  // FPVM_OP_SHIFT_RIGHT_BYTE,
  // FPVM_OP_SHIFT_LEFT_BYTE,
  // FPVM_OP_RESTORE,
  // FPVM_OP_ROUND,


  // These are used for correctness traps
  FPVM_OP_WARN,
  FPVM_OP_CALL,
  FPVM_OP_UNKNOWN,

  // marker
  FPVM_OP_LAST,
} fpvm_op_t;

typedef struct {
  fpvm_op_t op_type;
  int is_vector;     // is this a vector FP?
  int has_mask;      // mask vector?
  unsigned op_size;  // size of operands
  // dest_size is currently only meaningful for conversion (F2* or I2* or U2*)
  unsigned dest_size;  // size of destination operands in conversion
} fpvm_inst_common_t;

typedef struct fpvm_inst {
  void *addr;
  unsigned length;

  fpvm_inst_common_t *common;

  int is_simple_mov;

  // note that operands are in the *intel* order, not the at&t order
  unsigned operand_count;
  void *operand_addrs[16];     // where each operand is
  unsigned operand_sizes[16];  // size of operand (different from op_size in the
                               // case of registers)

  uint64_t *side_effect_addrs[8];
  // For x86:
  // 0 => rflags, 1=mxcsr, etc

  void *internal;  // internal representation (e.g., capstone)

  void *link;  // for use by the caller in any way they want (decoder cache, say)

} fpvm_inst_t;

//
// This is intended to be a generic representation of the
// register state captured by the virtual machine on an exit
// FPRs are pulled out separately because it is unclear
// exactly how >SSE2 registers are actually handled.
//
typedef struct fpvm_regs {
  mcontext_t *mcontext;  // including GPRs and FP context like mxcsr

  // fprs points to a blob that contains the
  // register contents in order (xmm0,xmm1, ...)
  // the fpr_size is intended to capture the base size of
  // the registers in the implementation, e.g, 16 bytes, 32 bytes,
  // etc.
  unsigned fpr_size;  // e.g., xmm=16, ymm=32, zmm=64 not provided by kernel
  void *fprs;         // pointer to the xmm/ymm/zmm registers

} fpvm_regs_t;

fpvm_inst_t *fpvm_decoder_decode_inst(void *addr);
int fpvm_decoder_bind_operands(fpvm_inst_t *fi, fpvm_regs_t *fr);
void fpvm_decoder_print_inst(fpvm_inst_t *fi, FILE *out);
// returns negative on failure, otherwise, the length of the instruction
int  fpvm_decoder_decode_and_print_any_inst(void *addr, FILE *out, char *prefix);
void fpvm_decoder_get_inst_str(fpvm_inst_t *fi, char *buf, int len);
void fpvm_decoder_free_inst(fpvm_inst_t *fi);

int fpvm_decoder_init(void);
void fpvm_decoder_deinit(void);

#endif
