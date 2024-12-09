/**
 *
 * Part of FPVM
 *
 * Copyright (c) 2018 Peter A. Dinda - see LICENSE
 *
 * This code does the following:
 *  - provides definitions for FPVM opcode construction
 *  - provides an interface for running a sequence of opcodes.
 */
#define _GNU_SOURCE

#include <fpvm/vm.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include "fpvm/decoder.h"
#include <fpvm/fp_ops.h>

#if CONFIG_ENABLE_NVM_LOGGING
#define VM_FPRINTF fprintf
#else
#define VM_FPRINTF(...) ({})
#endif



// Return the size of the instruction pointed to by `code`
size_t fpvm_opcode_size(uint8_t *code) {
  switch (*code) {
#define OPCODE(opcode)       \
  case fpvm_opcode_##opcode: \
    return 1;
#define OPCODE_ARG(opcode, type) \
  case fpvm_opcode_##opcode:     \
    return 1 + sizeof(type);
#include <fpvm/opcodes.inc>
    default:
      return 0;
  }
}



// Return the name of the instruction pointed to by `code`
const char *fpvm_opcode_name(uint8_t *code) {
  switch (*code) {
#define OPCODE(opcode)       \
  case fpvm_opcode_##opcode: \
    return #opcode;
#define OPCODE_ARG(opcode, type) \
  case fpvm_opcode_##opcode:     \
    return #opcode;
#include <fpvm/opcodes.inc>
    default:
      return "unk";
  }
}


static void _disas_operand_pointer(FILE *stream, void *ptr) {
  Dl_info dli;
  dladdr(ptr, &dli);
  if (dli.dli_sname) {
    VM_FPRINTF(stream, "%s <%p>", dli.dli_sname, ptr);
  } else {
    VM_FPRINTF(stream, "%p", ptr);
  }
}

void fpvm_disas_opcode(FILE *stream, uint8_t *code) {
  const char *op = fpvm_opcode_name(code);
  VM_FPRINTF(stream, "\e[32m");
  VM_FPRINTF(stream, "%-14s ", op);
  VM_FPRINTF(stream, "\e[0m");

  void *arg = code + 1;

  switch (*code) {
#define OPCODE_ARG(opcode, type) \
  case fpvm_opcode_##opcode:     \
    _Generic((type)0, \
    void * : _disas_operand_pointer(stream, *(void**)arg), \
    default : VM_FPRINTF(stream, "$%d", *(type*)arg) \
    );          \
    break;
#include <fpvm/opcodes.inc>
  }

  VM_FPRINTF(stream, "\n");
}


void fpvm_builder_disas(FILE *stream, fpvm_builder_t *b) {
  uint8_t *code = b->code;
  uint64_t codesize = b->size;

  off_t o = 0;

  VM_FPRINTF(stream, "<%p>:\n", code);
  while (o < codesize) {
    if (*code == fpvm_opcode_invalid) {
      VM_FPRINTF(stream, "\n");
      break;
    }
    size_t length = fpvm_opcode_size(code);
    if (length == 0) break;

    VM_FPRINTF(stream, "  %04x | ", o);

    // print out the bytes
    VM_FPRINTF(stream, "\e[90m");
    for (int i = 0; i < 9; i++) {
      if (i < length) {
        VM_FPRINTF(stream, "%02x ", code[i]);
      } else {
        VM_FPRINTF(stream, "   ");
      }
    }
    VM_FPRINTF(stream, "\e[0m");
    VM_FPRINTF(stream, "| ");

    // VM_FPRINTF(stream, "\e[32m");
    fpvm_disas_opcode(stream, code);
    // VM_FPRINTF(stream, "\e[0m");
    o += length;
    code += length;
  }
}


static void fpvm_builder_ensure(fpvm_builder_t *b, unsigned needed) {
  if (b->size <= b->offset + needed) {
    b->size *= 2;
    b->code = realloc(b->code, b->size);
  }
}

void fpvm_builder_init(fpvm_builder_t *b) {
  memset(b, 0, sizeof(*b));
  b->size = 1;
  b->offset = 0;
  b->code = calloc(b->size, 1);
}

void fpvm_builder_deinit(fpvm_builder_t *b) {
  free(b->code);
  memset(b, 0xFA, sizeof(*b));
}



static void fpvm_build_raw8(fpvm_builder_t *b, uint8_t val) {
  // ensure we can push 1 byte
  fpvm_builder_ensure(b, 1);
  b->code[b->offset++] = val;
}

static void fpvm_build_rawv(fpvm_builder_t *b, void *val, int length) {
  // ensure we can push `length` bytes
  fpvm_builder_ensure(b, length);
  memcpy(b->code + b->offset, val, length);
  b->offset += length;
}


#define OPCODE(opcode)                          \
  void fpvm_build_##opcode(fpvm_builder_t *b) { \
    fpvm_build_raw8(b, fpvm_opcode_##opcode);   \
  }

#define OPCODE_ARG(opcode, type)                          \
  void fpvm_build_##opcode(fpvm_builder_t *b, type arg) { \
    fpvm_build_raw8(b, fpvm_opcode_##opcode);             \
    fpvm_build_rawv(b, &arg, sizeof(type));               \
  }
#include <fpvm/opcodes.inc>



int fpvm_vm_compile(fpvm_inst_t *fi) {
#ifdef __amd64__
#include <fpvm/vm.h>
  extern int fpvm_vm_x86_compile(fpvm_inst_t *);
  return fpvm_vm_x86_compile(fi);
#else
#warning "FPVM's vm only works on x86_64 for now..."
  return -1;
#endif  // __amd64__
}

void vm_test_decode(fpvm_inst_t *fi) {
  DEBUG("vm test: %p\n", fi);
  fpvm_decoder_decode_and_print_any_inst(fi->addr, stdout, "vm: ");
}




void fpvm_vm_init(fpvm_vm_t *vm, fpvm_inst_t *inst, fpvm_regs_t *regs) {
  memset(vm, 0, sizeof(fpvm_vm_t));
  vm->mcstate = (uint8_t*)regs->mcontext->gregs;
  vm->fpstate = (uint8_t*)regs->fprs;
  vm->code = ((fpvm_builder_t*)inst->codegen)->code;
  vm->sp = vm->stack;
}

#define PUSH(v) (*(vm->sp++) = (uint64_t)(v))  // Push a value to the stack
#define POP(T) (*(T *)(--vm->sp))              // Pop from the stack as type T
#define PEEK(T) (*(T *)(vm->sp-1))             // Read from the stack as type T
#define O(T) (*(T *)(operand))                 // Read the operand of the instruction as type T

int fpvm_vm_step(fpvm_vm_t *vm) {
  DEBUG("BEFORE:\n");
  fpvm_vm_dump(vm, stderr);

  uint8_t opcode = *vm->code;
  // May or may not be one of these...
  void *operand = vm->code + 1;

  // Move the instruction pointer
  vm->code += fpvm_opcode_size(vm->code);

  op_t op;
  void *src1, *src2, *src3, *dest;
  uint64_t x;
  int error;
  switch (opcode) {
    case fpvm_opcode_fpptr:
      PUSH(vm->fpstate + O(uint16_t));
      break;

    case fpvm_opcode_mcptr:
      PUSH(vm->mcstate + O(uint16_t));
      break;

    case fpvm_opcode_dup:
      x = PEEK(uint64_t);
      PUSH(x);
      break;

    case fpvm_opcode_done:
      // no more work to do
      return 0;
      break;

    case fpvm_opcode_ld64:
      x = *POP(uint64_t*);
      PUSH(x);
      break;

  case fpvm_opcode_imm64:
    x = O(int64_t);
    PUSH(x);
    break;

  case fpvm_opcode_imm32:
    x = O(int32_t);
    PUSH(x);
    break;

  case fpvm_opcode_imm16:
    x = O(int16_t);
    PUSH(x);
    break;

  case fpvm_opcode_imm8:
    x = O(int8_t);
    PUSH(x);
    break;

  case fpvm_opcode_iadd:
    x = POP(uint64_t);
    x+= POP(uint64_t);
    PUSH(x);
    break;


    case fpvm_opcode_call1s1d:
      op = O(op_t);
      dest = POP(void *);
      src1 = POP(void *);

      error = op(&vm->special, dest, src1, NULL, NULL, NULL);
      if (error != 0) {
        DEBUG("WARNING: OP FAILED\n");
      }

      break;

    case fpvm_opcode_call2s1d:
      op = O(op_t);
      dest = POP(void *);
      src1 = POP(void *);
      src2 = POP(void *);

      error = op(&vm->special, dest, src1, src2, NULL, NULL);
      if (error != 0) {
        DEBUG("WARNING: OP FAILED\n");
      }

      break;

    case fpvm_opcode_call3s1d:
      op = O(op_t);
      dest = POP(void *);
      src1 = POP(void *);
      src2 = POP(void *);
      src3 = POP(void *);

      error = op(&vm->special, dest, src1, src2, src3, NULL);
      if (error != 0) {
        DEBUG("WARNING: OP FAILED\n");
      }

      break;

    case fpvm_opcode_clspecial:
      memset(&vm->special, 0, sizeof(op_special_t));
      break;

    case fpvm_opcode_setcti:
      vm->special.compare_type = O(uint32_t);
      break;

    default:
      DEBUG("WARNING: UNHANDLED OPCODE: %d\n", opcode);
      return 0;
  }
  DEBUG("AFTER:\n");
  fpvm_vm_dump(vm, stderr);

  return 1;
}

int fpvm_vm_run(fpvm_vm_t *vm) {
  int count=0;
  while (1) {
    DEBUG("executing instruction %d\n",count);
    int result = fpvm_vm_step(vm);
    count++;
    if (result == 0) {
      DEBUG("no more work to do - success!\n");
      break;
    }
  }

  return 0;
}

void fpvm_vm_dump(fpvm_vm_t *vm, FILE *stream) {
  VM_FPRINTF(stream, "Opcode:\n");
  fpvm_disas_opcode(stream, vm->code);

  // Print the stack.
  VM_FPRINTF(stream, "Stack:\n");
  int ind = 0;
  for (uint64_t *sp = vm->sp - 1; sp >= vm->stack; sp--) {
    VM_FPRINTF(stream, "  %04d: 0x%016zx", ind, *sp);
    if (ind == 0) VM_FPRINTF(stream, " <- tos");
    VM_FPRINTF(stream, "\n");
    ind++;
  }
}
