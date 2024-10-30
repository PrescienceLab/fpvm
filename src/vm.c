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
    fprintf(stream, "%s <%p>", dli.dli_sname, ptr);
  } else {
    fprintf(stream, "%p", ptr);
  }
}

void fpvm_disas_opcode(FILE *stream, uint8_t *code) {
  const char *op = fpvm_opcode_name(code);
  fprintf(stream, "\e[32m");
  fprintf(stream, "%-14s ", op);
  fprintf(stream, "\e[0m");

  void *arg = code + 1;

  switch (*code) {
#define OPCODE_ARG(opcode, type) \
  case fpvm_opcode_##opcode:     \
    _Generic((type)0, \
    void * : _disas_operand_pointer(stream, *(void**)arg), \
    default : fprintf(stream, "$%d", *(type*)arg) \
    );          \
    break;
#include <fpvm/opcodes.inc>
  }

  fprintf(stream, "\n");
}


void fpvm_builder_disas(FILE *stream, fpvm_builder_t *b) {
  uint8_t *code = b->code;
  uint64_t codesize = b->size;
  
  off_t o = 0;

  fprintf(stream, "<%p>:\n", code);
  while (o < codesize) {
    if (*code == fpvm_opcode_invalid) {
      fprintf(stream, "\n");
      break;
    }
    size_t length = fpvm_opcode_size(code);
    if (length == 0) break;

    fprintf(stream, "  %04x | ", o);

    // print out the bytes
    fprintf(stream, "\e[90m");
    for (int i = 0; i < 9; i++) {
      if (i < length) {
        fprintf(stream, "%02x ", code[i]);
      } else {
        fprintf(stream, "   ");
      }
    }
    fprintf(stream, "\e[0m");
    fprintf(stream, "| ");

    // fprintf(stream, "\e[32m");
    fpvm_disas_opcode(stream, code);
    // fprintf(stream, "\e[0m");
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
#error "FPVM's vm only works on x86_64 for now..."
#endif  // __amd64__
}

void vm_test_decode(fpvm_inst_t *fi) {
  printf("vm test: %p\n", fi);
  fpvm_decoder_decode_and_print_any_inst(fi->addr, stdout, "vm: ");
}




void fpvm_vm_init(fpvm_vm_t *vm, uint8_t *code, uint8_t *mcstate, uint8_t *fpstate) {
  memset(vm, 0, sizeof(fpvm_vm_t));
  vm->mcstate = mcstate;
  vm->fpstate = fpstate;
  vm->code = code;
  vm->sp = vm->stack;
}

#define PUSH(v) (*(vm->sp++) = (uint64_t)(v))  // Push a value to the stack
#define POP(T) (*(T *)(--vm->sp))              // Pop from the stack as type T
#define PEEK(T) (*(T *)(vm->sp-1))             // Read from the stack as type T
#define O(T) (*(T *)(operand))                 // Read the operand of the instruction as type T

int fpvm_vm_step(fpvm_vm_t *vm) {
  printf("\n\nBEFORE:\n");
  fpvm_vm_dump(vm, stdout);

  uint8_t opcode = *vm->code;
  // May or may not be one of these...
  void *operand = vm->code + 1;

  // Move the instruction pointer
  vm->code += fpvm_opcode_size(vm->code);

  op_t op;
  void *src1, *src2, *dest;
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
      return 0;

    case fpvm_opcode_call1s1d:
      op = O(op_t);
      dest = POP(void *);
      src1 = POP(void *);

      error = op(NULL, dest, src1, NULL, NULL, NULL);
      if (error != 0) {
        fprintf(stderr, "WARNING: OP FAILED\n");
      }

      break;

    case fpvm_opcode_call2s1d:
      op = O(op_t);
      dest = POP(void *);
      src1 = POP(void *);
      src2 = POP(void *);

      error = op(NULL, dest, src1, src2, NULL, NULL);
      if (error != 0) {
        fprintf(stderr, "WARNING: OP FAILED\n");
      }

      break;

    default:
      fprintf(stderr, "WARNING: UNHANDLED OPCODE\n");
      return 0;
  }
  printf("AFTER:\n");
  fpvm_vm_dump(vm, stdout);

  return 1;
}

int fpvm_vm_run(fpvm_vm_t *vm) {
  int count=0;
  while (1) {
    INFO("executing instruction %d\n",count);
    int result = fpvm_vm_step(vm);
    count++;
    if (result == 0) {
      ERROR("stopping early\n");
      break;
    }
  }

  return 0;
}

void fpvm_vm_dump(fpvm_vm_t *vm, FILE *stream) {
  fprintf(stream, "Opcode:\n");
  fpvm_disas_opcode(stream, vm->code);

  // Print the stack.
  fprintf(stream, "Stack:\n");
  int ind = 0;
  for (uint64_t *sp = vm->sp - 1; sp >= vm->stack; sp--) {
    fprintf(stream, "  %04d: 0x%016zx", ind, *sp);
    if (ind == 0) fprintf(stream, " <- tos");
    fprintf(stream, "\n");
    ind++;
  }
}
