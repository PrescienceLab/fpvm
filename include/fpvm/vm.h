#pragma once

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <fpvm/fpvm_common.h>
#include <fpvm/decoder.h>


#define FPVM_VM_STACK_SIZE 128
typedef struct {
  // The code that is currently executing
  uint8_t *code;

  // Register files
  uint8_t *mcstate;
  uint8_t *fpstate;


  uint64_t *sp; // the vm's stack pointer
  uint64_t stack[FPVM_VM_STACK_SIZE];

} fpvm_vm_t;


void fpvm_vm_init(fpvm_vm_t *vm, uint8_t *code, uint8_t *mcstate, uint8_t *fpstate);
// Step one instruction in the virtual machine, returning
// 0 if no more instructions are available to be run.
int fpvm_vm_step(fpvm_vm_t *);
void fpvm_vm_dump(fpvm_vm_t *, FILE *stream);


typedef enum {
  fpvm_opcode_invalid,
#define OPCODE(opcode) fpvm_opcode_##opcode,
#define OPCODE_ARG(opcode, ...) fpvm_opcode_##opcode,
#include <fpvm/opcodes.inc>
} fpvm_opcode_t;


void fpvm_disas(FILE *stream, uint8_t *code, size_t codesize);

// A structure to help in building the opcode stream
typedef struct {
  size_t size;
  off_t offset;
  uint8_t *code;
} fpvm_builder_t;

void fpvm_builder_init(fpvm_builder_t *);
void fpvm_builder_deinit(fpvm_builder_t *);



/**
 * @brief: compile an instruction into bytecode
 * @returns: 0 on success, nonzero otherwise (negative number)
 */
int fpvm_vm_compile(fpvm_inst_t *fi);


#define OPCODE(opcode) void fpvm_build_##opcode(fpvm_builder_t *b);
#define OPCODE_ARG(opcode, type) void fpvm_build_##opcode(fpvm_builder_t *b, type arg);
#include <fpvm/opcodes.inc>
