#pragma once

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <fpvm/fpvm_common.h>
#include <fpvm/decoder.h>
#include <fpvm/number_system.h>


#define FPVM_VM_STACK_SIZE 128
typedef struct {
  op_special_t special;

  // The code that is currently executing
  uint8_t *code;

  // Register files
  uint8_t *mcstate;
  uint8_t *fpstate;


  uint64_t *sp; // the vm's stack pointer
  uint64_t stack[FPVM_VM_STACK_SIZE];

} fpvm_vm_t;


void fpvm_vm_init(fpvm_vm_t *vm, fpvm_inst_t *inst, fpvm_regs_t *regs);
// Step one instruction in the virtual machine, returning
// 0 if no more instructions are available to be run.
int fpvm_vm_step(fpvm_vm_t *);
// Run the virtual machine until a done instruction
// Returns 0 if done instruction is reached, nonzero if there was an error
int fpvm_vm_run(fpvm_vm_t *);
void fpvm_vm_dump(fpvm_vm_t *, FILE *stream);


typedef enum {
  fpvm_opcode_invalid,
#define OPCODE(opcode) fpvm_opcode_##opcode,
#define OPCODE_ARG(opcode, ...) fpvm_opcode_##opcode,
#include <fpvm/opcodes.inc>
} fpvm_opcode_t;



// A structure to help in building the opcode stream
typedef struct {
  size_t size;
  off_t offset;
  uint8_t *code;
} fpvm_builder_t;

void fpvm_builder_init(fpvm_builder_t *);
void fpvm_builder_deinit(fpvm_builder_t *);


void fpvm_builder_disas(FILE *stream, fpvm_builder_t *b);


/**
 * @brief: compile an instruction into bytecode
 * @returns: 0 on success, nonzero otherwise (negative number)
 */
int fpvm_vm_compile(fpvm_inst_t *fi);


#define OPCODE(opcode) void fpvm_build_##opcode(fpvm_builder_t *b);
#define OPCODE_ARG(opcode, type) void fpvm_build_##opcode(fpvm_builder_t *b, type arg);
#include <fpvm/opcodes.inc>
