#pragma once

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

typedef struct {
  // The code that is currently executing
  uint8_t *code;
} fpvm_vm_t;


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

// Step one instruction in the virtual machine
void fpvm_vm_step(fpvm_vm_t *);


#define OPCODE(opcode) void fpvm_build_##opcode(fpvm_builder_t *b);
#define OPCODE_ARG(opcode, type) void fpvm_build_##opcode(fpvm_builder_t *b, type arg);
#include <fpvm/opcodes.inc>
