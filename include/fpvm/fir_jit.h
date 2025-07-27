#pragma once

#include <stdio.h>
#include <stdint.h>
#include <fpvm/vm.h>

typedef struct {
    char *code;
    size_t size;
    size_t capacity;
} asm_gen_t;

void asm_init(asm_gen_t *gen);
void* compile_and_load_assembly(const char* asm_code);
void translate_fir_to_assembly(uint8_t *fir_code, size_t code_size, asm_gen_t *gen);
int translate_fir_to_asm(FILE *out, uint8_t *fir_code, size_t code_size);