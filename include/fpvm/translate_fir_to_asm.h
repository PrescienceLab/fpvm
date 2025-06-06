#pragma once

#include <stdio.h>
#include <stdint.h>

/**
 * @brief  Translate a buffer of FIR bytecode into x86-64 assembly text.
 * @param[out] out        FILE* to write the generated assembly into.
 * @param      fir_code   Pointer to the FIR bytecode buffer.
 * @param      code_size  Number of bytes in fir_code.
 * @return     0 on success, nonzero on error.
 */
int translate_fir_to_asm(FILE *out, uint8_t *fir_code, size_t code_size);