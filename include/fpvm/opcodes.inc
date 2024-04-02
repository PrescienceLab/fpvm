// Ensure that the macros are at least defined to do nothing
#ifndef OPCODE
  #define OPCODE(...)
#endif

#ifndef OPCODE_ARG
  #define OPCODE_ARG(...)
#endif

// These are opcodes with no arguments.
//     op name     type      arg_name
OPCODE(alt_add)
OPCODE(alt_mul)
OPCODE(check) // Check if the TOS is a nan or not
OPCODE(done) // This instruction is done.


// These are opcodes with arguments
OPCODE_ARG(imm8, uint8_t)
OPCODE_ARG(imm16, uint16_t)
OPCODE_ARG(imm32, uint32_t)
OPCODE_ARG(imm64, uint64_t)
OPCODE_ARG(immptr, void*)




// Make sure to undef the macros here, so we don't have to
// remember to do so in the user code
#undef OPCODE
#undef OPCODE_ARG
