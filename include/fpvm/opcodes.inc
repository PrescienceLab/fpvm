// Ensure that the macros are at least defined to do nothing
#ifndef OPCODE
  #define OPCODE(...)
#endif

#ifndef OPCODE_ARG
  #define OPCODE_ARG(...)
#endif

// These are opcodes with no arguments.
OPCODE(check) // Check if the TOS is a nan or not
OPCODE(todo) // just a marker instruction
OPCODE(done) // Marker that the instruction is done.

// Pop address, load 64, push result
OPCODE(ld64)
// Pop two integers, multiply them, and push result
OPCODE(imul)
OPCODE(iadd)
OPCODE(fdiv)

OPCODE_ARG(xcall1, void*)


// These are opcodes with arguments
OPCODE_ARG(imm8, uint8_t)
OPCODE_ARG(imm16, uint16_t)
OPCODE_ARG(imm32, uint32_t)
OPCODE_ARG(imm64, uint64_t)
OPCODE_ARG(immptr, void*)




// Push a pointer to an offset in the machine context
OPCODE_ARG(mcptr, uint16_t)
// Push a pointer to an offset into the fpregs context
OPCODE_ARG(fpptr, uint16_t)


// Make sure to undef the macros here, so we don't have to
// remember to do so in the user code
#undef OPCODE
#undef OPCODE_ARG
