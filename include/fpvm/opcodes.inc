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


OPCODE(dup) // Copy the top of stack
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

// Calls an op_t with a special, 1 dest, and 3 sources.
OPCODE_ARG(call3s1d, void*)

// Calls an op_t with a special, 1 dest, and 2 sources.
OPCODE_ARG(call2s1d, void*)

// Calls an op_t with a special, 1 dest, and 1 source.
OPCODE_ARG(call1s1d, void*)

// Push a pointer to an offset in the machine context
OPCODE_ARG(mcptr, uint16_t)
// Push a pointer to an offset into the fpregs context
OPCODE_ARG(fpptr, uint16_t)

// Set compare type immediate (this is for special)
OPCODE_ARG(setcti, uint32_t)

// TODO: Set rflags (this is for special)
// OPCODE_ARG(setrflags, )

// Clear the special to be 0
OPCODE(clspecial)

// Make sure to undef the macros here, so we don't have to
// remember to do so in the user code
#undef OPCODE
#undef OPCODE_ARG
