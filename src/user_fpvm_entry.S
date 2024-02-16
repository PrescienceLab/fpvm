#include <fpvm/config.h>

.code64
.section .text

#if CONFIG_TRAP_SHORT_CIRCUITING
.global _user_fpvm_entry
_user_fpvm_entry:
  pushf
  pushq 16(%rsp)  		
  pushq 16(%rsp) 		
  pushq %rcx
  pushq %rax
  pushq %rdx
  pushq %rbx
  pushq %rbp
  pushq %rsi
  pushq %rdi
  pushq %r15
  pushq %r14
  pushq %r13
  pushq %r12
  pushq %r11
  pushq %r10
  pushq %r9
  pushq %r8
  movq %rsp, %rdi

  call *fpvm_short_circuit_handler@GOTPCREL(%rip)
	
  popq %r8
  popq %r9
  popq %r10
  popq %r11
  popq %r12
  popq %r13
  popq %r14
  popq %r15
  popq %rdi
  popq %rsi
  popq %rbp
  popq %rbx
  popq %rdx
  popq %rax
  popq %rcx
  popq 24(%rsp)
  // You wanna see something nasty? >.<
  popq 24(%rsp)
  leaq -0x8(%rsp), %rsp
  popq 32(%rsp)
  leaq -0x8(%rsp), %rsp
  popq 40(%rsp)
  // You're welcome :P
  popf
  popq %rsp
  jmp *-152(%rsp)
#endif

#if CONFIG_MAGIC_CORRECTNESS_TRAP
// This is highly dependent on e9patch's trampoline implementation
// For now, e9patch calls us in this manner:

/*
	lea -0x4000(%rsp), rsp
	call fpvm_correctness_trap_asm
	lea 0x4000(%rsp), rsp
	<original instruction>
*/

// For a variety of reasons, we will have to hack around this

.global fpvm_magic_trap_entry_asm
fpvm_magic_trap_entry_asm:
  // Gonna give FPVM the "correct" RSP 
  pushq %rcx
  leaq 0x4010(%rsp), %rcx

  // Now stack is either 
  pushf
  pushq 0x10(%rsp) 		
  pushq %rcx 
  pushq	0x18(%rsp)
  pushq %rax
  pushq %rdx
  pushq %rbx
  pushq %rbp
  pushq %rsi
  pushq %rdi
  pushq %r15
  pushq %r14
  pushq %r13
  pushq %r12
  pushq %r11
  pushq %r10
  pushq %r9
  pushq %r8

  movq %rsp, %rdi
 
// Check for 16-byte stack alignment
  test $0x8, %spl
  jnz fpvm_trap_entry_unaligned

fpvm_trap_entry_aligned:
  call *fpvm_magic_trap_entry@GOTPCREL(%rip)
  jmp fpvm_trap_entry_exit

fpvm_trap_entry_unaligned:
  subq $0x8, %rsp
  call *fpvm_magic_trap_entry@GOTPCREL(%rip)
  addq $0x8, %rsp

fpvm_trap_entry_exit:
  popq %r8
  popq %r9
  popq %r10
  popq %r11
  popq %r12
  popq %r13
  popq %r14
  popq %r15
  popq %rdi
  popq %rsi
  popq %rbp
  popq %rbx
  popq %rdx
  popq %rax
  popq %rcx
  // Ignore the saved %RIP and %RSP
  addq $0x10, %rsp
  popf
  movq -0x18(%rsp), %rsp
  jmp *-0x4020(%rsp)
#endif
