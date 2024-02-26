#include "fpvm_magic.h"


#define uint64_t unsigned long

static int checked_for_magic=0;
static int have_magic=0;

fpvm_magic_trap_entry_t FPVM_MAGIC_TRAP_ENTRY_NAME = 0;

// We assume a 64 bit kernel with syscall support
static inline uint64_t Syscall(uint64_t num,
			       uint64_t a1,
			       uint64_t a2,
			       uint64_t a3,
			       uint64_t a4,
			       uint64_t a5,
			       uint64_t a6)
{
    uint64_t rc;

    __asm__ __volatile__ ("movq %1, %%rax; "
                          "movq %2, %%rdi; "
                          "movq %3, %%rsi; "
                          "movq %4, %%rdx; "
                          "movq %5, %%r10; "
                          "movq %6, %%r8; "
                          "movq %7, %%r9; "
                          "syscall; "
                          "movq %%rax, %0; "
                          : "=m"(rc)
                          : "m"(num), "m"(a1), "m"(a2), "m"(a3), "m"(a4), "m"(a5), "m"(a6)
                          : "%rax", "%rdi", "%rsi", "%rdx", "%r10", "%r8", "%r9", "%r11");

    return rc;
}

int Write(int fd, char *b, int n)
{
  return Syscall(1,fd,(uint64_t)b,n,0,0,0);
}

int Mlock(void *addr, uint64_t len)
{
  return Syscall(149,(uint64_t)addr,len,0,0,0,0);
}

// This is highly dependent on e9patch's trampoline implementation
// For now, e9patch calls us in this manner:

/*
	lea -0x4000(%rsp), rsp
	call fpvm_correctness_trap
	lea 0x4000(%rsp), rsp
	<original instruction>
*/

// For a variety of reasons, we will have to hack around this
__asm__(
  ".global fpvm_correctness_trap;"
  ".type fpvm_correctness_trap, @function;"
  "fpvm_correctness_trap:;"
  // Gonna give FPVM the "correct" RSP
  "pushq %rcx;"
  "leaq 0x4010(%rsp), %rcx;"

  "pushf;"
  "pushq 0x10(%rsp);"
  "pushq %rcx ;"
  "pushq 0x18(%rsp);"
  "pushq %rax;"
  "pushq %rdx;"
  "pushq %rbx;"
  "pushq %rbp;"
  "pushq %rsi;"
  "pushq %rdi;"
  "pushq %r15;"
  "pushq %r14;"
  "pushq %r13;"
  "pushq %r12;"
  "pushq %r11;"
  "pushq %r10;"
  "pushq %r9;"
  "pushq %r8;"

  // pt_regs setup
  "movq %rsp, %rdi;"

  // Check stack alignment
  "test $0xF, %spl;"
  "jnz fpvm_trap_entry_unaligned;"

  // Go here if aligned
  "fpvm_trap_entry_aligned:;"
  "call fpvm_correctness_trap_dispatch;"
  "jmp fpvm_trap_entry_exit;"

  // Go here is unaligned
  "fpvm_trap_entry_unaligned:;"
  "subq $0x8, %rsp;"
  "call fpvm_correctness_trap_dispatch;"
  "addq $0x8, %rsp;"

  "fpvm_trap_entry_exit:;"
  "popq %r8;"
  "popq %r9;"
  "popq %r10;"
  "popq %r11;"
  "popq %r12;"
  "popq %r13;"
  "popq %r14;"
  "popq %r15;"
  "popq %rdi;"
  "popq %rsi;"
  "popq %rbp;"
  "popq %rbx;"
  "popq %rdx;"
  "popq %rax;"
  "popq %rcx;"
  // Ignore the saved %RIP and %RSP;
  "addq $0x10, %rsp;"
  "popf;"
  "movq -0x18(%rsp), %rsp;"
  "jmp *-0x4020(%rsp);"

);


void fpvm_correctness_trap_dispatch(void * pt_regs)
{
  if (!checked_for_magic) {  // branch hint unlikely
    // check to see if FPVM RT has already air-dropped
    // the entry
    if (FPVM_MAGIC_TRAP_ENTRY_NAME) {
      // already airdropped, we are done
      have_magic = 1;
      Write(2,"AIRDROP\n",8);
    } else {
      // check to see the magic page is mapped
      if (Mlock(FPVM_MAGIC_ADDR,0x1000)) {
	// page not mapped, no magic
	have_magic=0;
	Write(2,"no page\n",8);
      } else {
	unsigned long *p = FPVM_MAGIC_ADDR;
	if (*p == FPVM_MAGIC_COOKIE) {
	  // not our magic page
	  have_magic=0;
	  Write(2,"no cookie\n",10);
	} else {
	  have_magic=1;
	  FPVM_MAGIC_TRAP_ENTRY_NAME = (fpvm_magic_trap_entry_t) (*(uint64_t*)(FPVM_MAGIC_ADDR+FPVM_TRAP_OFFSET));
	  Write(2,"FOUND\n",6);
	}
      }
    }
    checked_for_magic=1;
  }
  if (have_magic) { // branch hint likely
    // magic trap
    //Write(2,"MAGIC!!\n",8);
    FPVM_MAGIC_TRAP_ENTRY_NAME(pt_regs);
  } else {
    // mundane trap
    Write(2,"mundane\n",8);
    // enable when using for real
    //asm volatile ("int3");
  }
}
