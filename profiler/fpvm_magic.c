#include "fpvm_magic.h"

#define uint64_t unsigned long

static int checked_for_magic = 0;
static int have_magic = 0;

fpvm_magic_trap_entry_t FPVM_MAGIC_TRAP_ENTRY_NAME = 0;
static int (*fpvm_demote_handler)(void *) = 0;


#if CONFIG_FPTRAPALL

#define FPTRAPALL_REGISTER_PATH "/sys/kernel/fptrapall/register"
#define FPTRAPALL_TS_PATH "/sys/kernel/fptrapall/ts"
#define FPTRAPALL_IN_SIGNAL_PATH "/sys/kernel/fptrapall/in_signal"


static void
fptrapall_set_ts(void)
{
	int fd = syscall(SYS_open, FPTRAPALL_TS_PATH, O_WRONLY);
	if(fd < 0) {
		perror("open");
		syscall(SYS_exit, fd);
	}

	syscall(SYS_lseek, fd, 0, SEEK_SET);

	uint8_t val = '1';
	long written = syscall(SYS_write, fd, &val, sizeof(val));

        if (written < 0) {
            perror("write");
	    syscall(SYS_exit, (int)written);
        }

	syscall(SYS_close, fd);
}

static void
fptrapall_clear_ts(void)
{
	int fd = syscall(SYS_open, FPTRAPALL_TS_PATH, O_WRONLY);
	if(fd < 0) {
		perror("open");
		syscall(SYS_exit, fd);
	}

	syscall(SYS_lseek, fd, 0, SEEK_SET);

	uint8_t val = '0';
	long written = syscall(SYS_write, fd, &val, sizeof(val));

        if (written < 0) {
            perror("write");
	    syscall(SYS_exit, (int)written);
        }

	syscall(SYS_close, fd);
}

#else

#define fptrapall_set_ts(...)
#define fptrapall_clear_ts(...)

#endif

// We assume a 64 bit kernel with syscall support
static inline uint64_t Syscall(
    uint64_t num, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
  uint64_t rc;

  __asm__ __volatile__(
      "movq %1, %%rax; "
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

int Write(int fd, char *b, int n) {
  return Syscall(1, fd, (uint64_t)b, n, 0, 0, 0);
}

int Mlock(void *addr, uint64_t len) {
  return Syscall(149, (uint64_t)addr, len, 0, 0, 0, 0);
}



static int check_for_magic(void) {
  if (!checked_for_magic) {  // branch hint unlikely
    // check to see if FPVM RT has already air-dropped
    // the entry
    if (FPVM_MAGIC_TRAP_ENTRY_NAME) {
      // already airdropped, we are done
      have_magic = 1;
      Write(2, "AIRDROP\n", 8);
    } else {
      // check to see the magic page is mapped
      if (Mlock(FPVM_MAGIC_ADDR, 0x1000)) {
        // page not mapped, no magic
        have_magic = 0;
        Write(2, "no page\n", 8);
      } else {
        unsigned long *p = FPVM_MAGIC_ADDR;
        struct fpvm_trap_magic *m = (struct fpvm_trap_magic *)p;
        if (m->magic_cookie == FPVM_MAGIC_COOKIE) {
          // not our magic page
          have_magic = 0;
          fprintf(stderr, "No cookie, no magic.\n");
        } else {
          FPVM_MAGIC_TRAP_ENTRY_NAME = m->trap;

          have_magic = 1;
          /* FPVM_MAGIC_TRAP_ENTRY_NAME = */
          /*     (fpvm_magic_trap_entry_t)(*(uint64_t *)(FPVM_MAGIC_ADDR + FPVM_TRAP_OFFSET)); */
          fprintf(stderr, "Found magic trap handler!\n");
          fpvm_demote_handler = m->demote;
        }
      }
    }
    checked_for_magic = 1;
  }
  return have_magic;
}

void fpvm_correctness_trap_dispatch(void *pt_regs) {
  fptrapall_clear_ts();
  if (check_for_magic()) {  // branch hint likely
    // magic trap
    //Write(2,"MAGIC!!\n",8);
    FPVM_MAGIC_TRAP_ENTRY_NAME(pt_regs);
  } else {
    fprintf(stderr, "magic trap is not enabled!\n");
    exit(-1);
  }
  fptrapall_set_ts();
}




// This is highly dependent on e9patch's trampoline implementation
// For now, e9patch calls us in this manner:

/*
  lea -0x4000(%rsp), rsp
  call fpvm_correctness_trap
  lea 0x4000(%rsp), rsp
  <original instruction>
*/


#define RED "\33[31m"
#define GREEN "\33[32m"
#define YELLOW "\33[33m"
#define RESET "\33[0m"

static int traps = 0;
// RENAME THIS FUNCTION NICK (Make it "correctness_trap_memory", and the other one should be
// "correctness_trap_instruction") -PAD
void fpvm_correctness_trap_test(
    const char *_asm, struct STATE *state, uint8_t *bytes, uint64_t *dst) {

  fptrapall_clear_ts();
  if (check_for_magic()) {
    //Write(2,"TEST!!\n",7);
    uint64_t old_val = *dst;
    if (old_val == -1) {
      // return;
    }
    if (fpvm_demote_handler(dst)) {
      fptrapall_set_ts();
      return;
      fprintf(stderr, RED "%8d - %.16lx: " GREEN " %s" RESET "\n", traps++, state->rip, _asm);
      fprintf(stderr, "       demoted: %zx -> %zx\n", old_val, *dst);
      fflush(stderr);
    }
  }
  fptrapall_set_ts();
  return;
  // *dst = 42;
  /* fprintf(stderr, "\t%rax    = 0x%.16lx (%p)\n", state->rax, &state->rax); */
  /* fprintf(stderr, "\t%rcx    = 0x%.16lx (%p)\n", state->rcx, &state->rcx); */
  /* fprintf(stderr, "\t%rdx    = 0x%.16lx (%p)\n", state->rdx, &state->rdx); */
  /* fprintf(stderr, "\t%rbx    = 0x%.16lx (%p)\n", state->rbx, &state->rbx); */
  /* fprintf(stderr, "\t%rsp    = 0x%.16lx (%p)\n", state->rsp, &state->rsp); */
  /* fprintf(stderr, "\t%rbp    = 0x%.16lx (%p)\n", state->rbp, &state->rbp); */
  /* fprintf(stderr, "\t%rsi    = 0x%.16lx (%p)\n", state->rsi, &state->rsi); */
  /* fprintf(stderr, "\t%rdi    = 0x%.16lx (%p)\n", state->rdi, &state->rdi); */
  /* fprintf(stderr, "\t%r8     = 0x%.16lx (%p)\n", state->r8,  &state->r8); */
  /* fprintf(stderr, "\t%r9     = 0x%.16lx (%p)\n", state->r9,  &state->r9); */
  /* fprintf(stderr, "\t%r10    = 0x%.16lx (%p)\n", state->r10, &state->r10); */
  /* fprintf(stderr, "\t%r11    = 0x%.16lx (%p)\n", state->r11, &state->r11); */
  /* fprintf(stderr, "\t%r12    = 0x%.16lx (%p)\n", state->r12, &state->r12); */
  /* fprintf(stderr, "\t%r13    = 0x%.16lx (%p)\n", state->r13, &state->r13); */
  /* fprintf(stderr, "\t%r14    = 0x%.16lx (%p)\n", state->r14, &state->r14); */
  /* fprintf(stderr, "\t%r15    = 0x%.16lx (%p)\n", state->r15, &state->r15); */

  /* jump(state); */
}

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
