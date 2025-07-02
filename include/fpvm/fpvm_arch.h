#pragma once

/* The functions exported through this header are intended for the arch-specific
 * backends to call back into the generic FPVM core.
 *
 * For example, the architecture-specific backends need access to the common way
 * FPVM aborts operation when some inconsistent state is encountered.
 */

#include <signal.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/time.h>

void fp_trap_handler(siginfo_t *si, ucontext_t *uc);
void brk_trap_handler(siginfo_t *si, ucontext_t *uc);
void abort_operation(char *reason);

// returns true if we are in the INIT state
int fpvm_current_execution_context_is_in_init(void);
