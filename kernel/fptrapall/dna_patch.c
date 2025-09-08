
#include <linux/kobject.h>
#include <linux/string.h>
#include <linux/sysfs.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/livepatch.h>

#include <asm/stacktrace.h>
#include <asm/processor.h>
#include <asm/debugreg.h>
#include <asm/realmode.h>
#include <asm/text-patching.h>
#include <asm/traps.h>
#include <asm/desc.h>
#include <asm/fpu/api.h>
#include <asm/cpu.h>
#include <asm/cpu_entry_area.h>
#include <asm/mce.h>
#include <asm/fixmap.h>
#include <asm/mach_traps.h>
#include <asm/alternative.h>
#include <asm/fpu/xstate.h>
#include <asm/vm86.h>
#include <asm/umip.h>
#include <asm/insn.h>
#include <asm/insn-eval.h>
#include <asm/vdso.h>
#include <asm/msr.h>

#include "tasks.h"
#include "extra_symbols.h"

// handle_xfd_event patching

/*
 * This is the "sketchy"-est part of the kernel module.
 *
 * We need to hook the #NM exception, but it seems the only "safe"
 * and consistent way to do so is to patch "handle_xfd_event", which
 * handles a pentium errata at the start of every #NM exception.
 *
 * By returning True, the rest of the standard #NM handling code should never be invoked.
 */

static inline void dna_patch_cond_local_irq_enable(struct pt_regs *regs)
{
	if (regs->flags & X86_EFLAGS_IF)
		local_irq_enable();
}

static inline void dna_patch_cond_local_irq_disable(struct pt_regs *regs)
{
	if (regs->flags & X86_EFLAGS_IF)
		local_irq_disable();
}

static nokprobe_inline int
dna_patch_do_trap_no_signal(struct task_struct *tsk, int trapnr, const char *str,
		  struct pt_regs *regs,	long error_code)
{
	tsk->thread.error_code = error_code;
	tsk->thread.trap_nr = trapnr;

	return -1;
}

static void
dna_patch_do_trap(int trapnr, int signr, char *str, struct pt_regs *regs,
	long error_code, int sicode, void __user *addr)
{
	struct task_struct *tsk = current;

	if (!dna_patch_do_trap_no_signal(tsk, trapnr, str, regs, error_code))
		return;

	if (!sicode) {
		force_sig(signr);
        } else {
	        force_sig_fault(signr, sicode, addr);
	}
}

static __always_inline void __user *dna_patch_error_get_trap_addr(struct pt_regs *regs)
{
	return (void __user *)uprobe_get_trap_addr(regs);
}

static void dna_patch_do_error_trap(struct pt_regs *regs, long error_code, char *str,
	unsigned long trapnr, int signr, int sicode, void __user *addr)
{
	RCU_LOCKDEP_WARN(!rcu_is_watching(), "entry code didn't wake RCU");
	dna_patch_cond_local_irq_enable(regs);
	dna_patch_do_trap(trapnr, signr, str, regs, error_code, sicode, addr);
	dna_patch_cond_local_irq_disable(regs);
}

static bool patched_handle_xfd_event(struct pt_regs *regs)
{
    // NOTE: We do not handle the Pentium Errata which this function would normally check for.

    unsigned long cr0 = read_cr0();
     
    if(!user_mode(regs)) {
        if (cr0 & X86_CR0_TS) {
            /* Try to fix it up and carry on. */
            write_cr0(cr0 & ~X86_CR0_TS);
            pr_warn("Kernel mode #NM exception clearing TS bit (address=%p)\n", dna_patch_error_get_trap_addr(regs));
	} else {
            /*
             * Something terrible happened, we have to panic instead of "die"-ing because "die" is un-exported
             */
            panic("unexpected #NM exception");
	}
    }
    else if(fptrapall_task_registered()) {
	if(fptrapall_task_get_flags() & FPTRAPALL_TASK_IN_SIGNAL) {
	    pr_warn("User-mode #NM exception occurred during signal handler... (Unexpected)\n");
	}
        /* Deliver a signal to user-mode (with TS clear now) */
	pr_info("Delivering CR0.TS=1 SIGFPE (pid=%d)\n", (int)task_pid_nr(current));
	fptrapall_task_set(FPTRAPALL_TASK_IN_SIGNAL);
        dna_patch_do_error_trap(regs, 0, "device not available", X86_TRAP_NM, SIGFPE,
    	                        FPE_FLTINV, dna_patch_error_get_trap_addr(regs));
    } else {
	/* Somehow an unregistered process was leaked a set TS bit, clear the bit and carry on. */
        write_cr0(cr0 & ~X86_CR0_TS);
        pr_warn("Unexpected user mode #NM exception, clearing TS bit (pid=%d)\n", (int)task_pid_nr(current));
    }
 
    return true;
}

static struct klp_func klp_funcs[] = {
	{
		.old_name = "handle_xfd_event",
		.new_func = patched_handle_xfd_event,
	},
	{ }
};
static struct klp_object klp_objs[] = {
	{
		/* name being NULL means vmlinux */
		.funcs = klp_funcs,
	}, { }
};
static struct klp_patch patch = {
	.mod = THIS_MODULE,
	.objs = klp_objs,
};

int setup_dna_patch(void)
{
    return klp_enable_patch(&patch);
}
