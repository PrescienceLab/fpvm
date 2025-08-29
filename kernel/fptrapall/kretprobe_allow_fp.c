
#include <linux/string.h>
#include <linux/module.h>
#include <linux/kernel.h>

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

static int kprobe_allow_fp_entry(
	struct kretprobe_instance *ri,
	struct pt_regs *regs)
{
    unsigned long cr0;
    //printk(KERN_INFO "kprobe_allow_fp_entry\n");
    if(!current->mm) {
	return 1; // Skip kernel threads
    }
    cr0 = read_cr0();
    *(unsigned long*)ri->data = cr0;
    write_cr0(cr0 & ~X86_CR0_TS);
    return 0;
}

static int kprobe_allow_fp_return(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    //printk(KERN_INFO "kprobe_allow_fp_return\n");
    write_cr0(*(unsigned long *)ri->data);
    return 0;
}

#define KPROBE_ALLOW_FP_XLIST(X)\
X(save_fpregs_to_fpstate)\
X(restore_fpregs_from_fpstate)\
X(fpu__drop)\
X(fpu__restore_sig)\


#define __KPROBE_ALLOW_FP_STATE(__FUNC)\
static struct kretprobe __kprobe_ ## __FUNC = {\
    .kp.symbol_name = #__FUNC, \
    .handler = kprobe_allow_fp_return, \
    .entry_handler = kprobe_allow_fp_entry, \
    .data_size = sizeof(unsigned long), \
};
KPROBE_ALLOW_FP_XLIST(__KPROBE_ALLOW_FP_STATE)
#undef __KPROBE_ALLOW_FP_STATE

int
setup_allow_fp_kprobes(void) {
    int res;
    unsigned long maxactive = num_online_cpus()*2;

    pr_info("Registering kprobes (maxactive=%ld)\n", maxactive);
#define __KPROBE_ALLOW_FP_REGISTER(__FUNC)\
    pr_info("Registering kprobe on function \"" #__FUNC "\"\n");\
    __kprobe_ ## __FUNC .maxactive = maxactive; \
    res = register_kretprobe(&__kprobe_ ## __FUNC);\
    if(res) {\
	pr_info("Failed to register kprobe on function \""#__FUNC"\"\n");\
	return res; \
    }
KPROBE_ALLOW_FP_XLIST(__KPROBE_ALLOW_FP_REGISTER)
#undef __KPROBE_ALLOW_FP_REGISTER
    pr_info("Registered all kprobes\n");
    return 0;
}

int
remove_allow_fp_kprobes(void) {
    pr_info("Unregistering kprobes\n");
#define __KPROBE_ALLOW_FP_REGISTER(__FUNC)\
    pr_info("Unregistering kprobe on function \"" #__FUNC "\"\n");\
    unregister_kretprobe(&__kprobe_ ## __FUNC);\
    if(__kprobe_ ## __FUNC.nmissed > 0) {\
	pr_info("Probe on function \""#__FUNC"\" missed %d attempts to probe!\n", __kprobe_ ## __FUNC.nmissed);\
    }
KPROBE_ALLOW_FP_XLIST(__KPROBE_ALLOW_FP_REGISTER)
#undef __KPROBE_ALLOW_FP_REGISTER
    pr_info("Unregistered all kprobes\n");
    return 0;
}

