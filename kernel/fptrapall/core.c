
#include <linux/string.h>
#include <linux/module.h>
#include <linux/kernel.h>

#include "tasks.h"
#include "sysfs.h"
#include "kretprobe_allow_fp.h"
#include "extra_symbols.h"
#include "dna_patch.h"

static int fptrapall_init(void)
{
	int res;

	pr_info("Starting Module\n");

	pr_info("Setting up Un-exported symbols\n");
	res = setup_unexported_symbols();
	if(res) {
	    return res;
	}

	pr_info("Setting up pertask cr0\n");
	res = fptrapall_init_tasks();
	if(res) {
	    return res;
	}

	pr_info("Setting up sysfs\n");
	res = fptrapall_sysfs_init();
	if(res) {
	    return res;
	}

	pr_info("Setting up Kprobes\n");
	res = setup_allow_fp_kprobes();
	if(res) {
	    return res;
	}

	pr_info("Enabling livepatch\n");
	res = setup_dna_patch();
	if (res) {
		return res;
	}
	return 0;
}

static void fptrapall_exit(void)
{
    fptrapall_deinit_tasks();
    fptrapall_sysfs_deinit();
    remove_allow_fp_kprobes();
}

module_init(fptrapall_init);
module_exit(fptrapall_exit);
MODULE_LICENSE("GPL");
MODULE_INFO(livepatch, "Y");

