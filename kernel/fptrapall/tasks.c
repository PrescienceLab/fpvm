
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/ftrace.h>

#include "tasks.h"

DEFINE_XARRAY(fptrapall_task_registry);

#define __GFP GFP_KERNEL

static struct preempt_ops fptrapall_task_preempt_ops;

struct fptrapall_task_state {
    unsigned long flags;
    struct preempt_notifier notif;
};

static inline void
set_ts(void) {
    unsigned long cr0 = read_cr0();
    cr0 |= (1ULL<<3);
    write_cr0(cr0);
}

static inline void
clear_ts(void) {
    unsigned long cr0 = read_cr0();
    cr0 &= ~(1ULL<<3);
    write_cr0(cr0);
}

static inline int
current_pid(void) {
    return task_pid_nr(current);
}

static inline void
current_update_from_flags(unsigned long flags)
{
    if(flags & FPTRAPALL_TASK_IN_SIGNAL) {
	clear_ts(); // Mask CR0.TS if we are in a signal handler
    } else {
        if(flags & FPTRAPALL_TASK_CR0_TS_SET) {
            set_ts();
        } else {
            clear_ts();
        }
    }
}

int
fptrapall_task_registered(void)
{
    return xa_load(&fptrapall_task_registry, current_pid()) != NULL;
}

int
fptrapall_task_register(void)
{
    int res;

    struct fptrapall_task_state *state;

    state = kzalloc(sizeof(*state), __GFP);
    if(state == NULL) {
	return -ENOMEM;
    }

    state->flags = 0;

    res = xa_insert(&fptrapall_task_registry, current_pid(), state, __GFP);
    if(res) {
	return res;
    }

    preempt_notifier_init(&state->notif, &fptrapall_task_preempt_ops);
    preempt_notifier_register(&state->notif);

    current_update_from_flags(state->flags);

    return 0;
}

int
fptrapall_task_unregister(void)
{
    struct fptrapall_task_state *state;

    state = xa_erase(&fptrapall_task_registry, current_pid());
    if(state == NULL) {
        return -ENXIO;
    }

    kfree(state);

    return 0;
}

int
fptrapall_task_set(unsigned long flags) {

    struct fptrapall_task_state *state;

    state = xa_load(&fptrapall_task_registry, current_pid());
    if(state == NULL) {
	return -EINVAL;
    }

    state->flags |= flags;
    current_update_from_flags(state->flags);

    return 0;
}

int
fptrapall_task_clear(unsigned long flags) {

    struct fptrapall_task_state *state = xa_load(&fptrapall_task_registry, current_pid());
    if(state == NULL) {
	return -EINVAL;
    }

    state->flags &= ~flags;

    current_update_from_flags(state->flags);

    return 0;
}

unsigned long
fptrapall_task_get_flags(void)
{
    struct fptrapall_task_state *state = xa_load(&fptrapall_task_registry, current_pid());
    if(state == NULL) {
	return 0;
    } 
    return state->flags;
}

static void
fptrapall_task_sched_in(struct preempt_notifier *notifier, int cpu)
{
    struct fptrapall_task_state *state;

    pr_info("fptrapall_task_sched_in\n");

    state = container_of(notifier, struct fptrapall_task_state, notif);

    current_update_from_flags(state->flags);
}

static void
fptrapall_task_sched_out(
        struct preempt_notifier *notifier,
        struct task_struct *next)
{
//    struct fptrapall_task_state *state;

    pr_info("fptrapall_task_sched_out\n");

//    state = container_of(notifier, struct fptrapall_task_state, notif);

    // Clean up and create a sane default state
    clear_ts();
}

static struct preempt_ops
fptrapall_task_preempt_ops = {
    .sched_in =  fptrapall_task_sched_in,
    .sched_out = fptrapall_task_sched_out,
};

static void
do_exit_callback(unsigned long ip, unsigned long parent_ip,
                             struct ftrace_ops *op, struct ftrace_regs *regs)
{
    int bit;

    bit = ftrace_test_recursion_trylock(ip, parent_ip);
    if (bit < 0) {
            return;
    }

    if(fptrapall_task_registered()) {
	pr_info("fptrapall unregistering pid=%d on exit\n", task_pid_nr(current));
	fptrapall_task_unregister();
	clear_ts();
    }

    ftrace_test_recursion_unlock(bit);
}

static struct ftrace_ops
do_exit_ftrace_ops = {
    .func = &do_exit_callback,
};

static void
restore_sigcontext_callback(unsigned long ip, unsigned long parent_ip,
                             struct ftrace_ops *op, struct ftrace_regs *regs)
{
    int bit;

    bit = ftrace_test_recursion_trylock(ip, parent_ip);
    if (bit < 0) {
            return;
    }

    if(fptrapall_task_registered()) {
	pr_info("fptrapall sigreturn pid=%d\n", task_pid_nr(current));
	fptrapall_task_clear(FPTRAPALL_TASK_IN_SIGNAL);
    }

    ftrace_test_recursion_unlock(bit);
}

static struct ftrace_ops
restore_sigcontext_ftrace_ops = {
    .func = &restore_sigcontext_callback,
};

int
fptrapall_init_tasks(void)
{
    int res;

    preempt_notifier_inc();

    res = ftrace_set_filter(&do_exit_ftrace_ops, "do_exit", strlen("do_exit"), 0);
    if(res) {
        printk(KERN_ERR "Failed to add filter for \"do_exit\"\n");
	preempt_notifier_dec();
	return res;
    }
    res = register_ftrace_function(&do_exit_ftrace_ops);
    if(res) {
	printk(KERN_ERR "Failed to register ftrace on \"do_exit\"\n");
	preempt_notifier_dec();
	return res;
    }

    res = ftrace_set_filter(&restore_sigcontext_ftrace_ops, "restore_sigcontext", strlen("restore_sigcontext"), 0);
    if(res) {
        printk(KERN_ERR "Failed to add filter for \"restore_sigcontext\"\n");
	preempt_notifier_dec();
	return res;
    }
    res = register_ftrace_function(&restore_sigcontext_ftrace_ops);
    if(res) {
	printk(KERN_ERR "Failed to register ftrace on \"restore_sigcontext\"\n");
	preempt_notifier_dec();
	return res;
    }


    return 0;
}
void
fptrapall_deinit_tasks(void)
{
    unregister_ftrace_function(&do_exit_ftrace_ops);
    unregister_ftrace_function(&restore_sigcontext_ftrace_ops);
    preempt_notifier_dec();
}

