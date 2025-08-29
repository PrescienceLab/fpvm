
#include <linux/kobject.h>
#include <linux/string.h>
#include <linux/sysfs.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/sched.h>

#include "sysfs.h"
#include "tasks.h"

static struct kobject *fptrapall_sysfs_kobject;

static ssize_t
register_show(
        struct kobject *kobj,
        struct kobj_attribute *attr,
        char *buf)
{
    int value = fptrapall_task_registered();
    return sysfs_emit(buf, "%d\n", value);
}

static ssize_t
register_store(
        struct kobject *kobj,
        struct kobj_attribute *attr,
        const char *buf, size_t count)
{
    if(fptrapall_task_registered()) {
	return 0;
    }

    fptrapall_task_register();
    return count;
}

static struct kobj_attribute register_attribute =__ATTR(register, 0220, register_show, register_store);

static ssize_t
ts_show(
        struct kobject *kobj,
        struct kobj_attribute *attr,
        char *buf)
{
    int value = (int)!!(fptrapall_task_get_flags() & FPTRAPALL_TASK_CR0_TS_SET);
    return sysfs_emit(buf, "%d\n", value);
}

static ssize_t
ts_store(
        struct kobject *kobj,
        struct kobj_attribute *attr,
        const char *buf, size_t count)
{
    int res;
    int value;

    if(!fptrapall_task_registered()) {
	return -EINVAL;
    }

    res = kstrtoint(buf, 10, &value);
    if (res < 0) {
	return res;
    }

    if(value) {
	fptrapall_task_set(FPTRAPALL_TASK_CR0_TS_SET);
    } else {
	fptrapall_task_clear(FPTRAPALL_TASK_CR0_TS_SET);
    }

    return count;
}

static struct kobj_attribute ts_attribute =__ATTR(ts, 0220, ts_show, ts_store);

static ssize_t
in_signal_show(
        struct kobject *kobj,
        struct kobj_attribute *attr,
        char *buf)
{
    int value = (int)!!(fptrapall_task_get_flags() & FPTRAPALL_TASK_IN_SIGNAL);
    return sysfs_emit(buf, "%d\n", value);
}

static ssize_t
in_signal_store(
        struct kobject *kobj,
        struct kobj_attribute *attr,
        const char *buf, size_t count)
{
    int res;
    int value;

    if(!fptrapall_task_registered()) {
	return -EINVAL;
    }

    res = kstrtoint(buf, 10, &value);
    if (res < 0) {
	return res;
    }

    if(value) {
	fptrapall_task_set(FPTRAPALL_TASK_IN_SIGNAL);
    } else {
	fptrapall_task_clear(FPTRAPALL_TASK_IN_SIGNAL);
    }

    return count;
}

static struct kobj_attribute in_signal_attribute =__ATTR(in_signal, 0220, in_signal_show, in_signal_store);

int
fptrapall_sysfs_init(void)
{
        int res = 0;

        fptrapall_sysfs_kobject = kobject_create_and_add("fptrapall", kernel_kobj);
        if(!fptrapall_sysfs_kobject)
                return -ENOMEM; 

        res = sysfs_create_file(fptrapall_sysfs_kobject, &register_attribute.attr);
        if (res) {
                pr_debug("failed to create the \"register\" file in \"/sys/kernel/fptrapall\"\n");
        }
        res = sysfs_create_file(fptrapall_sysfs_kobject, &ts_attribute.attr);
        if (res) {
                pr_debug("failed to create the \"ts\" file in \"/sys/kernel/fptrapall\"\n");
        }
        res = sysfs_create_file(fptrapall_sysfs_kobject, &in_signal_attribute.attr);
        if (res) {
                pr_debug("failed to create the \"in_signal\" file in \"/sys/kernel/fptrapall\"\n");
        }

        pr_info("fptrapall_sysfs initialized successfully\n");

        return res;
}

void
fptrapall_sysfs_deinit(void)
{
        kobject_put(fptrapall_sysfs_kobject);
        pr_info("fptrapall_sysfs un-initialized successfully\n");
}

