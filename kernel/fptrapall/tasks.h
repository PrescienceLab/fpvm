#ifndef __FPTRAPALL_TASK_H__
#define __FPTRAPALL_TASK_H__

#define FPTRAPALL_TASK_CR0_TS_SET   (1UL<<0)
#define FPTRAPALL_TASK_IN_SIGNAL    (1UL<<1)

// Modify the current process status
int
fptrapall_task_register(void);
int
fptrapall_task_unregister(void);
int
fptrapall_task_registered(void);

int
fptrapall_task_set(unsigned long flags);
int
fptrapall_task_clear(unsigned long flags);

unsigned long
fptrapall_task_get_flags(void);

// Global init/deinit
int
fptrapall_init_tasks(void);
void
fptrapall_deinit_tasks(void);

#endif
