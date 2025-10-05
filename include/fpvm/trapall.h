#ifndef __FPVM_TRAPALL_H__
#define __FPVM_TRAPALL_H__

// PAD: eventually this needs to become part of
// the arch interface
#define TRAPALL_OFF()
#define TRAPALL_ON()

#if CONFIG_FPTRAPALL

#undef TRAPALL_OFF
#undef TRAPALL_ON
#define TRAPALL_OFF() fptrapall_clear_ts()
#define TRAPALL_ON()  fptrapall_set_ts()

void fptrapall_register();
void fptrapall_mark_in_signal();

void fptrapall_set_ts();
void fptrapall_clear_ts();

#endif

#endif
