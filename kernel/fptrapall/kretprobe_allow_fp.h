#ifndef __FPTRAPALL_KRETPROBE_ALLOW_FP_H__
#define __FPTRAPALL_KRETPROBE_ALLOW_FP_H__

int
setup_allow_fp_kprobes(void);

int
remove_allow_fp_kprobes(void);

#endif
