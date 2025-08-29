#ifndef __FPTRAPALL_EXTRA_SYMBOLS_H__
#define __FPTRAPALL_EXTRA_SYMBOLS_H__

#include <linux/string.h>
#include <linux/module.h>
#include <linux/kernel.h>

typedef int(force_sig_fault_f)(int,int,void __user *);
typedef unsigned long(uprobe_get_trap_addr_f)(struct pt_regs*);

#define UNEXPORTED_SYMBOLS_XLIST(X)\
X(force_sig_fault, force_sig_fault_f)\
X(uprobe_get_trap_addr, uprobe_get_trap_addr_f)\


#define DECLARE_UNEXPORTED_SYMBOL(\
	__SYMBOL,\
	__TYPE)\
extern unsigned long __SYMBOL ## _addr;\
extern __TYPE *__SYMBOL ## _ptr;

UNEXPORTED_SYMBOLS_XLIST(DECLARE_UNEXPORTED_SYMBOL)

#undef DECLARE_UNEXPORTED_SYMBOL

int
setup_unexported_symbols(void);

#ifndef DO_NOT_DEFINE_EXTRA_SYMBOL_MACROS
#define force_sig_fault (*force_sig_fault_ptr)
#define uprobe_get_trap_addr (*uprobe_get_trap_addr_ptr)
#endif

#endif
