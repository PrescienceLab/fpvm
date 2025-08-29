
#define DO_NOT_DEFINE_EXTRA_SYMBOL_MACROS
#include "extra_symbols.h"

#define DEFINE_UNEXPORTED_SYMBOL(\
	__SYMBOL,\
	__TYPE)\
unsigned long __SYMBOL ## _addr = 0;\
__TYPE *__SYMBOL ## _ptr = NULL;\
module_param_named(__SYMBOL, __SYMBOL ## _addr, ulong, 0);\
MODULE_PARM_DESC(__SYMBOL, "Address of the \"" #__SYMBOL "\" symbol");

UNEXPORTED_SYMBOLS_XLIST(DEFINE_UNEXPORTED_SYMBOL)

#undef DEFINE_UNEXPORTED_SYMBOL

int
setup_unexported_symbols(void) 
{
#define SETUP_SYMBOL(__SYMBOL,...)\
    if(__SYMBOL ## _addr == 0) {\
	return -1;\
    } else {\
	__SYMBOL ## _ptr = (void*) __SYMBOL ## _addr;\
    }

    UNEXPORTED_SYMBOLS_XLIST(SETUP_SYMBOL)

#undef SETUP_SYMBOL

    return 0;
}

