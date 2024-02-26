/*
  We can invoke a correctness trap on the FPVM runtime in one of three ways,
  in order of preference:

  1. At startup, FPVM RT links to FPVM_MAGIC_TRAP_ENTRY_NAME
     and modifies it to point to the correctness trap entry point,
     The fpvm_magic notices this on first use.
  2. At startup, FPVM RT mmaps a page at FPVM_MAGIC_ADDR, sets the 
     first quad FPVM_MAGIC_COOKIE, and sets the second quad to 
     the entry point for correctness traps.   The fpvm_magic notices
     this on first use.
  3. The binary does not use magic traps, in which case the ordinary
     SIGTRAP handler is invoked
*/


typedef void (*fpvm_magic_trap_entry_t)(void * pt_regs);

#define FPVM_MAGIC_TRAP_ENTRY_NAME fpvm_correctness_trap_entry
#define FPVM_MAGIC_TRAP_ENTRY_NAME_STR "fpvm_correctness_trap_entry"

#define FPVM_MAGIC_ADDR    ((void*)0xf65ef65e000UL)
#define FPVM_MAGIC_COOKIE  0xf65ef65ef65ef65eUL
#define FPVM_TRAP_OFFSET   8


