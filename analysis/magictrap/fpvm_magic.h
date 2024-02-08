/*
  FPVM RT mmaps a page at FPVM_MAGIC_ADDR, sets the first quad
  to FPVM_MAGIC_COOKIE, and sets the second quad to the address
  of the entry point for correctness traps
*/


#define FPVM_MAGIC_ADDR    ((void*)0xf65ef65e000UL)
#define FPVM_MAGIC_COOKIE  0xf65ef65ef65ef65eUL
#define FPVM_TRAP_OFFSET   8

