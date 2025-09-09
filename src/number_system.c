// weak versions of basic functions in case the
// altmath system does not provide them

#define WEAK __attribute__((weak))
#define UNUSED __attribute__((unused))

void WEAK fpvm_number_init(UNUSED void *x) {} 
void WEAK fpvm_number_deinit(UNUSED void *x) {}

void WEAK fpvm_number_system_init(void) {}
void WEAK fpvm_number_system_deinit(void) {}
