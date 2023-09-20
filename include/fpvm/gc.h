#pragma once


#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include <stdint.h>

typedef void (*fpvm_gc_callback_t)(void *);

// call with the constructor for your number system
void fpvm_gc_init(fpvm_gc_callback_t constructor, fpvm_gc_callback_t destructor);
void *fpvm_gc_alloc(size_t sz);

// run a round of garbage collection, returning how many items were freed
unsigned fpvm_gc_run(void);

// box a pointer into a form that the garbage collector can find :)
double fpvm_gc_box(void *ptr);
// unbox a double into a void*
void *fpvm_gc_unbox(double val);

// return 1 if the double is a boxed pointer that we are tracking in the GC
int fpvm_gc_is_tracked_nan(double nanbox);

#ifdef __cplusplus
}
#endif
