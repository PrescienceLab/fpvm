#pragma once


#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include <stdint.h>

#include <fpvm/fpvm_common.h>
  
typedef void (*fpvm_gc_callback_t)(void *);

// call with the constructor for your number system
void fpvm_gc_init(fpvm_gc_callback_t constructor, fpvm_gc_callback_t destructor);
void *fpvm_gc_alloc(size_t sz);
  
// run a round of garbage collection, returning how many items were freed
unsigned fpvm_gc_run(void);

// box a pointer into a form that the garbage collector can find :)
double   fpvm_gc_box(void *ptr);
// same, but to uint
uint64_t NO_TOUCH_FLOAT fpvm_gc_box_to_uint(void *ptr);
void     NO_TOUCH_FLOAT fpvm_gc_box_to_ptr(void *ptr, void *target);
// unbox a double into a void*
void *fpvm_gc_unbox(double val);
// unbox a uint64_t into a void*
void * NO_TOUCH_FLOAT fpvm_gc_unbox_from_uint(uint64_t val);
// unbox from a pointer to  void* (ie, is the thing pointed to a nanbox)
void * NO_TOUCH_FLOAT fpvm_gc_unbox_from_ptr(void *val);

// return 1 if the double is a boxed pointer that we are tracking in the GC
int fpvm_gc_is_tracked_nan(double nanbox);
// same, but from uint64_t
int NO_TOUCH_FLOAT fpvm_gc_is_tracked_nan_from_uint(uint64_t nanbox);
// same, but given a pointer (ie, is the thing pointed to a nanbox)
int NO_TOUCH_FLOAT fpvm_gc_is_tracked_nan_from_ptr(void *nanbox);


#ifdef __cplusplus
}
#endif
