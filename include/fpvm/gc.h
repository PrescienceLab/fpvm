#pragma once


#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include <stdint.h>

#include <fpvm/fpvm_common.h>

typedef void (*fpvm_gc_callback_t)(void *);

// call with the constructor for your number system
int   fpvm_gc_init(fpvm_gc_callback_t constructor, fpvm_gc_callback_t destructor);
void *fpvm_gc_alloc(size_t sz);

// run a round of garbage collection, returning how many items were freed
unsigned fpvm_gc_run(void);

// box a pointer into a form that the garbage collector can find :)
// Having the GC actually involving doubles/floats might be a bad idea...
double   fpvm_gc_box(void *ptr, int sign);
// same, but to uint
uint64_t NO_TOUCH_FLOAT fpvm_gc_box_to_uint(void *ptr, int sign);
void     NO_TOUCH_FLOAT fpvm_gc_box_to_ptr(void *ptr, void *target, int sign);
// unbox a double into a void*,
// indicate whether the value represented in val has been
// negated external to alt number system control, which the
// alt number system needs to be aware of
//    This is due to xor 1<<63, [value] being a way sign can be flipped
void *fpvm_gc_unbox(double val, int *sign);
// unbox a uint64_t into a void*
void * NO_TOUCH_FLOAT fpvm_gc_unbox_from_uint(uint64_t val, int *sign);
// unbox from a pointer to  void* (ie, is the thing pointed to a nanbox)
void * NO_TOUCH_FLOAT fpvm_gc_unbox_from_ptr(void *val, int *sign);

// return 1 if the double is a boxed pointer that we are tracking in the GC
int fpvm_gc_is_tracked_nan(double nanbox);
// same, but from uint64_t
int NO_TOUCH_FLOAT fpvm_gc_is_tracked_nan_from_uint(uint64_t nanbox);
// same, but given a pointer (ie, is the thing pointed to a nanbox)
int NO_TOUCH_FLOAT fpvm_gc_is_tracked_nan_from_ptr(void *nanbox);


#ifdef __cplusplus
}
#endif
