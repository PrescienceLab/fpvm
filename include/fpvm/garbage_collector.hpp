#pragma once
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <queue>
#include <cassert>
#include <unistd.h>

#define GC_DEBUG_PRINT if (GC_DEBUG) printf 

extern "C" void do_garbage_collect(allocator *);
void add_alloc(void * addr);
void remove_alloc(void* addr);