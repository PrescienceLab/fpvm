#include <fpvm/gc.h>

#include <chrono>
#include <fpvm/number_system.h> // For fpvm_alt_apply_sign 
#include <fpvm/nan_boxing.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <unordered_map>
#include <vector>

namespace gc {
  // a region is a block of virtual memory that the garbage
  // collector is interested in. It is parsed from /proc/self/maps
  // and is only created on memory map regions that are writable
  struct region {
    off_t start;
    off_t end;

    template <typename T>
    bool contains(T addr) const {
      return start >= (off_t)addr && (off_t)addr < end;
    }
    size_t size(void) const {
      return end - start;
    }
  };

  // a box is a float that NaNboxes a 16bit value
  // that offsets into the FPVM heap w/ a handle
  // (2^23 floats should be enough, maybe)
  class box {
   public:
    void set(uint64_t);
    // is this a valid nanbox?
    bool valid(void) const;
    // inline void store(float *f) const { *f = as.f64; }
    inline void store(double *d) const {
      *d = as.f64;
    }
    void *get(void) const;
    double get_boxed(void) const {
      return as.f64;
    }
    uint64_t get_boxed_uint(void) const {
      return as.u64;
    }
    void set_boxed(double f) {
      as.f64 = f;
    }
    void set_boxed(uint64_t u) {
      as.u64 = u;
    }

   private:
    union {
      uint64_t u64;
      double f64;
      struct __attribute__((__packed__)) {
        uint64_t storage : 51;
        uint64_t signal : 1;

        unsigned exp : 11;
        unsigned sign : 1;
      } bits;
    } as;
  };
};  // namespace gc

void gc::box::set(uint64_t val) {
  as.u64 = NANBOX_ENCODE(val, 0LLU);
}

void *gc::box::get(void) const {
  return NANBOX_DECODE(as.u64);
}

// is it a valid nanbox?
bool gc::box::valid(void) const {
  return ISNAN(as.u64);
}

// Global variables
static fpvm_gc_callback_t gcConstructor = NULL;
static fpvm_gc_callback_t gcDestructor = NULL;
static std::unordered_map<void *, bool> *_gcHeap = NULL;

static auto &get_heap(void) {
  if (_gcHeap == NULL) {
    _gcHeap = new std::unordered_map<void *, bool>;
  }

  return *_gcHeap;
}

// a nice function to get the current time
using namespace std::chrono;
inline uint64_t time_us(void) {
  return std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::system_clock::now().time_since_epoch())
      .count();
}

uint64_t getrsp() {
  uint64_t retVal;
  __asm__ __volatile__("movq %%rsp, %0" : "=a"(retVal) : : "memory");
  return retVal;
}

extern "C" void dumpregs(void *target);

template <typename Fn>
void find_nans(const std::vector<gc::region> &regions, Fn cb) {
  for (const auto &r : regions) {
    // auto start_time = time_us();
    auto start = (gc::box *)r.start;
    auto end = (gc::box *)r.end;

    uint64_t rsp = getrsp();
    if (r.contains(rsp)) start = (gc::box *)rsp;

    int found = 0;
    for (auto p = start; p < end; p++) {
      if (p->valid()) {
        found++;
        cb(r, p);
      }
    }
  }
}

static std::vector<gc::region> gc_find_regions() {
  // TODO: maybe cache this, and use calls to mmap, sbrk, munmap, mremap to
  // invalidate it.
  FILE *f = fopen("/proc/self/maps", "r");

  // TODO: optimize stack.
  std::vector<gc::region> regions;

  // hopefully all /proc/self/maps lines are less than 256 bytes
  char line_buf[256];

  // read all the lines of the
  while (!feof(f)) {
    off_t start, end;
    char flags[5];  // "rwxp\0"
    if (fgets(line_buf, 256, f) == 0) break;

    int count = sscanf(line_buf, "%lx-%lx %s\n", &start, &end, flags);
    if (count == 3) {
      // printf("region:%s", line_buf);

      // if (strstr(line_buf, ".so") != NULL) continue;
      if (flags[1] == 'w') {
        gc::region r;
        r.start = start;
        r.end = end;
        regions.push_back(r);
      }
    }
  }

  fclose(f);
  return regions;
}

static uint64_t instructions = 0;
static uint64_t last_run_ms = 0;
static uint64_t start_time = 0;
static uint64_t last_instruction_count = 0;

static FILE *gcLogFile = NULL;

extern "C" unsigned fpvm_gc_run(void) {
  uint64_t now_ms = time_us() / 1000;

  if (start_time == 0) start_time = now_ms;
  instructions++;

  if (now_ms - last_run_ms < 10000) {
    return 0;
  }

  last_run_ms = now_ms;
  // run a mark + sweep phase

  // save xmm registers to memory.
  uint64_t xmms[32][2];
  dumpregs(xmms);

  // ====================== MARK ======================

  auto &heap = get_heap();
  // clear all the previous markings
  for (auto &kv : heap) {
    kv.second = false;
  }

  size_t total_size = 0;

  auto start = time_us();
  auto regions = gc_find_regions();
  for (auto r : regions) {
    total_size += r.size();
  }
  find_nans(regions, [&](auto &region, gc::box *b) {
    void *i = b->get();
    auto it = heap.find(i);
    if (it != heap.end()) {
      (*it).second = true;
    }
  });

  // ====================== SWEEP ======================
  std::vector<void *> toFree;
  for (auto &kv : heap) {
    // if it's marked, add it to the toFree list to be freed later
    if (!kv.second) toFree.push_back(kv.first);
  }

  unsigned freed = toFree.size();

  for (auto ptr : toFree) {
    if (gcDestructor) gcDestructor(ptr);

    // free the pointer w/ free :)
    free(ptr);
    // remove the pointer from the heap
    heap.erase(heap.find(ptr));
  }

  // if (gcLogFile == NULL) {
  //   gcLogFile = fopen("gc_log.csv", "w");
  //   fprintf(gcLogFile, "time, instructions, freed, alive, gc_latency
  //   (us)\n");
  // }

  // // printf("[GC] swept %zu regions, %zu bytes (freed %d, %zu alive) in %lu
  // // us\n", regions.size(), total_size, freed, get_heap().size(), time_us() -
  // // start);
  // fprintf(gcLogFile, "%lu, %lu, %u, %lu, %lu\n", now_ms - start_time,
  //         instructions, freed, get_heap().size(), time_us() - start);
  // fflush(gcLogFile);
  instructions = 0;
  return freed;
}

extern "C" void *fpvm_gc_alloc(size_t sz) {
  void *ptr = calloc(sz, 1);
  if (gcConstructor != NULL) (*gcConstructor)(ptr);
  get_heap()[ptr] = false;  // not marked
  return ptr;
}

extern "C" void fpvm_gc_init(fpvm_gc_callback_t c, fpvm_gc_callback_t d) {
  gcConstructor = c;
  gcDestructor = d;
}

extern "C" double fpvm_gc_box(void *ptr) {
  gc::box b;

  b.set((uint64_t)ptr);
  return b.get_boxed();
}

extern "C" uint64_t NO_TOUCH_FLOAT fpvm_gc_box_to_uint(void *ptr) {
  gc::box b;

  b.set((uint64_t)ptr);
  return b.get_boxed_uint();
}

extern "C" void NO_TOUCH_FLOAT fpvm_gc_box_to_ptr(void *ptr, void *target) {
  gc::box b;

  b.set((uint64_t)ptr);
  b.store((double*)target);
}



static bool is_tracked(void *ptr) {
  if (get_heap().count(ptr) != 0) return true;
  return false;
}

extern "C" void *fpvm_gc_unbox(double val) {
  gc::box b;
  b.set_boxed(val);

  if (!b.valid()) return 0;
  void *ptr = b.get();
  return is_tracked(ptr) ? ptr : nullptr;
}

extern "C" void * NO_TOUCH_FLOAT fpvm_gc_unbox_from_uint(uint64_t val)
{
  gc::box b;
  b.set_boxed(val);

  if (!b.valid()) return 0;
  void *ptr = b.get();
  return is_tracked(ptr) ? ptr : nullptr;
}

extern "C" void * NO_TOUCH_FLOAT fpvm_gc_unbox_from_ptr(void *val)
{
  return fpvm_gc_unbox_from_uint((*(uint64_t*)val));
}

extern "C" int fpvm_gc_is_tracked_nan(double val) {
  gc::box b;
  b.set_boxed(val);

  if (!b.valid()) return 0;
  void *ptr = b.get();

  return is_tracked(ptr) ? 1 : 0;
}

extern "C" int NO_TOUCH_FLOAT fpvm_gc_is_tracked_nan_from_uint(uint64_t val) {
  gc::box b;
  b.set_boxed(val);

  if (!b.valid()) return 0;
  void *ptr = b.get();

  return is_tracked(ptr) ? 1 : 0;
}


extern "C" int NO_TOUCH_FLOAT fpvm_gc_is_tracked_nan_from_ptr(void *val) {
  gc::box b;
   b.set_boxed(*(uint64_t*)val);

  if (!b.valid()) return 0;
  void *ptr = b.get();

  return is_tracked(ptr) ? 1 : 0;
}
