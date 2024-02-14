#ifndef _PERF
#define _PERF

#include <string.h>
#include <stdio.h>
#include <stdint.h>

typedef struct perf_stat {
  char *name;
  uint64_t start;  // last starting rdtsc
  uint64_t n;
  uint64_t sum;
  uint64_t sum2;
  uint64_t min_val;
  uint64_t max_val;
} perf_stat_t;

static inline void perf_stat_init(perf_stat_t *p, char *name) {
  memset(p, 0, sizeof(*p));
  p->min_val = -1;
  p->name = name;
}

static inline void perf_stat_start(perf_stat_t *p) {
  p->start = rdtsc();
}

static inline void perf_stat_end(perf_stat_t *p) {
  uint64_t end = rdtsc();
  uint64_t dur = end - p->start;

  p->n++;
  p->sum += dur;
  p->sum2 += dur * dur;
  if (dur < p->min_val) {
    p->min_val = dur;
  }
  if (dur > p->max_val) {
    p->max_val = dur;
  }
}

static inline void perf_stat_print(perf_stat_t *p, FILE *f, char *prefix) {
  double mean = (double)p->sum / p->n;
  double std = sqrt((double)p->sum2 / p->n - mean * mean);
  fprintf(f, "%s%s : count=%lu sum=%lu sum2=%lu avg=%lf std=%lf min=%lu max=%lu\n", prefix, p->name, p->n,
	  p->sum, p->sum2, mean, std, p->min_val, p->max_val);
}


#endif
