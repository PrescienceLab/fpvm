#ifndef _PERF
#define _PERF

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <math.h>

#include <fpvm/fpvm.h>
#include <fpvm/arch.h>
#include <fpvm/pulse.h>

typedef struct perf_stat {
  char *name;
  uint64_t start;  // last starting cyclecount
  uint64_t n;
  uint64_t sum;
  uint64_t sum2;
  uint64_t min_val;
  uint64_t max_val;

  #ifdef CONFIG_ENABLE_PULSE_PROFILING
  pulse_event_t pulse_event; // for pulse profiling
  #endif

} perf_stat_t;

static inline void perf_stat_init(perf_stat_t *p, char *name) {
  memset(p, 0, sizeof(*p));
  p->min_val = -1;
  p->name = name;
}

// The start and end routines are "NO_TOUCH_FLOAT" so they can be used
// to measure anywhere

static inline void NO_TOUCH_FLOAT perf_stat_start(perf_stat_t *p) {
  p->start = arch_cycle_count();
  #ifdef CONFIG_ENABLE_PULSE_PROFILING
  p->pulse_event.start = pulse_timestamp();
  #endif
}

static inline void NO_TOUCH_FLOAT perf_stat_end(perf_stat_t *p) {
  uint64_t end = arch_cycle_count();
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


#ifdef CONFIG_ENABLE_PULSE_PROFILING
  p->pulse_event.name = p->name;
  p->pulse_event.duration = pulse_timestamp() - p->pulse_event.start;
  p->pulse_event.thread_id = 0;
  pulse_track(&p->pulse_event);
#endif
}

static inline void perf_stat_print(perf_stat_t *p, FILE *f, char *prefix) {
  double mean = DIVF((double)p->sum,(double)p->n);
  double std = sqrt(DIVF((double)p->sum2,(double)p->n) - mean * mean);
  fprintf(f, "%s%s : count=%lu sum=%lu sum2=%lu avg=%lf std=%lf min=%lu max=%lu\n", prefix, p->name, p->n,
	  p->sum, p->sum2, mean, std, p->min_val, p->max_val);
}


#endif
