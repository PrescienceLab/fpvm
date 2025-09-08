#pragma once

#include <stdint.h>
#include <fpvm/config.h>
#include <stdio.h>


typedef struct pulse_event {
  const char *name; // Must be static
  uint64_t start;
  uint64_t duration;
  int thread_id;
} pulse_event_t;

void pulse_start(const char *output_path);
void pulse_stop(void);
void pulse_flush(void);
uint64_t pulse_timestamp(void);

void pulse_track(pulse_event_t *e);

static inline pulse_event_t pulse_begin_event(const char *name) {
  pulse_event_t e;
  e.name = name;
  e.start = pulse_timestamp();
  e.thread_id = 0;
  return e;
}
static inline void pulse_end_event(pulse_event_t *e) {
  e->duration = pulse_timestamp() - e->start; 
  pulse_track(e);
}

#ifdef CONFIG_ENABLE_PULSE_PROFILING
#define PULSE_PROFILE_SCOPE(name)                                              \
  __attribute__((cleanup(pulse_end_event))) pulse_event_t e_##__LINE__ =       \
      pulse_begin_event(name)

#else
#define PULSE_PROFILE_SCOPE(name)
#endif

