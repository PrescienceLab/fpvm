#include <fpvm/pulse.h>

#include <stdio.h>
#include <time.h>
#include <sys/time.h>

static uint64_t pulse_start_time = 0;

#define PULSE_BUFFER_LEN 10000
// How many events are there in the buffer
static long pulse_events = 0;
static pulse_event_t events[PULSE_BUFFER_LEN];
// How many events have been flushed to the output file
static long flushed_events = 0;
static FILE *output = NULL;

void pulse_start(const char *output_path) {
#ifdef CONFIG_ENABLE_PULSE_PROFILING
  // Open the output file for writing.
  output = fopen(output_path, "w");

  // Write the header for the JSON file.
  fprintf(output, "{\"otherData\": {}, \"displayTimeUnit\": \"ns\", \"traceEvents\":[");
#endif
}

void pulse_stop(void) {
#ifdef CONFIG_ENABLE_PULSE_PROFILING
  pulse_flush();
  fprintf(output, "]}\n");
#endif
}

void pulse_flush(void) {
#ifdef CONFIG_ENABLE_PULSE_PROFILING
  for (int i = 0; i < pulse_events; i++) {
    pulse_event_t *e = &events[i];
    if (flushed_events > 0) {
      fprintf(output, ",");
    }
    flushed_events++;
    // Write the event to the output file.
    fprintf(output,
            "{\"name\": \"%s\", \"ph\": \"X\", \"ts\": %lu, \"dur\": %lu, "
            "\"pid\": 0, \"tid\": %d}",
            e->name, e->start, e->duration, e->thread_id);
  }
  pulse_events = 0;
#endif
}

uint64_t pulse_timestamp(void) {
  // get the current time in nanoseconds
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  uint64_t current_time = (uint64_t)ts.tv_sec * 1000000000 + (uint64_t)ts.tv_nsec;
  if (pulse_start_time == 0) {
    pulse_start_time = current_time;
  }
  return current_time - pulse_start_time;
  /* uint32_t lo, hi; */
  /* __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi)); */
  /* return ((uint64_t)hi << 32) | lo; */
}

void pulse_track(pulse_event_t *e) {
  // Quickly exit if we aren't tracking.
  if (output == NULL)
    return;

  if (pulse_events >= PULSE_BUFFER_LEN) {
    return;
    pulse_flush();
  }
  if (pulse_events < PULSE_BUFFER_LEN) {
    events[pulse_events++] = *e;
  }
}
