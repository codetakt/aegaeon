/* Native batch context only; no calls from inside the measured loop. */
#ifndef AEGAEON_DUDECT_CONTEXT_H
#define AEGAEON_DUDECT_CONTEXT_H
#include <sched.h>
#include <sys/resource.h>
#include <time.h>

typedef struct {
    uint64_t monotonic_ns, cpu, minor_faults, major_faults;
    uint64_t voluntary_switches, involuntary_switches, user_us, system_us;
} dudect_context_t;

static dudect_context_t dudect_context(void) {
    struct timespec now;
    struct rusage usage;
    if (clock_gettime(CLOCK_MONOTONIC, &now) || getrusage(RUSAGE_SELF, &usage)) abort();
    int cpu = sched_getcpu();
    dudect_context_t result = {
        (uint64_t)now.tv_sec * 1000000000 + (uint64_t)now.tv_nsec,
        cpu < 0 ? UINT64_MAX : (uint64_t)cpu,
        (uint64_t)usage.ru_minflt, (uint64_t)usage.ru_majflt,
        (uint64_t)usage.ru_nvcsw, (uint64_t)usage.ru_nivcsw,
        (uint64_t)usage.ru_utime.tv_sec * 1000000 + (uint64_t)usage.ru_utime.tv_usec,
        (uint64_t)usage.ru_stime.tv_sec * 1000000 + (uint64_t)usage.ru_stime.tv_usec
    };
    return result;
}
#endif
