#define _GNU_SOURCE
#include <sched.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>

/* Functional-only observation. Never enabled for timing measurements. */
static void observe(const char *name, int child) {
  char path[1024];
  const char *directory = getenv("ORT_DIR");
  if (!directory) _exit(80);
  if (snprintf(path, sizeof path, "%s/%s.json", directory, name) >= (int)sizeof path) _exit(81);
  int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0644);
  if (fd < 0) _exit(82);
  cpu_set_t set;
  CPU_ZERO(&set);
  struct rlimit rt, pr;
  struct sched_param sp;
  if (sched_getaffinity(0, sizeof set, &set) || getrlimit(RLIMIT_RTTIME, &rt) ||
      getrlimit(RLIMIT_RTPRIO, &pr) || sched_getparam(0, &sp)) _exit(83);
  int policy = sched_getscheduler(0);
  int cpu = atoi(getenv("ORT_CPU"));
  int expected = child ? SCHED_OTHER : atoi(getenv("ORT_POLICY"));
  int ok = policy == expected && sp.sched_priority == (child ? 0 : ((expected & ~SCHED_RESET_ON_FORK) == SCHED_FIFO))
    && CPU_COUNT(&set) == 1 && CPU_ISSET(cpu, &set)
    && (child || getpid() == atoi(getenv("ORT_PID")))
    && rt.rlim_cur == strtoull(getenv("ORT_RTSOFT"), NULL, 10)
    && rt.rlim_max == strtoull(getenv("ORT_RTHARD"), NULL, 10)
    && pr.rlim_cur == strtoull(getenv("ORT_RTPRIO"), NULL, 10)
    && pr.rlim_max == pr.rlim_cur;
  dprintf(fd, "{\"pid\":%d,\"tid\":%ld,\"uid\":%d,\"policy\":%d,\"priority\":%d,\"cpu\":%d,\"rttime\":[%llu,%llu],\"rtprio\":[%llu,%llu],\"ok\":%s}\n",
    getpid(), syscall(SYS_gettid), getuid(), policy, sp.sched_priority, cpu,
    (unsigned long long)rt.rlim_cur,(unsigned long long)rt.rlim_max,
    (unsigned long long)pr.rlim_cur,(unsigned long long)pr.rlim_max,ok ? "true" : "false");
  fsync(fd); close(fd);
  if (!ok) _exit(84);
}
