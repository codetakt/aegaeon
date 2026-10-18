#include "observe.h"
#include <signal.h>
#include <pthread.h>
#include <sys/wait.h>

static int softfd;
static void soft(int sig) { (void)sig; const char x[] = "SIGXCPU\n"; if (write(softfd, x, sizeof x - 1) < 0) _exit(85); }
static void *sleeper(void *unused) { (void)unused; for (;;) pause(); return NULL; }
int main(int argc, char **argv) {
  if (argc != 2) return 70;
  observe("target", 0);
  if (!strcmp(argv[1], "exit")) return 0;
  if (!strcmp(argv[1], "busy")) {
    char path[1024];
    snprintf(path, sizeof path, "%s/soft-signal.txt", getenv("ORT_DIR"));
    softfd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0644);
    if (softfd < 0) return 71;
    struct sigaction sa = {0}; sa.sa_handler = soft; sigaction(SIGXCPU, &sa, NULL);
    volatile unsigned long long x=0; for (;;) x++;
  }
  if (!strcmp(argv[1], "fork")) {
    pid_t p = fork(); if (p < 0) return 72;
    if (!p) { observe("child", 1); for (;;) pause(); }
    for (;;) pause();
  }
  if (!strcmp(argv[1], "thread")) {
    pthread_t th; if (pthread_create(&th, NULL, sleeper, NULL)) return 73;
    for (;;) pause();
  }
  if (!strcmp(argv[1], "blocking")) {
    for (;;) { volatile unsigned x=0; for (int i=0;i<100;i++) x++; usleep(10000); }
  }
  return 74;
}
