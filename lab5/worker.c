#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>

#define SIG_SOFT (SIGRTMIN + 1)
#define SIG_HEARTBEAT (SIGRTMIN + 2)

int seq = 0;
pid_t parent_pid;
pid_t my_pid;

void failure_skip(int signum)
{
    seq++;
    printf("[LOCAL] PID=%d seq=%d type=SKIPPED\n", my_pid, seq);
}

void failure_soft(int signum)
{
    seq++;
    printf("[LOCAL] PID=%d seq=%d type=FAILURE_SOFT\n", my_pid, seq);
    union sigval value;
    value.sival_int = seq;
    sigqueue(parent_pid, SIG_SOFT, value);
}

void heartbeat()
{
    seq++;
    printf("[LOCAL] PID=%d seq=%d type=HEARTBEAT\n", my_pid, seq);
    union sigval value;
    value.sival_int = seq;
    sigqueue(parent_pid, SIG_HEARTBEAT, value);
}

int main(const int argc, char *argv[])
{
    if (argc != 2)
    {
        fprintf(stderr, "%s: Inappropriate number of arguments\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    parent_pid = getppid();
    my_pid = getpid();
    struct sigaction sa;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = failure_skip;
    sigaction(SIGUSR1, &sa, NULL);

    sa.sa_handler = failure_soft;
    sigaction(SIGUSR2, &sa, NULL);
    char *endptr;
    int heartbeat_interval = (int) strtol(argv[1], &endptr, 0);
    if (endptr == argv[1] || heartbeat_interval <= 0)
    {
        fprintf(stderr, "%s: inappropriate heartbeat_interval\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    heartbeat();
    while (true)
    {
        struct timespec req_t = {heartbeat_interval, 0};
        struct timespec rem_t;
        while (nanosleep(&req_t, &rem_t) == -1)
            req_t = rem_t;
        heartbeat();
    }
}
