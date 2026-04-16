#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#define BILLION 1000000000.0

#define SIG_SOFT (SIGRTMIN + 1)
#define SIG_HEARTBEAT (SIGRTMIN + 2)

int *seqs;
pid_t *pids;
char *workerArgv[3];
struct timespec *last_times;
int workers = -1;

int find(const pid_t pid)
{
    for (int i = 0; i < workers; i++)
        if (pids[i] == pid)
            return i;
    return -1;
}

void check_and_update_worker(const pid_t pid, int seq)
{
    const int id = find(pid);
    if (id < 0)
    {
        fprintf(stderr, "Unknown worker pid = %d\n", pid);
        exit(EXIT_FAILURE);
    }
    const int old_seq = seqs[id];
    if (old_seq + 1 != seq)
    {
        printf("[WARNING] PID=%d, nr of missing seqs=%d\n", pid, seq - old_seq - 1);
    }
    seqs[id] = seq;
    clock_gettime(CLOCK_MONOTONIC, &last_times[id]);
}

void sigint_handler(int signum)
{
    printf("\n[RECV] SIGINT received. Shutting down...\n");
    for (int i = 0; i < workers; i++)
        kill(pids[i], SIGKILL);
    free(workerArgv[1]);
    free(pids);
    free(last_times);
    free(seqs);
    exit(EXIT_SUCCESS);
}

void failure_soft_handler(int signum, siginfo_t *info, void *context)
{
    const pid_t pid = info->si_pid;
    const int seq = info->si_value.sival_int;
    printf("[RECV]  PID=%d seq=%d type=FAILURE_SOFT\n", pid, seq);
    check_and_update_worker(pid, seq);
}

void heartbeat_handler(int signum, siginfo_t *info, void *context)
{
    const pid_t pid = info->si_pid;
    const int seq = info->si_value.sival_int;
    printf("[RECV]  PID=%d seq=%d type=HEARTBEAT\n", pid, seq);
    check_and_update_worker(pid, seq);
}

int main(const int argc, char *argv[])
{
    int heartbeat_interval = -1;
    int max_time_to_wait_for_heartbeat = -1;
    int ret;
    while ((ret = getopt(argc, argv, "n:h:t:")) != -1)
    {
        int val = -1;
        bool arg_flag = false;
        if (ret == 'n' || ret == 'h' || ret == 't')
        {
            arg_flag = true;
            char *endptr;
            val = (int) strtol(optarg, &endptr, 0);
            if (endptr == optarg || val < 1)
            {
                fprintf(stderr, "%s: option '%c' requires number >= 1 as a parameter\n", argv[0], ret);
                exit(EXIT_FAILURE);
            }
        }
        if (!arg_flag)
            continue;
        switch (ret)
        {
            case 'n':
                workers = val;
                break;
            case 'h':
                heartbeat_interval = val;
                break;
            case 't':
                max_time_to_wait_for_heartbeat = val;
                break;
        }
    }
    if (workers == -1 || heartbeat_interval == -1 || max_time_to_wait_for_heartbeat == -1)
    {
        fprintf(stderr, "%s: options 'n', 'h', 't' are mandatory\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    if (max_time_to_wait_for_heartbeat <= heartbeat_interval)
    {
        fprintf(stderr, "%s: 't' has to be greater than 'h'\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    struct sigaction sa;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = heartbeat_handler;
    sigaction(SIG_HEARTBEAT, &sa, NULL);

    sa.sa_sigaction = failure_soft_handler;
    sigaction(SIG_SOFT, &sa, NULL);

    sa.sa_flags = 0;
    sa.sa_handler = sigint_handler;
    sigaction(SIGINT, &sa, NULL);

    seqs = calloc(workers, sizeof(int));
    pids = malloc(workers * sizeof(pid_t));
    last_times = malloc(workers * sizeof(struct timespec));

    // char *workerArgv[3];
    workerArgv[0] = "./worker";
    workerArgv[1] = malloc(16);
    workerArgv[2] = NULL;
    snprintf(workerArgv[1], 16, "%d", heartbeat_interval);
    for (int i = 0; i < workers; i++)
    {
        const pid_t pid = fork();
        if (pid == -1)
        {
            fprintf(stderr, "fork error\n");
            free(workerArgv[1]);
            free(pids);
            free(last_times);
            free(seqs);
            exit(EXIT_FAILURE);
        }
        if (pid == 0)
        {
            execv("./worker", workerArgv);
            fprintf(stderr, "exec error\n");
            exit(EXIT_FAILURE);
        }
        pids[i] = pid;
        clock_gettime(CLOCK_MONOTONIC, &last_times[i]);;
    }
    const struct timespec loop_sleep = {0, 10000000}; //10ms sleep to not drain cpu
    while (true)
    {
        nanosleep(&loop_sleep, NULL);
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        for (int i = 0; i < workers; i++)
        {
            const double elapsed = (double) (now.tv_sec - last_times[i].tv_sec) +
                                   (double) (now.tv_nsec - last_times[i].tv_nsec) / BILLION;
            if (elapsed > max_time_to_wait_for_heartbeat)
            {
                printf("[RECV]  PID=%d timeout, restarting...\n", pids[i]);
                kill(pids[i], SIGKILL);

                const pid_t new_pid = fork();
                if (new_pid == -1)
                {
                    fprintf(stderr, "fork error\n");
                    free(workerArgv[1]);
                    free(pids);
                    free(last_times);
                    free(seqs);
                    exit(EXIT_FAILURE);
                }
                if (new_pid == 0)
                {
                    execv("./worker", workerArgv);
                    fprintf(stderr, "exec error\n");
                    exit(EXIT_FAILURE);
                }
                pids[i] = new_pid;
                seqs[i] = 0;
                clock_gettime(CLOCK_MONOTONIC, &last_times[i]);
            }
        }
    }
}
