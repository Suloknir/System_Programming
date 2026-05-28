// todo: sigint handler
// todo: worker notifies master by sending signal to pid = getpgrp() (master pid)
// todo: sigrtmin + 1 handler in master if worker found password
#define _GNU_SOURCE
#include "ipc_datatypes.h"
#include <err.h>
#include <fcntl.h>
#include <mqueue.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef CRACK_FOUND
#define CRACK_FOUND 1
#endif

#ifndef CRACK_NOT_FOUND
#define CRACK_NOT_FOUND 0
#endif

#ifndef CRACK_ERR
#define CRACK_ERR -1
#endif

struct CleanerData
{
    char *workerArgv[4];
    struct ShmData *shm_mapped;
    struct sigaction *old_action;
    const char *queue_name;
    const char *shm_name;
    size_t shm_size;
    int pswd_fd;
    int shm_fd;
    int queue_des;
};

struct CleanerData cleaner_data = {
    {"./worker", NULL, NULL, NULL}, //
    NULL, //
    NULL, //
    "/hash_cracker_queue", //
    "/hash_cracker_shm", //
    0, //
    -1, //
    -1, //
    -1 //
};

void parse_argv(int argc, char *const *argv, char **ret_hash, char **ret_filepath, int *ret_n_jobs)
{
    if (!ret_hash || !ret_filepath || !ret_n_jobs)
        err(EXIT_FAILURE, "parse_argv requires non-null arguments\n");
    bool p = false;
    bool f = false;
    bool n = false;
    opterr = 0;
    int ret;
    while ((ret = getopt(argc, argv, "p:f:n:")) != -1)
    {
        switch (ret)
        {
            case 'p':
                p = true;
                *ret_hash = optarg;
                break;
            case 'f':
                f = true;
                *ret_filepath = optarg;
                break;
            case 'n':
            {
                n = true;
                char *endptr;
                const int val = (int)strtol(optarg, &endptr, 0);
                if (endptr == optarg || val < 1)
                    err(EXIT_FAILURE, "%s: option '%c' requires number >= 1 as an argument\n", argv[0], ret);
                *ret_n_jobs = val;
                break;
            }
            case '?':
                err(EXIT_FAILURE, "%s: Option '%c' requires argument\n", argv[0], optopt);
                break;
            default:
                abort();
        }
    }
    if (!p || !f || !n)
    {
        fprintf(stderr, "Parameters 'p', 'f', 'n' are mandatory\n");
        fprintf(stderr, "Usage: %s -p [hashed password] -f [file] -n [n jobs]\n", argv[0]);
        exit(EXIT_FAILURE);
    }
}

void sigint_handler(int signum) // NOLINT
{
    // exit(EXIT_FAILURE);
    // printf("got signal %d\n", signum);
}

void crack_cleaner(void)
{
    if (cleaner_data.workerArgv[1])
        free(cleaner_data.workerArgv[1]);
    if (cleaner_data.workerArgv[2])
        free(cleaner_data.workerArgv[2]);
    if (cleaner_data.shm_mapped)
        munmap(cleaner_data.shm_mapped, cleaner_data.shm_size);
    if (cleaner_data.shm_fd != -1)
        shm_unlink(cleaner_data.shm_name);
    if (cleaner_data.pswd_fd != -1)
        close(cleaner_data.pswd_fd);
    if (cleaner_data.queue_des != -1)
    {
        mq_close(cleaner_data.queue_des);
        mq_unlink(cleaner_data.queue_name);
    }
    sigaction(SIGINT, cleaner_data.old_action, NULL);
}

/// returns -1 on failure and 0 on succes
short init_ipc(const char *salted_hash, long queue_max_msg)
{
    struct mq_attr attr = {0};
    attr.mq_msgsize = sizeof(struct QueueMsg);
    attr.mq_maxmsg = queue_max_msg;
    // const mqd_t queue_des = mq_open(data.queue_name, O_RDWR | O_CREAT | O_EXCL, 0666, attr);
    cleaner_data.queue_des = mq_open(cleaner_data.queue_name, O_RDWR | O_CREAT, 0666, attr);
    if (cleaner_data.queue_des == -1)
    {
        fprintf(stderr, "mq_open error\n");
        return -1;
    }

    // const int shm_fd = shm_open(data.shm_name, O_RDWR | O_CREAT | O_EXCL, 0666);
    cleaner_data.shm_fd = shm_open(cleaner_data.shm_name, O_RDWR | O_CREAT, 0666);
    if (cleaner_data.shm_fd == -1)
    {
        crack_cleaner();
        fprintf(stderr, "shmopen error\n");
        return -1;
    }
    cleaner_data.shm_size = sizeof(struct ShmData) + strlen(salted_hash);
    if (ftruncate(cleaner_data.shm_fd, (off_t)cleaner_data.shm_size) == -1)
    {
        crack_cleaner();
        fprintf(stderr, "ftruncate error\n");
        return -1;
    }
    cleaner_data.shm_mapped =
        mmap(NULL, cleaner_data.shm_size, PROT_READ | PROT_WRITE, MAP_SHARED, cleaner_data.shm_fd, 0);
    if (cleaner_data.shm_mapped == MAP_FAILED)
    {
        crack_cleaner();
        fprintf(stderr, "mmap error\n");
        return -1;
    }
    cleaner_data.shm_mapped->progress = 0;
    cleaner_data.shm_mapped->force_stop = false;
    strcpy(cleaner_data.shm_mapped->salted_hash, salted_hash);
    return 0;
}

/// If 'CRACK_FOUND' was returned, memory allocated in '*ret_found'
/// should be freed manually.\n If 'CRACK_NOT_FOUND' was returned,
/// '*ret_found' is equal to NULL.\n Otherwise, '*ret_found' value is
/// undefined. If 'NULL' is passed as 'ret_found', value is not set
/// at all.
short crack(const char *salted_hash, const char *pswd_path, int total_jobs, char **ret_found)
{
    struct sigaction sa = {0};
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO;
    sa.sa_handler = sigint_handler;
    sigaction(SIGINT, &sa, cleaner_data.old_action);

    const int max_workers = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (init_ipc(salted_hash, (long)max_workers * 2) != 0)
        return CRACK_ERR;
    cleaner_data.pswd_fd = open(pswd_path, O_RDONLY);
    if (cleaner_data.pswd_fd == -1)
    {
        crack_cleaner();
        fprintf(stderr, "open error\n");
        return CRACK_ERR;
    }
    printf("queue name: %s\n", cleaner_data.queue_name);

    // cleaner_data.workerArgv[0] = "./worker";
    cleaner_data.workerArgv[1] = malloc(strlen(cleaner_data.queue_name) + 1);
    strcpy(cleaner_data.workerArgv[1], cleaner_data.queue_name);
    const size_t buff_len = 16;
    cleaner_data.workerArgv[2] = malloc(buff_len);
    int created = 0;
    const int to_create = max_workers > total_jobs ? total_jobs : max_workers;
    pid_t workers[to_create];
    for (int i = 0; i < to_create; i++)
    {
        workers[i] = fork();
        if (workers[i] == -1)
        {
            for (int j = 0; j < created; j++)
            {
                kill(workers[j], SIGKILL);
                waitpid(workers[j], NULL, 0);
            }
            crack_cleaner();
            fprintf(stderr, "fork error\n");
            return CRACK_ERR;
        }
        else if (workers[i] == 0)
        {
            snprintf(cleaner_data.workerArgv[2], buff_len, "%d",
                     total_jobs); // todo: change to count n jobs for a specific process
            execve("./worker", cleaner_data.workerArgv, NULL);
            err(EXIT_FAILURE, "execve error\n");
        }
        else
        {
            created++;
        }
    }

    for (int i = 0; i < created; i++)
    {
        waitpid(workers[i], NULL, 0);
        printf("%d finished\n", workers[i]);
    }
    crack_cleaner();
    if (ret_found != NULL)
        *ret_found = NULL;
    return CRACK_NOT_FOUND;
}

int main(const int argc, char *argv[])
{
    char *salted_hash = NULL;
    char *pswd_path = NULL;
    int total_jobs = -1;
    parse_argv(argc, argv, &salted_hash, &pswd_path, &total_jobs);
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    char *found = NULL;
    crack(salted_hash, pswd_path, total_jobs, &found); // todo: switch statement
    clock_gettime(CLOCK_MONOTONIC, &end);
    const double elapsed = (double)(end.tv_sec - start.tv_sec) + (double)(end.tv_nsec - start.tv_nsec) / 1e9;
    printf("\nFinished in %.2fs,\n", elapsed);
    printf("Process group: %d, pid: %d\n", getpgrp(), getpid());
    return 0;
}
