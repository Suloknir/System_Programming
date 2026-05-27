// todo: sigint handler
// todo: worker notifies master by sending signal to pid = getpgrp() (master pid)
// todo: sigrtmin + 1 handler in master if worker found password

#define _GNU_SOURCE
#include "ipc_datatypes.h"
#include <err.h>
#include <fcntl.h>
#include <mqueue.h>
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

void crack_cleaner(char **workerArgv, //
                   struct ShmData *shm_mapped, //
                   size_t shm_size, //
                   int pswd_fd, //
                   const char *shm_name, //
                   int queue_des, //
                   const char *queue_name)
{
    if (workerArgv)
    {
        free(workerArgv[1]);
        free(workerArgv[2]);
    }
    if (shm_mapped)
        munmap(shm_mapped, shm_size);
    if (shm_name)
        shm_unlink(shm_name);
    if (pswd_fd != -1)
        close(pswd_fd);
    if (queue_des)
    {
        mq_close(queue_des);
        mq_unlink(queue_name);
    }
}

/// If 'CRACK_FOUND' was returned, memory allocated in '*ret_found'
/// should be freed manually.\n If 'CRACK_NOT_FOUND' was returned,
/// '*ret_found' is equal to NULL.\n Otherwise, '*ret_found' value is
/// undefined. If 'NULL' is passed as 'ret_found', value is not set
/// at all.
short crack(const char *salted_hash, const char *pswd_path, int total_jobs, char **ret_found)
{
    const char *queue_name = "/hash_cracker_queue";
    struct mq_attr attr = {0};
    attr.mq_msgsize = sizeof(struct QueueMsg);
    const int max_workers = (int)sysconf(_SC_NPROCESSORS_ONLN);
    attr.mq_maxmsg = (long)max_workers * 2;
    const mqd_t queue_des = mq_open(queue_name, O_RDWR | O_CREAT | O_EXCL, 0666, attr);
    // const mqd_t queue_des = mq_open(queue_name, O_RDWR | O_CREAT, 0666, attr);
    if (queue_des == -1)
    {
        fprintf(stderr, "mq_open error\n");
        return CRACK_ERR;
    }

    const char *shm_name = "/hash_cracker_shm";
    const int shm_fd = shm_open(shm_name, O_RDWR | O_CREAT | O_EXCL, 0666);
    // const int shm_fd = shm_open(shm_name, O_RDWR | O_CREAT, 0666);
    if (shm_fd == -1)
    {
        crack_cleaner(NULL, NULL, -1, -1, NULL, queue_des, queue_name);
        fprintf(stderr, "shmopen error\n");
        return CRACK_ERR;
    }
    const size_t shm_size = sizeof(struct ShmData) + strlen(salted_hash);
    if (ftruncate(shm_fd, (off_t)shm_size) == -1)
    {
        crack_cleaner(NULL, NULL, -1, -1, shm_name, queue_des, queue_name);
        fprintf(stderr, "ftruncate error\n");
        return CRACK_ERR;
    }
    struct ShmData *shm_mapped = mmap(NULL, shm_size, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (shm_mapped == MAP_FAILED)
    {
        crack_cleaner(NULL, NULL, -1, -1, shm_name, queue_des, queue_name);
        fprintf(stderr, "mmap error\n");
        return CRACK_ERR;
    }
    shm_mapped->progress = 0;
    shm_mapped->force_stop = false;
    strcpy(shm_mapped->salted_hash, salted_hash);

    const int pswd_fd = open(pswd_path, O_RDONLY);
    if (pswd_fd == -1)
    {
        crack_cleaner(NULL, shm_mapped, shm_size, -1, shm_name, queue_des, queue_name);
        fprintf(stderr, "open error\n");
        return CRACK_ERR;
    }
    printf("queue name: %s\n", queue_name);
    char *workerArgv[4];
    workerArgv[0] = "./worker";
    workerArgv[1] = malloc(strlen(queue_name) + 1);
    strcpy(workerArgv[1], queue_name);
    const size_t buff_len = 16;
    workerArgv[2] = malloc(buff_len);
    workerArgv[3] = NULL;
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
            crack_cleaner(workerArgv, shm_mapped, shm_size, pswd_fd, shm_name, queue_des, queue_name);
            fprintf(stderr, "fork error\n");
            return CRACK_ERR;
        }
        else if (workers[i] == 0)
        {
            snprintf(workerArgv[2], buff_len, "%d",
                     total_jobs + i); // todo: change to count n jobs for a specific process
            execve("./worker", workerArgv, NULL);
            err(EXIT_FAILURE, "execve error\n");
        }
        else
        {
            created++;
        }
    }

    // sleep(3);
    // printf("killed\n");
    for (int i = 0; i < created; i++)
    {
        waitpid(workers[i], NULL, 0);
    }
    crack_cleaner(workerArgv, shm_mapped, shm_size, pswd_fd, shm_name, queue_des, queue_name);
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
    crack(salted_hash, pswd_path, total_jobs, &found);
    clock_gettime(CLOCK_MONOTONIC, &end);
    const double elapsed = (double)(end.tv_sec - start.tv_sec) + (double)(end.tv_nsec - start.tv_nsec) / 1e9;
    printf("\nFinished in %.2fs,\n", elapsed);
    printf("Process group: %d, pid: %d\n", getpgrp(), getpid());
    return 0;
}
