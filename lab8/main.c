// todo: sigint handler
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
                const int val = (int) strtol(optarg, &endptr, 0);
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

/// If 'CRACK_FOUND' was returned, memory allocated in '*ret_found'
/// should be freed manually.\n If 'CRACK_NOT_FOUND' was returned,
/// '*ret_found' is equal to NULL.\n Otherwise, '*ret_found' value is
/// undefined. If 'NULL' is passed as 'ret_found', value is not set
/// at all.
short crack(const char *salted_hash, const char *pswd_path, int n_jobs, char **ret_found)
{
    const char *queue_name = "/hash_cracker_queue";
    struct mq_attr attr = {0};
    attr.mq_msgsize = sizeof(struct QueueMsg);
    const int max_workers = (int) sysconf(_SC_NPROCESSORS_ONLN);
    attr.mq_maxmsg = (long) max_workers * 2;
    const mqd_t queue_des = mq_open(queue_name, O_RDWR | O_CREAT | O_EXCL, 0666, attr);
    if (queue_des == -1)
    {
        fprintf(stderr, "mq_open error\n");
        return CRACK_ERR;
    }

    const char *shm_name = "/hash_cracker_shm";
    const int shm_fd = shm_open(shm_name, O_RDWR | O_CREAT | O_EXCL, 0666);
    if (shm_fd == -1)
    {
        mq_close(queue_des);
        mq_unlink(queue_name);
        fprintf(stderr, "shmopen error\n");
        return CRACK_ERR;
    }
    const size_t shm_size = sizeof(struct ShmData) + strlen(salted_hash);
    if (ftruncate(shm_fd, (off_t) shm_size) == -1)
    {
        shm_unlink(shm_name);
        mq_close(queue_des);
        mq_unlink(queue_name);
        fprintf(stderr, "ftruncate error\n");
        return CRACK_ERR;
    }
    struct ShmData *shm_mapped = mmap(NULL, shm_size, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (shm_mapped == MAP_FAILED)
    {
        shm_unlink(shm_name);
        mq_close(queue_des);
        mq_unlink(queue_name);
        fprintf(stderr, "mmap error\n");
        return CRACK_ERR;
    }
    const int pswd_fd = open(pswd_path, O_RDONLY);
    if (pswd_fd == -1)
    {
        munmap(shm_mapped, shm_size);
        shm_unlink(shm_name);
        mq_close(queue_des);
        mq_unlink(queue_name);
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
    snprintf(workerArgv[2], buff_len, "%d", n_jobs); // todo: change n_jobs, count jobs for a specific process
    workerArgv[3] = NULL;
    for (int i = 0; i < n_jobs; i++)
    {
        pid_t pid = fork();
        if (pid == -1)
        {
            // for (int j = 0; j < i - 1; j++) todo: stop other processes
            free(workerArgv[1]);
            free(workerArgv[2]);
            munmap(shm_mapped, shm_size);
            close(pswd_fd);
            shm_unlink(shm_name);
            mq_close(queue_des);
            fprintf(stderr, "fork error\n");
            return CRACK_ERR;
        }
        else if (pid == 0)
        {
            execve("./worker", workerArgv, NULL);
            err(EXIT_FAILURE, "execve error\n");
        }
        else
        {
            // parent
        }
    }

    sleep(3);
    //todo: waitpid
    free(workerArgv[1]);
    free(workerArgv[2]);
    munmap(shm_mapped, shm_size);
    close(pswd_fd);
    shm_unlink(shm_name);
    mq_close(queue_des);
    mq_unlink(queue_name);
    if (ret_found != NULL)
        *ret_found = NULL;
    return CRACK_NOT_FOUND;
}

int main(const int argc, char *argv[])
{
    char *salted_hash = NULL;
    char *pswd_path = NULL;
    int n_jobs = -1;
    parse_argv(argc, argv, &salted_hash, &pswd_path, &n_jobs);
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    char *found = NULL;
    crack(salted_hash, pswd_path, n_jobs, &found);
    clock_gettime(CLOCK_MONOTONIC, &end);
    const double elapsed = (double) (end.tv_sec - start.tv_sec) + (double) (end.tv_nsec - start.tv_nsec) / 1e9;
    printf("\nFinished in %.2fs\n", elapsed);
    return 0;
}
