// todo: sigint handler
#define _GNU_SOURCE
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <err.h>
#include <unistd.h>
#include <stdbool.h>
#include <mqueue.h>
#include <time.h>
#include <sys/mman.h>
#include "ipc_datatypes.h"

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
    const mqd_t queue_des = mq_open(queue_name, O_RDWR | O_CREAT | O_EXCL, 0666, NULL);
    if (queue_des == -1)
        err(EXIT_FAILURE, "mq_open");
    const char *shm_name = "/hash_cracker_shm";
    const int shm_fd = shm_open(shm_name, O_RDWR | O_CREAT | O_EXCL, 0666);
    if (shm_fd == -1)
    {
        mq_unlink(queue_name);
        err(EXIT_FAILURE, "shm_open");
    }
    const int pswd_fd = open(pswd_path, O_RDONLY);
    if (pswd_fd == -1)
    {
        shm_unlink(shm_name);
        mq_unlink(queue_name);
        err(EXIT_FAILURE, "open");
    }
    printf("queue name: %s", queue_name);
    // const int max_processes = (int) sysconf(_SC_NPROCESSORS_ONLN);


    
    close(pswd_fd);
    shm_unlink(shm_name);
    mq_close(queue_des);
    mq_unlink(queue_name);
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
