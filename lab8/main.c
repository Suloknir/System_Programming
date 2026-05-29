// todo: sigchild handler
// todo: sigrtmin + 1 handler in master if worker found password (found password written in shm->salted_hash)
#define _GNU_SOURCE
#include "ipc_datatypes.h"
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <mqueue.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
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

bool sigint_receaved = false;

struct IpcsData ipd = {
    .workerArgv = {"./worker", NULL, NULL, NULL}, //
};

void parse_argv(int argc, char *const *argv, char **ret_hash, char **ret_filepath, int *ret_n_tasks)
{
    if (!ret_hash || !ret_filepath || !ret_n_tasks)
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
                *ret_n_tasks = val;
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
        fprintf(stderr, "Usage: %s -p [hashed password] -f [file] -n [n tasks]\n", argv[0]);
        exit(EXIT_FAILURE);
    }
}

void sigint_handler(int signum) // NOLINT
{
    sigint_receaved = true;
}

void clean(void)
{
    if (ipd.workerArgv[1])
        free(ipd.workerArgv[1]);
    if (ipd.workerArgv[2])
        free(ipd.workerArgv[2]);
    if (ipd.shm_map != NULL && ipd.shm_map != MAP_FAILED)
        munmap(ipd.shm_map, ipd.shm_size);
    if (ipd.shm_fd > 0)
    {
        close(ipd.shm_fd);
        shm_unlink(ipd.shm_name);
    }
    if (ipd.pswd_map == NULL && ipd.pswd_map != MAP_FAILED)
        munmap(ipd.pswd_map, ipd.pswd_length);
    if (ipd.pswd_fd > 0)
        close(ipd.pswd_fd);
    if (ipd.queue_fd > 0)
    {
        mq_close(ipd.queue_fd);
        mq_unlink(ipd.queue_name);
    }
    sigaction(SIGINT, ipd.old_action, NULL);
}

struct timespec *set_timeout(long ms, struct timespec *ret_timeout)
{
    clock_gettime(CLOCK_REALTIME, ret_timeout);
    ret_timeout->tv_sec += ms / 1000;
    ret_timeout->tv_nsec += (ms % 1000) * 1000000;
    if (ret_timeout->tv_nsec >= 1000000000)
    {
        ret_timeout->tv_sec += 1;
        ret_timeout->tv_nsec -= 1000000000;
    }
    return ret_timeout;
}
/// returns -1 on failure and 0 on succes
short create_ipcs(const char *salted_hash)
{
    struct mq_attr attr = {0};
    attr.mq_msgsize = sizeof(struct QueueMsg);
    attr.mq_maxmsg = 10;
    // cleaner_data.queue_fd = mq_open(cleaner_data.queue_name, O_RDWR | O_CREAT | O_EXCL, 0666, &attr);
    ipd.queue_fd = mq_open(ipd.queue_name, O_RDWR | O_CREAT, 0666, &attr);
    if (ipd.queue_fd == -1)
    {
        fprintf(stderr, "mq_open error\n");
        return -1;
    }

    // const int shm_fd = shm_open(data.shm_name, O_RDWR | O_CREAT | O_EXCL, 0666);
    ipd.shm_fd = shm_open(ipd.shm_name, O_RDWR | O_CREAT, 0666);
    if (ipd.shm_fd == -1)
    {
        clean();
        fprintf(stderr, "shmopen error\n");
        return -1;
    }
    ipd.shm_size = sizeof(struct ShmFormat) + strlen(salted_hash);
    if (ftruncate(ipd.shm_fd, (off_t)ipd.shm_size) == -1)
    {
        clean();
        fprintf(stderr, "ftruncate error\n");
        return -1;
    }
    ipd.shm_map = mmap(NULL, ipd.shm_size, PROT_READ | PROT_WRITE, MAP_SHARED, ipd.shm_fd, 0);
    if (ipd.shm_map == MAP_FAILED)
    {
        clean();
        fprintf(stderr, "mmap error (shm)\n");
        return -1;
    }
    ipd.shm_map->progress = 0;
    ipd.shm_map->is_master_sending = true;
    snprintf(ipd.shm_map->data.target_hash, NAME_MAX_LEN, "%s", salted_hash);
    return 0;
}

/// If 'CRACK_FOUND' was returned, memory allocated in '*ret_found'
/// should be freed manually.\n If 'CRACK_NOT_FOUND' was returned,
/// '*ret_found' is equal to NULL.\n Otherwise, '*ret_found' value is
/// undefined. If 'NULL' is passed as 'ret_found', value is not set
/// at all.
short crack(const char *salted_hash, const char *pswd_path, int total_tasks, char **ret_found)
{
    struct sigaction sa = {0};
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_handler = sigint_handler;
    sigaction(SIGINT, &sa, ipd.old_action);

    const int max_workers = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (create_ipcs(salted_hash) != 0)
        return CRACK_ERR;
    ipd.pswd_fd = open(pswd_path, O_RDONLY);
    if (ipd.pswd_fd == -1)
    {
        clean();
        fprintf(stderr, "open error\n");
        return CRACK_ERR;
    }
    struct stat sb;
    if (fstat(ipd.pswd_fd, &sb) == -1)
    {
        clean();
        fprintf(stderr, "fstat error\n");
        return CRACK_ERR;
    }
    ipd.pswd_length = sb.st_size;
    if (ipd.pswd_length == 0)
        return CRACK_NOT_FOUND;
    ipd.pswd_map = mmap(NULL, ipd.pswd_length, PROT_READ, MAP_PRIVATE, ipd.pswd_fd, 0);
    if (ipd.pswd_map == MAP_FAILED)
    {
        clean();
        fprintf(stderr, "mmap error (pswd)\n");
        return CRACK_ERR;
    }

    printf("queue name: %s\n", ipd.queue_name);

    // cleaner_data.workerArgv[0] = "./worker";
    ipd.workerArgv[1] = malloc(strlen(ipd.queue_name) + 1);
    snprintf(ipd.workerArgv[1], NAME_MAX_LEN, "%s", ipd.queue_name);
    const size_t buff_len = 16;
    ipd.workerArgv[2] = malloc(buff_len);
    snprintf(ipd.workerArgv[2], buff_len, "%d", getpid());

    int processes_created = 0;
    const int workers_to_create = max_workers > total_tasks ? total_tasks : max_workers;
    pid_t workers[workers_to_create];
    for (int i = 0; i < workers_to_create; i++)
    {
        workers[i] = fork();
        if (workers[i] == -1)
        {
            for (int j = 0; j < processes_created; j++)
            {
                kill(workers[j], SIGTERM);
                waitpid(workers[j], NULL, 0);
            }
            clean();
            fprintf(stderr, "fork error\n");
            return CRACK_ERR;
        }
        else if (workers[i] == 0)
        {
            execve("./worker", ipd.workerArgv, NULL);
            err(EXIT_FAILURE, "execve error\n");
        }
        else
        {
            processes_created++;
        }
    }
    const char *mapped = ipd.pswd_map;
    const size_t file_length = ipd.pswd_length;
    struct QueueMsg msg = {0};
    msg.pswd_fd = ipd.pswd_fd;
    msg.shm_size = ipd.shm_size;
    // msg.shm_name = ipd.shm_name;
    snprintf(msg.shm_name, NAME_MAX_LEN, "%s", ipd.shm_name);

    size_t approx_task_size = file_length / total_tasks;
    if (approx_task_size == 0)
        approx_task_size = 1;
    size_t next_start_offset = 0;
    int tasks_sent = 0;
    for (int i = 0; i < total_tasks; i++)
    {
        const size_t task_start_offset = next_start_offset;
        if (task_start_offset >= file_length)
            break;
        size_t task_end_offset;
        if (i == total_tasks - 1)
            task_end_offset = file_length - 1;
        else
        {
            task_end_offset = (i + 1) * approx_task_size - 1;
            if (task_end_offset < task_start_offset)
                continue;
            if (task_end_offset < file_length - 1 && mapped[task_end_offset] != '\n')
            {
                const char *line_end = memchr(&mapped[task_end_offset], '\n', file_length - task_end_offset);
                if (line_end != NULL)
                    task_end_offset = line_end - mapped;
                else
                {
                    task_end_offset = file_length - 1;
                    i = total_tasks - 1; // to stop after just that task
                }
            }
        }
        next_start_offset = task_end_offset + 1;
        struct timespec timeout;
        msg.start_offset = (off_t)task_start_offset;
        msg.task_id = tasks_sent;
        msg.length = task_end_offset - task_start_offset + 1;
        while (!sigint_receaved)
        {
            const ssize_t bytes_sent =
                mq_timedsend(ipd.queue_fd, (const char *)&msg, sizeof(msg), 1, set_timeout(10, &timeout));
            if (bytes_sent == -1)
            {
                if (errno == ETIMEDOUT)
                {
                    // printf("send timeout (probably queue is full)\n"); // fixme: remove in final code
                    continue;
                }
                else
                {
                    clean();
                    fprintf(stderr, "mq_timedsend error\n");
                    return CRACK_ERR;
                }
            }
            tasks_sent++;
            break;
        }
    }
    ipd.shm_map->is_master_sending = false;
    // if(sigint_receaved) //todo
    munmap(ipd.pswd_map, ipd.pswd_length);
    ipd.pswd_map = NULL;

    for (int i = 0; i < processes_created; i++)
        waitpid(workers[i], NULL, 0);
    printf("[MASTER] sent %d tasks\n", tasks_sent);
    printf("[MASTER] created %d processes\n", processes_created);
    clean();
    if (sigint_receaved)
        return CRACK_ERR;
    if (ret_found != NULL)
        *ret_found = NULL;
    return CRACK_NOT_FOUND;
}

int main(const int argc, char *argv[])
{
    snprintf(ipd.queue_name, NAME_MAX_LEN, "%s", "/hash_cracker_queue");
    snprintf(ipd.shm_name, NAME_MAX_LEN, "%s", "/hash_cracker_shm");
    char *salted_hash = NULL;
    char *pswd_path = NULL;
    int total_tasks = -1;
    parse_argv(argc, argv, &salted_hash, &pswd_path, &total_tasks);
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    char *found = NULL;
    crack(salted_hash, pswd_path, total_tasks, &found); // todo: switch statement
    clock_gettime(CLOCK_MONOTONIC, &end);
    const double elapsed = (double)(end.tv_sec - start.tv_sec) + (double)(end.tv_nsec - start.tv_nsec) / 1e9;
    printf("\nFinished in %.2fs,\n", elapsed);
    printf("Pid: %d\n", getpid());
    return 0;
}
