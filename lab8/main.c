// todo: sigchild handler
// todo: sigrtmin + 1 handler in master if worker found password (found password written in shm->salted_hash)
#define _GNU_SOURCE
#include "ipc_datatypes.h"
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <mqueue.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef EASY_ON_CPU
#define EASY_ON_CPU true
#endif

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

struct IpcsData ipd = {0};

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

void force_print_progress(size_t done, size_t to_do, int bars)
{
    const float fraction_done = (float)done / to_do; // NOLINT
    const int bars_to_print = fraction_done * bars; // NOLINT
    printf("\r[");
    for (int i = 0; i < bars_to_print; i++)
        printf("=");
    for (int i = 0; i < bars - bars_to_print; i++)
        printf(" ");
    printf("] %6.2f%%", fraction_done * 100);
    fflush(stdout);
}

void print_progress(size_t done, size_t to_do, int bars, float refresh_rate)
{
    static bool already_printed = false;
    static struct timespec last_print;
    if (!already_printed || done == to_do)
    {
        clock_gettime(CLOCK_MONOTONIC, &last_print);
        force_print_progress(done, to_do, bars);
        already_printed = true;
        return;
    }

    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    const float elapsed =
        (float)(now.tv_sec - last_print.tv_sec) + (float)(now.tv_nsec - last_print.tv_nsec) / 1e9; // NOLINT
    if (elapsed >= 1.0f / refresh_rate)
    {
        clock_gettime(CLOCK_MONOTONIC, &last_print);
        force_print_progress(done, to_do, bars);
    }
}

void clean_ipc(void)
{
    if (ipd.shm_map != NULL && ipd.shm_map != MAP_FAILED)
    {
        atomic_store_explicit(&ipd.shm_map->is_master_sending, false, memory_order_relaxed);
        atomic_store_explicit(&ipd.shm_map->is_password_found, true, memory_order_relaxed); // to stop workers
        munmap(ipd.shm_map, ipd.shm_size);
    }
    if (ipd.shm_fd > 0)
        close(ipd.shm_fd);
    if (ipd.pswd_map != NULL && ipd.pswd_map != MAP_FAILED)
        munmap(ipd.pswd_map, ipd.pswd_length);
    if (ipd.pswd_fd > 0)
        close(ipd.pswd_fd);
    if (ipd.queue_fd > 0)
        mq_close(ipd.queue_fd);
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
short remove_cloexec(int fd)
{
    int flags = fcntl(fd, F_GETFD);
    if (flags == -1)
    {
        fprintf(stderr, "fcntl getfd error");
        return -1;
    }
    flags &= ~FD_CLOEXEC;
    if (fcntl(fd, F_SETFD, flags) == -1)
    {
        fprintf(stderr, "fcntl setfd error");
        return -1;
    }
    return 0;
}

/// returns -1 on failure and 0 on succes
short create_ipcs(const char *salted_hash)
{
    char queue_name[] = "/hash_cracker_queue";
    char shm_name[] = "/hash_cracker_shm";
    struct mq_attr attr = {0};
    attr.mq_msgsize = sizeof(struct QueueMsg);
    attr.mq_maxmsg = 10;
    // cleaner_data.queue_fd = mq_open(cleaner_data.queue_name, O_RDWR | O_CREAT | O_EXCL, 0666, &attr);
    ipd.queue_fd = mq_open(queue_name, O_RDWR | O_CREAT, 0666, &attr);
    if (ipd.queue_fd == -1)
    {
        fprintf(stderr, "mq_open error\n");
        return -1;
    }
    mq_unlink(queue_name);
    remove_cloexec(ipd.queue_fd);
    // const int shm_fd = shm_open(data.shm_name, O_RDWR | O_CREAT | O_EXCL, 0666);
    ipd.shm_fd = shm_open(shm_name, O_RDWR | O_CREAT, 0666);
    if (ipd.shm_fd == -1)
    {
        clean_ipc();
        fprintf(stderr, "shmopen error\n");
        return -1;
    }
    shm_unlink(shm_name);
    remove_cloexec(ipd.shm_fd);
    ipd.shm_size = sizeof(struct ShmFormat) + strlen(salted_hash);
    if (ftruncate(ipd.shm_fd, (off_t)ipd.shm_size) == -1)
    {
        clean_ipc();
        fprintf(stderr, "ftruncate error\n");
        return -1;
    }
    ipd.shm_map = mmap(NULL, ipd.shm_size, PROT_READ | PROT_WRITE, MAP_SHARED, ipd.shm_fd, 0);
    if (ipd.shm_map == MAP_FAILED)
    {
        clean_ipc();
        fprintf(stderr, "mmap error (shm)\n");
        return -1;
    }
    atomic_store_explicit(&ipd.shm_map->progress, 0, memory_order_relaxed);
    atomic_store_explicit(&ipd.shm_map->is_password_found, false, memory_order_relaxed);
    atomic_store_explicit(&ipd.shm_map->is_master_sending, true, memory_order_relaxed);
    snprintf(ipd.shm_map->target_hash, SHM_STRING_SIZE, "%s", salted_hash);

    printf("queue name: %s\n", queue_name);
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
        clean_ipc();
        fprintf(stderr, "open error\n");
        return CRACK_ERR;
    }
    remove_cloexec(ipd.pswd_fd);
    struct stat sb;
    if (fstat(ipd.pswd_fd, &sb) == -1)
    {
        clean_ipc();
        fprintf(stderr, "fstat error\n");
        return CRACK_ERR;
    }
    ipd.pswd_length = sb.st_size;
    if (ipd.pswd_length == 0)
        return CRACK_NOT_FOUND;
    ipd.pswd_map = mmap(NULL, ipd.pswd_length, PROT_READ, MAP_PRIVATE, ipd.pswd_fd, 0);
    if (ipd.pswd_map == MAP_FAILED)
    {
        clean_ipc();
        fprintf(stderr, "mmap error (pswd)\n");
        return CRACK_ERR;
    }
    const size_t av_len = 16;
    char arg[3][av_len];
    snprintf(arg[0], av_len, "./worker");
    snprintf(arg[1], av_len, "%d", ipd.queue_fd);
    snprintf(arg[2], av_len, "%d", getpid());
    char *workerArgv[] = {
        arg[0],
        arg[1],
        arg[2],
        NULL,
    };

    int workers_created = 0;
    const int workers_to_create = max_workers > total_tasks ? total_tasks : max_workers;
    pid_t workers[workers_to_create];
    for (int i = 0; i < workers_to_create; i++)
    {
        if (sigint_receaved)
            break;
        workers[i] = fork();
        if (workers[i] == -1)
        {
            for (int j = 0; j < workers_created; j++)
            {
                kill(workers[j], SIGTERM);
                waitpid(workers[j], NULL, 0);
            }
            clean_ipc();
            fprintf(stderr, "fork error\n");
            return CRACK_ERR;
        }
        else if (workers[i] == 0)
        {
            execve("./worker", workerArgv, NULL);
            err(EXIT_FAILURE, "execve error\n");
        }
        else
        {
            workers_created++;
        }
    }
    const char *mapped = ipd.pswd_map;
    const size_t file_length = ipd.pswd_length;
    struct QueueMsg msg = {0};
    msg.pswd_fd = ipd.pswd_fd;
    msg.shm_size = ipd.shm_size;
    msg.shm_fd = ipd.shm_fd;

    size_t approx_task_size = file_length / total_tasks;
    if (approx_task_size == 0)
        approx_task_size = 1;
    size_t next_start_offset = 0;
    int tasks_sent = 0;
    const float refresh_rate = 24.0f;
    const int bars = 30;
    int workers_running = workers_created;
    for (int i = 0; i < total_tasks; i++)
    {
        if (sigint_receaved)
            break;
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

        while (!sigint_receaved && !atomic_load_explicit(&ipd.shm_map->is_password_found, memory_order_relaxed))
        {
            const ssize_t bytes_sent =
                mq_timedsend(ipd.queue_fd, (const char *)&msg, sizeof(msg), 1, set_timeout(1, &timeout));
            size_t current_progress = atomic_load_explicit(&ipd.shm_map->progress, memory_order_relaxed);
            print_progress(current_progress, file_length, bars, refresh_rate);
            if (bytes_sent == -1)
            {
                if (errno == ETIMEDOUT)
                {
                    pid_t done;
                    while ((done = waitpid(-1, NULL, WNOHANG)) > 0)
                        workers_running--;
                    if (workers_running <= 0)
                    {
                        fprintf(stderr, "[FATAL] all workers died");
                        clean_ipc();
                        return CRACK_ERR;
                    }
                    continue;
                }
                else if (sigint_receaved)
                {
                    break;
                }
                else
                {
                    for (int j = 0; j < workers_created; j++)
                    {
                        kill(workers[j], SIGTERM);
                        waitpid(workers[j], NULL, 0);
                    }
                    clean_ipc();
                    fprintf(stderr, "mq_timedsend error\n");
                    return CRACK_ERR;
                }
            }
            tasks_sent++;
            break;
        }
    }
    atomic_store_explicit(&ipd.shm_map->is_master_sending, false, memory_order_relaxed);
    munmap(ipd.pswd_map, ipd.pswd_length);
    ipd.pswd_map = NULL;
    size_t current_progress = atomic_load_explicit(&ipd.shm_map->progress, memory_order_relaxed);
    while (workers_running > 0)
    {
        current_progress = atomic_load_explicit(&ipd.shm_map->progress, memory_order_relaxed);
        print_progress(current_progress, file_length, bars, refresh_rate);
#if EASY_ON_CPU == true
        const struct timespec loop_sleep = {0, 1000000};
        nanosleep(&loop_sleep, NULL);
#endif
        if (sigint_receaved)
            atomic_store_explicit(&ipd.shm_map->is_password_found, true, memory_order_relaxed);
        pid_t done;
        while ((done = waitpid(-1, NULL, WNOHANG)) > 0)
            workers_running--;
    }
    force_print_progress(current_progress, file_length, bars);
    printf("\nsent %d tasks\n", tasks_sent);
    printf("progress: %lu\n", current_progress);
    printf("file_length: %lu\n", file_length);
    printf("spawned %d workers\n", workers_created);
    if (sigint_receaved)
    {
        clean_ipc();
        printf("INTERRUPTED BY SIGNAL [SIGINT]\n");
        return CRACK_ERR;
    }
    const bool found = atomic_load_explicit(&ipd.shm_map->is_password_found, memory_order_relaxed);
    if (found)
    {
        if (ret_found != NULL)
            *ret_found = strdup(ipd.shm_map->found_password);
    }
    else
    {
        if (ret_found != NULL)
            *ret_found = NULL;
    }
    clean_ipc();
    if (found)
        return CRACK_FOUND;
    else
        return CRACK_NOT_FOUND;
}

int main(const int argc, char *argv[])
{
    char *salted_hash = NULL;
    char *pswd_path = NULL;
    int total_tasks = -1;
    parse_argv(argc, argv, &salted_hash, &pswd_path, &total_tasks);
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    char *found_pass = NULL;
    const short crack_result = crack(salted_hash, pswd_path, total_tasks, &found_pass);
    printf("\n");
    switch (crack_result)
    {
        case CRACK_FOUND:
            printf("Found password: %s\n", found_pass);
            free(found_pass);
            break;
        case CRACK_NOT_FOUND:
            printf("Password not found\n");
            break;
        case CRACK_ERR:
            err(EXIT_FAILURE, "crack_error\n");
            // ReSharper disable once CppDFAUnreachableCode
            break;
        default:
            fprintf(stderr, "Unexpected crack return\n");
            abort();
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    const double elapsed = (double)(end.tv_sec - start.tv_sec) + (double)(end.tv_nsec - start.tv_nsec) / 1e9;
    printf("\nFinished in %.2fs,\n", elapsed);
    return 0;
}
