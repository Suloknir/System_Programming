#define _GNU_SOURCE
#include "ipc_datatypes.h"
#include <crypt.h>
#include <err.h>
#include <errno.h>
#include <mqueue.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

struct IpcsData ipd = {0};

/// splits string of type '$alg$salt$hash'.
// return should be freed manually
/// on success returns string "$alg$salt"
char *desalinate(const char *salted_hash)
{
    // todo: error checking
    const char *alg = salted_hash + 1;
    const char *salt = strchr(alg, '$') + 1;
    const char *hash = strchr(salt, '$') + 1;
    return strndup(salted_hash, hash - salted_hash - 1);
}

void clean_ipc(void)
{
    if (ipd.shm_map != NULL && ipd.shm_map != MAP_FAILED)
        munmap(ipd.shm_map, ipd.shm_size);
    if (ipd.pswd_map != NULL && ipd.pswd_map != MAP_FAILED)
        munmap(ipd.pswd_map, ipd.pswd_length);
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

void process_task(struct QueueMsg *task)
{
    size_t buff_len = 64;
    char *buffer = malloc(buff_len * sizeof *buffer);
    if (buffer == NULL)
    {
        clean_ipc();
        err(EXIT_FAILURE, "malloc error\n");
    }
    char *salt = desalinate(ipd.shm_map->target_hash);
    const char *current = ipd.pswd_map + task->start_offset;
    const char *end = current + task->length - 1;
    const char *line_end = NULL;
    const size_t progress_min_update = 128;
    size_t unreported_progress = 0;
    do
    {
        line_end = memchr(current, '\n', end - current + 1);
        if (line_end == NULL)
            line_end = end;
        const size_t line_length = line_end - current + 1;
        if (line_length >= buff_len)
        {
            (buff_len * 2 > line_length) ? (buff_len *= 2) : (buff_len = line_length + 8);
            char *new_buffer = realloc(buffer, buff_len * sizeof *new_buffer);
            if (new_buffer == NULL)
            {
                free(buffer);
                clean_ipc();
                err(EXIT_FAILURE, "realloc error\n");
            }
            buffer = new_buffer;
        }
        strncpy(buffer, current, line_length);
        if (buffer[line_length - 1] == '\n')
            buffer[line_length - 1] = '\0';
        else
            buffer[line_length] = '\0';
        const char *hashed = crypt(buffer, salt);
        if (strcmp(ipd.shm_map->target_hash, hashed) == 0)
        {
            atomic_fetch_add_explicit(&ipd.shm_map->progress, unreported_progress, memory_order_relaxed);
            atomic_store_explicit(&ipd.shm_map->is_password_found, true, memory_order_relaxed);
            snprintf(ipd.shm_map->found_password, SHM_STRING_SIZE, "%s", buffer);
            free(salt);
            free(buffer);
            clean_ipc();
            exit(EXIT_SUCCESS);
        }
        unreported_progress += line_length;
        if (unreported_progress >= progress_min_update)
        {
            atomic_fetch_add_explicit(&ipd.shm_map->progress, unreported_progress, memory_order_relaxed);
            unreported_progress = 0;
        }
        current = line_end + 1;
    } while (current <= end && !atomic_load_explicit(&ipd.shm_map->is_password_found, memory_order_relaxed));
    atomic_fetch_add_explicit(&ipd.shm_map->progress, unreported_progress, memory_order_relaxed);
    free(salt);
    free(buffer);
}

void crack(mqd_t queue_fd)
{
    ipd.queue_fd = queue_fd;
    struct QueueMsg task;
    struct timespec timeout;
    ssize_t bytes_received =
        mq_timedreceive(ipd.queue_fd, (char *)&task, sizeof(task), NULL, set_timeout(3000, &timeout));
    if (bytes_received == -1)
    {
        if (errno == ETIMEDOUT)
            printf("Worker timeout - did not receive first task\n");
        else
            fprintf(stderr, "first mq_timedreceive error\n");
        clean_ipc();
        exit(EXIT_FAILURE);
    }
    ipd.pswd_fd = task.pswd_fd;
    struct stat sb;
    if (fstat(ipd.pswd_fd, &sb) == -1)
    {
        clean_ipc();
        err(EXIT_FAILURE, "fstat error\n");
    }
    ipd.pswd_length = sb.st_size;
    ipd.pswd_map = mmap(NULL, ipd.pswd_length, PROT_READ, MAP_PRIVATE, ipd.pswd_fd, 0);
    if (ipd.pswd_map == MAP_FAILED)
    {
        clean_ipc();
        err(EXIT_FAILURE, "mmap error (pswd)\n");
    }
    ipd.shm_fd = task.shm_fd;
    ipd.shm_size = task.shm_size;
    ipd.shm_map = mmap(NULL, ipd.shm_size, PROT_READ | PROT_WRITE, MAP_SHARED, ipd.shm_fd, 0);
    if (ipd.shm_map == MAP_FAILED)
    {
        clean_ipc();
        err(EXIT_FAILURE, "mmap error (shm)\n");
    }
    process_task(&task);
    while (atomic_load_explicit(&ipd.shm_map->is_master_sending, memory_order_relaxed))
    {
        bytes_received = mq_timedreceive(ipd.queue_fd, (char *)&task, sizeof(task), NULL, set_timeout(10, &timeout));
        if (bytes_received > 0)
        {
            process_task(&task);
        }
        else if (bytes_received == -1 && errno == ETIMEDOUT)
        {
            continue;
        }
        else
        {
            clean_ipc();
            err(EXIT_FAILURE, "mq_timedreceive error\n");
        }
    }
}

int main(const int argc, char *argv[])
{
    prctl(PR_SET_PDEATHSIG, SIGTERM);
    if (argc != 3)
        err(EXIT_FAILURE, "argc != 3");
    const mqd_t queue_fd = atoi(argv[1]);
    const pid_t master_pid = atoi(argv[2]);
    if (master_pid != getppid())
        err(EXIT_FAILURE, "Master process terminated before worker called prctl()\n");
    crack(queue_fd);
    return 0;
}
