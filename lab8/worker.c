#define _GNU_SOURCE
#include "ipc_datatypes.h"
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
/// ret_... values should be freed manually
/// on success ret_salt = "$alg$salt", ret_hash = "hash"
void desalinate(const char *restrict salted_hash, //
                char **restrict ret_salt, //
                char **restrict ret_hash)
{
    // todo: error checking
    const char *alg = salted_hash + 1;
    const char *salt = strchr(alg, '$') + 1;
    const char *hash = strchr(salt, '$') + 1;
    *ret_salt = strndup(salted_hash, hash - salted_hash - 1);
    *ret_hash = strdup(hash);
}

void clean(void)
{
    if (ipd.shm_map != NULL && ipd.shm_map != MAP_FAILED)
        munmap(ipd.shm_map, ipd.shm_size);
    if (ipd.shm_fd > 0)
        close(ipd.shm_fd);
    if (ipd.pswd_map != NULL && ipd.pswd_map != MAP_FAILED)
        munmap(ipd.pswd_map, ipd.pswd_length);
    if (ipd.queue_fd > 0)
        mq_close(ipd.queue_fd);
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

void crack(const char *queue_name)
{
    ipd.queue_fd = mq_open(queue_name, O_RDONLY);
    if (ipd.queue_fd == -1)
        err(EXIT_FAILURE, "mq_open\n");
    struct QueueMsg msg;
    struct timespec timeout;
    ssize_t bytes_received =
        mq_timedreceive(ipd.queue_fd, (char *)&msg, sizeof(msg), NULL, set_timeout(3000, &timeout));
    if (bytes_received == -1)
    {
        if (errno == ETIMEDOUT)
            printf("Worker timeout - did not receive first message\n");
        else
            fprintf(stderr, "first mq_timedreceive error\n");
        clean();
        exit(EXIT_FAILURE);
    }
    printf("worker: received first job_id = %d\n", msg.job_id);
    ipd.pswd_fd = msg.pswd_fd;
    struct stat sb;
    if (fstat(ipd.pswd_fd, &sb) == -1)
    {
        clean();
        err(EXIT_FAILURE, "fstat error\n");
    }
    ipd.pswd_length = sb.st_size;
    ipd.pswd_map = mmap(NULL, ipd.pswd_length, PROT_READ, MAP_PRIVATE, ipd.pswd_fd, 0);
    if (ipd.pswd_map == MAP_FAILED)
    {
        clean();
        err(EXIT_FAILURE, "mmap error (pswd)\n");
    }
    snprintf(ipd.shm_name, NAME_MAX_LEN, "%s", msg.shm_name);
    ipd.shm_fd = shm_open(ipd.shm_name, O_RDWR, 0);
    if (ipd.shm_fd == -1)
    {
        clean();
        err(EXIT_FAILURE, "shmopen error\n");
    }
    ipd.shm_size = msg.shm_size;
    ipd.shm_map = mmap(NULL, ipd.shm_size, PROT_READ | PROT_WRITE, MAP_SHARED, ipd.shm_fd, 0);
    if (ipd.shm_map == MAP_FAILED)
    {
        clean();
        err(EXIT_FAILURE, "mmap error (shm)\n");
    }
    // todo: also process first job!!!
    for(int i = 0; i < 10000000; i++){} //work simulation
    do
    {
        bytes_received = mq_timedreceive(ipd.queue_fd, (char *)&msg, sizeof(msg), NULL, set_timeout(10, &timeout));
        if (bytes_received == -1)
        {
            if (errno == ETIMEDOUT)
            {
                // printf("[WORKER] receive timeout\n"); // fixme: remove in final code
                continue;
            }
            else
            {
                clean();
                err(EXIT_FAILURE, "mq_timedreceive error\n");
            }
        }
        // printf("[WORKER]  received job_id = %d\n", msg.job_id);
    } while (bytes_received > 0 || atomic_load_explicit(&ipd.shm_map->is_master_sending, memory_order_relaxed));
}

int main(const int argc, char *argv[])
{
    prctl(PR_SET_PDEATHSIG, SIGTERM);
    if (argc != 3)
        err(EXIT_FAILURE, "argc != 3");
    const char *queue_name = argv[1];
    const pid_t master_pid = atoi(argv[2]);
    if (master_pid != getppid())
        err(EXIT_FAILURE, "Master process terminated before worker called prctl()\n");
    crack(queue_name);
    return 0;
}
