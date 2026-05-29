#ifndef _IPC_DATATYPES_H
#define _IPC_DATATYPES_H 1
#define _GNU_SOURCE
#include <sys/types.h>
#include <stdbool.h>
#include <signal.h>

#define MAX_WORKERS 256

#define TASK_FINISHED -1

#define SHM_STRING_SIZE 256

// struct QueueMsg;


struct QueueTask
{
    off_t start_offset;
    size_t length;
    size_t shm_size;
    int task_id; 
    int pswd_fd;
    int shm_fd;
    size_t reported_progress;
};

struct ShmFormat
{
    _Atomic size_t progress;
    _Atomic bool is_master_sending;
    _Atomic bool is_password_found;
    char target_hash[SHM_STRING_SIZE];
    char found_password[SHM_STRING_SIZE];
    struct QueueTask active_tasks[MAX_WORKERS];
};


struct IpcsData
{
    struct sigaction old_action;
    struct ShmFormat *shm_map;
    char *pswd_map;
    size_t shm_size;
    size_t pswd_length;
    int pswd_fd;
    int shm_fd;
    int queue_fd;
};

#endif
