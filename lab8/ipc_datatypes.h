#ifndef _IPC_DATATYPES_H
#define _IPC_DATATYPES_H 1
#define _GNU_SOURCE
#include <sys/types.h>
#include <stdbool.h>
#include <signal.h>

#define SHM_STRING_SIZE 256

struct ShmFormat
{
    _Atomic size_t progress;
    _Atomic bool is_master_sending;
    _Atomic bool is_password_found;
    char target_hash[SHM_STRING_SIZE];
    char found_password[SHM_STRING_SIZE];
};

struct QueueMsg
{
    off_t start_offset;
    size_t length;
    size_t shm_size;
    int task_id;
    int pswd_fd;
    int shm_fd;
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
