#ifndef _IPC_DATATYPES_H
#define _IPC_DATATYPES_H 1
#include <sys/types.h>
#include <stdbool.h>

#define NAME_MAX_LEN 64

union PswdHash
{
    char target_hash[1];
    char found_password[1];
};

struct ShmFormat
{
    _Atomic size_t progress;
    _Atomic bool is_master_sending;
    union PswdHash data;
};

struct QueueMsg
{
    off_t start;
    size_t length;
    size_t shm_size;
    int job_id;
    int pswd_fd;
    char shm_name[NAME_MAX_LEN];
};

struct IpcsData
{
    char *workerArgv[4]; //todo: remove that from here
    struct ShmFormat *shm_map;
    char *pswd_map;
    struct sigaction *old_action;
    size_t shm_size;
    size_t pswd_length;
    int pswd_fd;
    int shm_fd;
    int queue_fd;
    char shm_name[NAME_MAX_LEN];
    char queue_name[NAME_MAX_LEN];
};

#endif
