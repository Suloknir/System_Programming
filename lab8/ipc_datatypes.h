#ifndef _IPC_DATATYPES_H
#define _IPC_DATATYPES_H 1
#include <sys/types.h>
#include <stdbool.h>

// struct FoundEvent
// {
//     size_t pswd_len;
//     char found_password[1];
// };

union PswdHash
{
    char salted_hash[1];
    char found_password[1];
};

struct ShmFormat
{
    _Atomic size_t progress;
    _Atomic bool force_stop;
    union PswdHash data;
};

struct QueueMsg
{
    off_t start;
    size_t length;
    int pswd_fd;
    int shm_fd;
};

#endif
