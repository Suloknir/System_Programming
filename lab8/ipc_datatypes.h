#ifndef _IPC_DATATYPES_H
#define _IPC_DATATYPES_H 1
#include <sys/types.h>
#include <stdbool.h>

// struct FoundEvent
// {
//     size_t pswd_len;
//     char found_password[1];
// };

struct ShmData
{
    _Atomic size_t progress;
    _Atomic bool force_stop;
    char salted_hash[1];
};

struct QueueMsg
{
    off_t start;
    size_t length;
    int pipe_fd;
    int pswd_fd;
    int shm_fd;
};

#endif
