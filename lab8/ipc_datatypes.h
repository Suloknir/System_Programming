#ifndef _IPC_DATATYPES_H
#define _IPC_DATATYPES_H 1
#include <sys/types.h>

#define FOUND 1
#define NOT_FOUND 0
struct FinishEvent
{
    int worker_id;
    short status;
};

struct ShmData
{
    _Atomic size_t progress;
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
