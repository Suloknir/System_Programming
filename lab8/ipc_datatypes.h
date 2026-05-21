#ifndef _DEFINITIONS_H
#define _DEFINITIONS_H 1
#include <sys/types.h>

#define FOUND 0
#define NOT_FOUND -1
struct FinishEvent
{
    short worker_id;
    short status;
};

struct QueueMsg
{
    size_t length;
    off_t offset;
    int pipe_fd;
    int pswd_fd;
    int shm_fd;
};

#endif
