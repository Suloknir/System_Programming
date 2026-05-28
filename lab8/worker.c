#include "ipc_datatypes.h"
#include <err.h>
#include <mqueue.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <unistd.h>

int main(const int argc, char *argv[])
{
    prctl(PR_SET_PDEATHSIG, SIGTERM);
    if (argc != 3)
        err(EXIT_FAILURE, "argc != 3");
    const char *queue_name = argv[1];
    const pid_t master_pid = atoi(argv[2]);
    if (master_pid != getppid())
        err(EXIT_FAILURE, "Master process terminated before worker called prctl()");
    printf("worker queue: %s, master_pid(argv) %d, parentpid(getppid): %d, worker pid: %d\n", //
           queue_name, master_pid, getppid(), getpid());
    const mqd_t queue_fd = mq_open(queue_name, O_RDONLY);
    if (queue_fd == -1)
        err(EXIT_FAILURE, "mq_open\n");
    struct QueueMsg msg = {0};
    const ssize_t msg_length = mq_receive(queue_fd, (char *)&msg, sizeof(msg), NULL);
    printf("msg length: %lu, start: %lu\n", msg_length, msg.start);
    mq_close(queue_fd);
    return 0;
}
