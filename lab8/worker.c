// #include "ipc_datatypes.h"
#include <signal.h>
#include <sys/prctl.h>
#include <mqueue.h>
#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <unistd.h>

int main(const int argc, char *argv[])
{
    prctl(PR_SET_PDEATHSIG, SIGTERM);
    if (argc != 3)
        err(EXIT_FAILURE, "argc != 3");
    //todo: get master pid and end process if master_pid != getppid()
    const char *queue_name = argv[1];
    const int n_jobs = atoi(argv[2]);
    printf("worker queue: %s, jobs %d, process group: %d, pid: %d\n", queue_name, n_jobs, getpgrp(), getpid());
    // for(;;){}
    return 0;
}
