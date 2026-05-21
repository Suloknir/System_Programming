#include "ipc_datatypes.h"
#include <mqueue.h>
#include <stdio.h>
#include <stdlib.h>
#include <err.h>

int main(const int argc, char *argv[])
{
    if (argc != 3)
        err(EXIT_FAILURE, "argc != 3");
    const char *queue_name = argv[1];
    const int n_jobs = atoi(argv[2]);
    printf("worker queue: %s, jobs: %d\n", queue_name, n_jobs);
    return 0;
}
