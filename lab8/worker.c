#include <stdio.h>
#include <stdlib.h>
#include <mqueue.h>
#include "definitions.h"

int main(const int argc, char *argv[])
{
    if (argc != 3)
        exit(EXIT_FAILURE);
    const char *queue_name = argv[1];
    const int n_jobs = atoi(argv[2]);
    printf("queue: %s, jobs: %d", queue_name, n_jobs);
    return 0;
}
