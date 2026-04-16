#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <time.h>
#include <fcntl.h>

int main(const int argc, char* argv[])
{
    long repeats = 1;
    bool printTestOutput = false;
    int ret;
    while ((ret = getopt(argc, argv, "+vr:")) != -1)
    {
        switch (ret)
        {
            case 'v':
                printTestOutput = true;
                break;
            case 'r':
                char* endptr;
                const long val = strtol(optarg, &endptr, 0);
                if (endptr == optarg || val < 1)
                {
                    fprintf(stderr, "%s: option 'r' requires number >= 1 as a parameter\n", argv[0]);
                    exit(EXIT_FAILURE);
                }
                repeats = val;
                break;
        }
    }
    if (optind == argc)
    {
        fprintf(stderr, "Usage: %s [option ...] command [argument ....]\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    double avgReal = 0, avgSys = 0, avgUsr = 0;
    struct timespec start, end;
    struct rusage usage;
    for (int i = 0; i < repeats; i++)
    {
        clock_gettime(CLOCK_MONOTONIC, &start);
        const pid_t pid = fork();
        if (pid == -1)
        {
            fprintf(stderr, "fork error\n");
            exit(EXIT_FAILURE);
        }
        if (pid == 0)
        {
            if (!printTestOutput)
            {
                close(1);
                const int h1 = open("/dev/null", O_WRONLY);
                dup2(h1, 1);
                close(2);
                const int h2 = open("/dev/null", O_WRONLY);
                dup2(h2, 2);
            }
            execvp(argv[optind], argv + optind);
            fprintf(stderr, "execvp error\n");
            exit(EXIT_FAILURE);
        }

        if (wait4(pid, NULL, 0, &usage) == -1)
            fprintf(stderr, "wait4 error\n");
        clock_gettime(CLOCK_MONOTONIC, &end);

        const double realTime = (double) (end.tv_sec - start.tv_sec)
                                + (double) (end.tv_nsec - start.tv_nsec) / 1000000000.0;
        const double usrTime = (double) usage.ru_utime.tv_sec + (double) usage.ru_utime.tv_usec / 1000000.0;
        const double sysTime = (double) usage.ru_stime.tv_sec + (double) usage.ru_stime.tv_usec / 1000000.0;
        avgReal += realTime;
        avgSys += sysTime;
        avgUsr += usrTime;
        printf("\nreal: %.3fs\n", realTime);
        printf("user: %.3fs\n", usrTime);
        printf("sys: %.3fs\n", sysTime);
    }
    if (repeats > 1)
    {
        printf("\nAverage real: %.3fs\n", avgReal / (double) repeats);
        printf("Average user: %.3fs\n", avgUsr / (double) repeats);
        printf("Average sys: %.3fs\n", avgSys / (double) repeats);
    }
}



