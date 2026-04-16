#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <time.h>

#define BILLION 1000000000

typedef struct
{
    struct timespec time_to_live;
    pthread_t tid;
} ThreadInfo;

void* thread_func(void* unused)
{
    for (;;){}
}

int main(const int argc, char *argv[])
{
    long nr_threads = -1;
    long max_time_to_live = -1;
    int ret;
    while ((ret = getopt(argc, argv, "n:t:")) != -1)
    {
        char *endptr;
        long val = -1;
        switch (ret)
        {
            case 'n':
                val = strtol(optarg, &endptr, 0);
                if (endptr == optarg || val < 1)
                {
                    fprintf(stderr, "%s: option '%c' requires number >= 1 as a parameter\n", argv[0], ret);
                    exit(EXIT_FAILURE);
                }
                nr_threads = val;
                break;
            case 't':
                val = strtol(optarg, &endptr, 0);
                if (endptr == optarg || val < 1)
                {
                    fprintf(stderr, "%s: option '%c' requires number >= 1 as a parameter\n", argv[0], ret);
                    exit(EXIT_FAILURE);
                }
                max_time_to_live = val;
                break;
        }
    }
    if (max_time_to_live == -1 || nr_threads == -1)
    {
        fprintf(stderr, "%s: Parameters 'n', 't' are mandatory\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    srand((unsigned int) time(NULL));
    ThreadInfo *threads = malloc(sizeof(ThreadInfo) * nr_threads);
    for (long i = 0; i < nr_threads; i++)
    {
        const float time = ((float) rand() / (float) RAND_MAX) * max_time_to_live;
        const long seconds = time;
        const long nanoseconds = (time - (long) time) * BILLION;
        const struct timespec time_to_live = {seconds, nanoseconds};
        threads[i].time_to_live = time_to_live;
        if (pthread_create(&threads[i].tid, NULL, thread_func, NULL) != 0)
        {
            fprintf(stderr, "pthread_create error\n");
            free(threads);
            exit(EXIT_FAILURE);
        }
        printf("tid: %ld | time to live: %.3fs\n", threads[i].tid, time);
    }

    for (long i = 0; i< nr_threads; i++)
        pthread_join(threads[i].tid, NULL);

    free(threads);
}
