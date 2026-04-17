// Compilation:
// gcc main.c thread_time.c -o main -pthread

#define EASY_ON_CPU true

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <time.h>
#include <signal.h>
#include <stdbool.h>
#include "thread_time.h"

typedef struct
{
    pthread_t tid;
    float time_to_live;
    bool cancel_sent;
} ThreadInfo;

void thread_cancel_handler(void *unused)
{
    const long long millis = stop();
    printf("Thread stopped, tid: %ld, execution time: %lld ms\n", pthread_self(), millis);
}

void* thread_func(void *unused)
{
    #if EASY_ON_CPU == false
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
    #endif
    pthread_cleanup_push(thread_cancel_handler, NULL);
    start();
    // pretend that following loop calculates factorial
    for (;;)
    {
        #if EASY_ON_CPU == true
        const struct timespec loop_sleep = {0, 1000000}; //1 ms sleep to not drain CPU
        nanosleep(&loop_sleep, NULL);
        #endif
    }
    pthread_cleanup_pop(0);
    return NULL;
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

    ThreadInfo *threads = malloc(sizeof(ThreadInfo) * nr_threads);
    if (threads == NULL)
    {
        fprintf(stderr, "malloc error\n");
        exit(EXIT_FAILURE);
    }

    pthread_once(&keys_once, create_keys);
    srand((unsigned int) time(NULL));
    for (long i = 0; i < nr_threads; i++)
    {
        threads[i].cancel_sent = false;
        const float time_to_live = ((float) rand() / (float) RAND_MAX) * max_time_to_live;
        threads[i].time_to_live = time_to_live;
        if (pthread_create(&threads[i].tid, NULL, thread_func, NULL) != 0)
        {
            fprintf(stderr, "pthread_create error\n");
            free(threads);
            exit(EXIT_FAILURE);
        }
        printf("tid: %ld | time to live: %.3fs\n", threads[i].tid, threads[i].time_to_live);
    }

    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);
    int stopped_threads = 0;
    while (stopped_threads < nr_threads)
    {
        #if EASY_ON_CPU == true
        const struct timespec loop_sleep = {0, 10000000}; //10 ms sleep to not drain CPU
        nanosleep(&loop_sleep, NULL);
        #endif
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        const float elapsed = (float) (now.tv_sec - start.tv_sec) +
                              (float) (now.tv_nsec - start.tv_nsec) / 1e9;
        for (long i = 0; i < nr_threads; i++)
        {
            if (!threads[i].cancel_sent && elapsed >= threads[i].time_to_live)
            {
                threads[i].cancel_sent = true;
                stopped_threads++;
                if (pthread_cancel(threads[i].tid) != 0)
                {
                    fprintf(stderr, "pthread_kill error\n");
                    free(threads);
                    exit(EXIT_FAILURE);
                }
            }
        }
    }

    for (long i = 0; i < nr_threads; i++)
    {
        pthread_join(threads[i].tid, NULL);
    }
    delete_keys();
    free(threads);
}
