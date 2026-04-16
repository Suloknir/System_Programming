#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <time.h>
#include <signal.h>
#include <stdbool.h>

#define BILLION 1000000000

typedef struct
{
    pthread_t tid;
    float time_to_live;
    bool stopped;
} ThreadInfo;

pthread_key_t clock_running_key;
pthread_key_t start_time_key;
pthread_once_t keys_once = PTHREAD_ONCE_INIT;

static void free_memory(void *buffer)
{
    free(buffer);
}

void create_keys()
{
    pthread_key_create(&clock_running_key, free_memory);
    pthread_key_create(&start_time_key, free_memory);
}

void start()
{
    pthread_once(&keys_once, create_keys);
    struct timespec *start_time = pthread_getspecific(start_time_key);
    bool *clock_running = pthread_getspecific(clock_running_key);
    if (clock_running == NULL)
    {
        clock_running = malloc(sizeof(bool));
        start_time = malloc(sizeof(struct timespec));
        *clock_running = false;
        pthread_setspecific(clock_running_key, clock_running);
        pthread_setspecific(start_time_key, start_time);
    }

    if (*clock_running == false)
    {
        *clock_running = true;
        clock_gettime(CLOCK_MONOTONIC, start_time);
    }
}

void* thread_func(void *unused)
{
    start();
    for (;;)
    {
        constexpr struct timespec loop_sleep = {0, 1000000}; //1ms sleep to not drain cpu
        nanosleep(&loop_sleep, NULL);
    }
}

size_t stop()
{
    pthread_once(&keys_once, create_keys);
    bool *clock_running = pthread_getspecific(clock_running_key);
    if (clock_running == NULL || *clock_running == false)
    {
        return -1;
    }
    *clock_running = false;
    struct timespec *start_time = pthread_getspecific(start_time_key);
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    //todo: count ms
    const float elapsed_seconds = (float) (now.tv_sec - start_time->tv_sec) +
                                  (float) (now.tv_nsec - start_time->tv_nsec) / BILLION;
    return elapsed_seconds * 1000;
}

void sigusr1_handler(int sig_num)
{
    //todo: delete keys
    size_t millis = stop();
    printf("Stopping, tid: %ld, execution time: %ld ms\n", pthread_self(), millis);
    pthread_key_delete(clock_running_key);
    pthread_key_delete(start_time_key);
    pthread_exit(&millis);
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

    struct sigaction sa;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_handler = sigusr1_handler;
    sigaction(SIGUSR1, &sa, NULL);

    srand((unsigned int) time(NULL));
    for (long i = 0; i < nr_threads; i++)
    {
        threads[i].stopped = false;
        const float time_to_live = ((float) rand() / (float) RAND_MAX) * max_time_to_live;
        // const long seconds = time;
        // const long nanoseconds = (time - (long) time) * BILLION;
        // const struct timespec time_to_live = {seconds, nanoseconds};
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
        constexpr struct timespec loop_sleep = {0, 10000000}; //10ms sleep to not drain cpu
        nanosleep(&loop_sleep, NULL);
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        const float elapsed = (float) (now.tv_sec - start.tv_sec) +
                              (float) (now.tv_nsec - start.tv_nsec) / BILLION;
        for (long i = 0; i < nr_threads; i++)
        {
            if (!threads[i].stopped && elapsed >= threads[i].time_to_live)
            {
                threads[i].stopped = true;
                stopped_threads++;
                if (pthread_kill(threads[i].tid, SIGUSR1) != 0)
                {
                    fprintf(stderr, "pthread_kill error\n");
                    free(threads);
                    exit(EXIT_FAILURE);
                }
            }
        }
    }

    for (long i = 0; i < nr_threads; i++)
        pthread_join(threads[i].tid, NULL);
    free(threads);
}
