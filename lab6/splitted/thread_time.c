#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdbool.h>
#include "thread_time.h"

static pthread_key_t clock_running_key;
static pthread_key_t start_time_key;
pthread_once_t keys_once = PTHREAD_ONCE_INIT;

static void free_memory(void *buffer)
{
    free(buffer);
}

void create_keys()
{
    if (pthread_key_create(&clock_running_key, free_memory) != 0)
    {
        fprintf(stderr, "pthread_create error\n");
        exit(EXIT_FAILURE);
    }
    if (pthread_key_create(&start_time_key, free_memory) != 0)
    {
        fprintf(stderr, "pthread_create error\n");
        exit(EXIT_FAILURE);
    }
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
        if (clock_running == NULL || start_time == NULL)
        {
            fprintf(stderr, "malloc error\n");
            exit(EXIT_FAILURE);
        }
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

long long stop()
{
    pthread_once(&keys_once, create_keys);
    bool *clock_running = pthread_getspecific(clock_running_key);
    if (clock_running == NULL || *clock_running == false)
    {
        return -1;
    }
    *clock_running = false;
    const struct timespec *start_time = pthread_getspecific(start_time_key);
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    const float elapsed_seconds = (float) (now.tv_sec - start_time->tv_sec) +
                                  (float) (now.tv_nsec - start_time->tv_nsec) / 1e9;
    return elapsed_seconds * 1000;
}

void delete_keys()
{
    if (pthread_key_delete(clock_running_key) != 0)
    {
        fprintf(stderr, "pthread_key_delete error\n");
        exit(EXIT_FAILURE);
    }
    if (pthread_key_delete(start_time_key) != 0)
    {
        fprintf(stderr, "pthread_key_delete error\n");
        exit(EXIT_FAILURE);
    }
}
