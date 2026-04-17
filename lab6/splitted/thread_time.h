#ifndef THREAD_TIME_H
#define THREAD_TIME_H

#include <pthread.h>
extern pthread_once_t keys_once;

void free_memory(void *buffer);

void start();

long long stop();

void create_keys();

void delete_keys();

#endif //THREAD_TIME_H
