#include <stdio.h>
#include <err.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <time.h>
#include <pthread.h>
#include <stdatomic.h>
// #include <crypt.h>

#ifndef CRACK_FOUND
#define CRACK_FOUND 1
#endif

#ifndef CRACK_NOT_FOUND
#define CRACK_NOT_FOUND 0
#endif

#ifndef CRACK_ERR
#define CRACK_ERR -1
#endif

struct ThreadArgs
{
    const char *mapped;
    const char *salted_hash;
    _Atomic size_t *progress;

    size_t length;
    pthread_t main_tid;
    int id;
    bool stop_on_found;
};

void parse_argv(const int argc, char *const*argv, char **ret_hash, char **ret_filepath, int *ret_n_threads)
{
    if (ret_hash == NULL || ret_filepath == NULL || ret_n_threads == NULL)
        err(EXIT_FAILURE, "parse_argv requires non-null arguments\n");
    opterr = 0;
    int ret;
    while ((ret = getopt(argc, argv, "p:f:n:")) != -1)
    {
        switch (ret)
        {
            case 'p':
                *ret_hash = optarg;
                break;
            case 'f':
                *ret_filepath = optarg;
                break;
            case 'n':
                char *endptr;
                const int val = (int) strtol(optarg, &endptr, 0);
                if (endptr == optarg || val < 1)
                    err(EXIT_FAILURE, "%s: option '%c' requires number >= 1 as an argument\n", argv[0], ret);
                *ret_n_threads = val;
                break;
            case '?':
                err(EXIT_FAILURE, "%s: Option '%c' requires argument\n", argv[0], optopt);
                // ReSharper disable once CppDFAUnreachableCode
                break;
            default:
                abort();
        }
    }
    if (*ret_hash == NULL || *ret_filepath == NULL)
    {
        fprintf(stderr, "Parameters 'p', 'f' are mandatory\n");
        fprintf(stderr, "Usage: %s -p [hashed password] -f [file] -n [n threads]\n", argv[0]);
        exit(EXIT_FAILURE);
    }
}

void force_print_progress(size_t done, size_t to_do, int bars)
{
    const float fraction_done = (float) done / to_do;
    const int bars_to_print = fraction_done * bars;
    printf("\r[");
    for (int i = 0; i < bars_to_print; i++)
        printf("=");
    for (int i = 0; i < bars - bars_to_print; i++)
        printf(" ");
    printf("] %6.2f%%", fraction_done * 100);
    fflush(stdout);
}

void print_progress(size_t done, size_t to_do, int bars, float fps)
{
    static bool already_printed = false;
    static struct timespec last_print;
    if (!already_printed || done == to_do)
    {
        clock_gettime(CLOCK_MONOTONIC, &last_print);
        force_print_progress(done, to_do, bars);
        already_printed = true;
        return;
    }
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    const float elapsed = (float) (now.tv_sec - last_print.tv_sec) +
                          (float) (now.tv_nsec - last_print.tv_nsec) / 1e9;
    if (elapsed >= 1.0f / fps)
    {
        clock_gettime(CLOCK_MONOTONIC, &last_print);
        force_print_progress(done, to_do, bars);
    }
}

void *crack_worker(void *args)
{
    struct ThreadArgs th_args = *(struct ThreadArgs*)args;
    size_t buff_len = 256;
    char* buffer = malloc(buff_len * sizeof(char));
    if (buffer == NULL)
        err(EXIT_FAILURE, "malloc error\n");
    printf("worker %d:\n", th_args.id);
    for (size_t i = 0; i < th_args.length; i++)
    {
        printf("%c", th_args.mapped[i]);
    }
    //todo: return buffer if password found (maybe realloc also to shrink buffer size?)
    free(buffer);
    return NULL;
}

/// If 'CRACK_FOUND' was returned, memory allocated in '*ret_found' should be freed manually.
/// If 'CRACK_NOT_FOUND' was returned, '*ret_found' is equal to NULL.
/// Otherwise, '*ret_found' value is undefined.
short crack(const char *salted_hash, const char *pswd_path, int n_threads, char **ret_found)
{
    const int fd = open(pswd_path, O_RDONLY);
    if (fd == -1)
    {
        fprintf(stderr, "open error\n");
        return CRACK_ERR;
    }
    struct stat sb;
    if (fstat(fd, &sb) == -1)
    {
        close(fd);
        fprintf(stderr, "fstat error\n");
        return CRACK_ERR;
    }
    size_t file_length = sb.st_size;
    if (file_length == 0)
        return CRACK_NOT_FOUND;
    char *mapped = mmap(NULL, file_length, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (mapped == MAP_FAILED)
    {
        fprintf(stderr, "mmap error\n");
        return CRACK_ERR;
    }
    size_t approx_pack_size = file_length / n_threads;
    if (approx_pack_size == 0)
        approx_pack_size = 1;
    printf("file_length = %lu\n", file_length);
    printf("approx_pack_size = %lu\n", approx_pack_size);
    // print_progress(atomic_load_explicit(&progress, memory_order_relaxed), file_length, 30, 36);
    struct ThreadArgs *args = calloc(n_threads, sizeof(struct ThreadArgs));
    if (args == NULL)
    {
        fprintf(stderr, "calloc error\n");
        return CRACK_ERR;
    }

    pthread_t *threads = malloc(n_threads * sizeof(pthread_t));
    if (threads == NULL)
    {
        free(args);
        fprintf(stderr, "calloc error\n");
        return CRACK_ERR;
    }

    _Atomic size_t progress = 0;
    size_t main_tid = pthread_self();
    size_t next_start_id = 0;
    int created = 0;
    for (int i = 0; i < n_threads; i++)
    {
        const size_t pack_start_id = next_start_id;
        if (pack_start_id >= file_length)
            break;
        size_t pack_end_id;
        if (i == n_threads - 1)
            pack_end_id = file_length - 1;
        else
        {
            pack_end_id = (i + 1) * approx_pack_size - 1;
            if (pack_end_id < pack_start_id)
                continue;
            if (pack_end_id < file_length - 1 && mapped[pack_end_id] != '\n')
            {
                const char *next_line = memchr(&mapped[pack_end_id], '\n', file_length - pack_end_id);
                if (next_line != NULL)
                    pack_end_id = next_line - mapped;
                else
                {
                    pack_end_id = file_length - 1;
                    i = n_threads - 1; //to stop after just that thread
                }
            }
        }
        next_start_id = pack_end_id + 1;

        args[created].mapped = mapped + pack_start_id;
        args[created].salted_hash = salted_hash;
        args[created].progress = &progress;
        args[created].length = pack_end_id - pack_start_id + 1;
        args[created].main_tid = main_tid;
        args[created].id = created;
        args[created].stop_on_found = true;
        // args[i].created = true;
        pthread_create(&threads[created], NULL, crack_worker, &args[created]);
        // printf("--- %d: [start_id: %lu] [end_id: %lu] [pack_size = %lu] [end == '\\n' ? %d] [start = '%c']\n",
        //        i,
        //        pack_start_id,
        //        pack_end_id,
        //        pack_end_id - pack_start_id,
        //        mapped[pack_end_id] == '\n',
        //        mapped[pack_start_id]);
        // for (size_t j = pack_start_id; j <= pack_end_id; j++)
        // {
        //     printf("%c", mapped[j]);
        //     // print_progress(j - pack_start_id, pack_end_id - pack_start_id, 30, 1.5f);
        // }
        created++;
    }
    for (int i = 0; i < created; i++)
    {
        //todo: check if that saves data to ret_found
        pthread_join(threads[i], (void**)ret_found);
    }

    // printf("\nCreated Threads: %d\n", created_threads);
    munmap(mapped, file_length);
    free(args);
    free(threads);
    return CRACK_NOT_FOUND;
}

int main(const int argc, char *argv[])
{
    char *salted_hash = NULL;
    char *pswd_path = NULL;
    int n_threads = -1;
    parse_argv(argc, argv, &salted_hash, &pswd_path, &n_threads);
    const int max_threads = (int) sysconf(_SC_NPROCESSORS_ONLN);
    if (n_threads == -1)
    {
        //todo: find best nr of threads
        //print progress after every thread tested. print_progress(i, max_threads)
    }
    else
    {
        if (n_threads > max_threads) n_threads = max_threads;
        char *found_pass = NULL;
        switch (crack(salted_hash, pswd_path, n_threads, &found_pass))
        {
            case CRACK_FOUND:
                printf("Found password: %s\n", found_pass);
                free(found_pass);
                break;
            case CRACK_NOT_FOUND:
                printf("Password not found\n");
                break;
            case CRACK_ERR:
                err(EXIT_FAILURE, "crack_error\n");
                // ReSharper disable once CppDFAUnreachableCode
                break;
            default:
                fprintf(stderr, "Unexpected crack return\n");
                abort();
        }
    }
    return 0;
}
