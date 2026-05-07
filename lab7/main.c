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

#ifndef CRACK_WORKER_ERR
#define CRACK_WORKER_ERR ((void *) -1)
#endif

struct ThreadArg
{
    char *algorithm;
    char *salt;
    char *hash;
    const char *mapped;
    _Atomic size_t *progress;

    size_t length;
    pthread_t main_tid;
    int id;
    bool stop_on_found;
};

void parse_argv(int argc, char *const*argv, char **ret_hash, char **ret_filepath, int *ret_n_threads)
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

void free_args(struct ThreadArg *to_free)
{
    free(to_free->algorithm);
    free(to_free->salt);
    free(to_free->hash);
}

/// splits string of type '$alg$salt$hash'
void desalinate(const char *salted_hash, char **ret_alg, char **ret_salt, char **ret_hash)
{
    const char *alg = salted_hash + 1;
    const char *salt = strchr(alg, '$') + 1;
    const char *hash = strchr(salt, '$') + 1;
    *ret_alg = strndup(alg, salt - alg - 1);
    *ret_salt = strndup(salt, hash - salt - 1);
    *ret_hash = strdup(hash);
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
    size_t buff_len = 64;
    char *buffer = malloc(buff_len * sizeof(char));
    if (buffer == NULL)
    {
        fprintf(stderr, "malloc error\n");
        return CRACK_WORKER_ERR;
    }
    struct ThreadArg th_args = *(struct ThreadArg*) args;
    printf("%d: alg: [%s] salt: [%s], hash: [%s]\n", th_args.id, th_args.algorithm, th_args.salt, th_args.hash);

    const char *current = th_args.mapped;
    const char *end = &th_args.mapped[th_args.length - 1];
    const char *line_end = NULL;
    do
    {
        line_end = memchr(current, '\n', end - current + 1);
        if (line_end == NULL)
            line_end = end;
        const size_t line_length = line_end - current + 1;
        if (line_length > buff_len)
        {
            (buff_len * 2 > line_length) ? (buff_len *= 2) : (buff_len = line_length + 8);
            char *new_buffer = realloc(buffer, buff_len * sizeof(char));
            if (new_buffer == NULL)
            {
                free(buffer);
                fprintf(stderr, "realloc error\n");
                return CRACK_WORKER_ERR;
            }
            buffer = new_buffer;
        }

        atomic_fetch_add_explicit(th_args.progress, line_length, memory_order_relaxed);
        current = line_end + 1;
    } while (current <= end);
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
    struct ThreadArg *args = calloc(n_threads, sizeof(struct ThreadArg));
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
    const size_t main_tid = pthread_self();
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
                const char *line_end = memchr(&mapped[pack_end_id], '\n', file_length - pack_end_id);
                if (line_end != NULL)
                    pack_end_id = line_end - mapped;
                else
                {
                    pack_end_id = file_length - 1;
                    i = n_threads - 1; //to stop after just that thread
                }
            }
        }
        next_start_id = pack_end_id + 1;
        desalinate(salted_hash, &args[created].algorithm, &args[created].salt, &args[created].hash);
        args[created].mapped = mapped + pack_start_id;
        args[created].progress = &progress;
        args[created].length = pack_end_id - pack_start_id + 1;
        args[created].main_tid = main_tid;
        args[created].id = created;
        args[created].stop_on_found = true;
        if (pthread_create(&threads[created], NULL, crack_worker, &args[created]) != 0)
        {
            fprintf(stderr, "pthread_create error\n");
            for (int j = 0; j < created; j++)
            {
                pthread_join(threads[j], NULL);
                free_args(&args[j]);
            }
            free_args(&args[created]);
            free(args);
            free(threads);
            return CRACK_ERR;
        }
        created++;
    }
    for (int i = 0; i < created; i++)
    {
        pthread_join(threads[i], (void**) ret_found);
        free_args(&args[i]);
        // printf("%lu finished with return: %s\n", threads[i], *ret_found);
        // printf("done: %lu, to_do: %lu\n", atomic_load_explicit(&progress, memory_order_relaxed), file_length);
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
