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
#include <crypt.h>

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

struct ThreadInfo
{
    char *alg;
    char *salt;
    char *hash;
    const char *mapped;
    _Atomic bool *report_found;
    _Atomic size_t *progress;

    size_t length;
    pthread_t tid;
    bool stopped;
    // pthread_t main_tid;
    // int id;
    bool stop_on_found;
    bool force_stop;
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

void free_arg(struct ThreadInfo *to_free)
{
    if (to_free->alg != NULL)
        free(to_free->alg);
    if (to_free->salt != NULL)
        free(to_free->salt);
    if (to_free->hash != NULL)
        free(to_free->hash);
}

/// splits string of type '$alg$salt$hash'.\n
/// ret_... values should be freed manually
/// on success ret_alg = alg, ret_salt = salt, ret_hash = hash
void desalinate(const char *salted_hash, char **ret_alg, char **ret_salt, char **ret_hash)
{
    //todo: error checking
    const char *alg = salted_hash + 1;
    const char *salt = strchr(alg, '$') + 1;
    const char *hash = strchr(salt, '$') + 1;
    *ret_alg = strndup(alg, salt - alg - 1);
    *ret_salt = strndup(salt, hash - salt - 1);
    *ret_hash = strdup(hash);
}

/// splits string of type '$alg$salt$hash'.\n
/// ret_... values should be freed manually
/// on success ret_salt = '$alg$salt', ret_hash = hash
void desalinate2(const char *salted_hash, char **ret_salt, char **ret_hash)
{
    //todo: error checking
    const char *alg = salted_hash + 1;
    const char *salt = strchr(alg, '$') + 1;
    const char *hash = strchr(salt, '$') + 1;
    *ret_salt = strndup(salted_hash, hash - salted_hash - 1);
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

void worker_exit_handler(void *args)
{
    ((struct ThreadInfo*) args)->stopped = true;
}

void *crack_worker(void *args)
{
    // @formatter:off
    pthread_cleanup_push(worker_exit_handler, args);
        // @formatter:on
        size_t buff_len = 64;
        char *buffer = malloc(buff_len * sizeof *buffer);
        if (buffer == NULL)
        {
            fprintf(stderr, "malloc error\n");
            pthread_exit(CRACK_WORKER_ERR);
        }
        const struct ThreadInfo *th_info = args;
        const size_t target_size = strlen(th_info->salt) + strlen(th_info->hash) + 2 * sizeof(char);
        char target_hashed[target_size];
        snprintf(target_hashed, target_size, "%s$%s", th_info->salt, th_info->hash);
        struct crypt_data data;
        data.initialized = 0;
        const char *current = th_info->mapped;
        const char *end = &th_info->mapped[th_info->length - 1];
        const char *line_end = NULL;
        bool exit_found_flag = false;
        char *exit_buffer = NULL;
        do
        {
            line_end = memchr(current, '\n', end - current + 1);
            if (line_end == NULL)
                line_end = end;
            const size_t line_length = line_end - current + 1;
            if (line_length >= buff_len)
            {
                (buff_len * 2 > line_length) ? (buff_len *= 2) : (buff_len = line_length + 8);
                char *new_buffer = realloc(buffer, buff_len * sizeof *new_buffer);
                if (new_buffer == NULL)
                {
                    free(buffer);
                    fprintf(stderr, "realloc error\n");
                    pthread_exit(CRACK_WORKER_ERR);
                }
                buffer = new_buffer;
            }
            strncpy(buffer, current, line_length);
            if (buffer[line_length - 1] == '\n')
                buffer[line_length - 1] = '\0';
            else
                buffer[line_length] = '\0';
            const char *hashed = crypt_r(buffer, th_info->salt, &data);
            if (strcmp(target_hashed, hashed) == 0)
            {
                if (th_info->stop_on_found)
                {
                    atomic_store_explicit(th_info->report_found, true, memory_order_relaxed);
                    pthread_exit(buffer);
                }
                if (!exit_found_flag)
                {
                    exit_buffer = malloc(line_length * sizeof *exit_buffer);
                    if (exit_buffer == NULL)
                    {
                        fprintf(stderr, "malloc error\n");
                        pthread_exit(CRACK_WORKER_ERR);
                    }
                    strcpy(exit_buffer, buffer);
                    exit_found_flag = true;
                }
            }

            atomic_fetch_add_explicit(th_info->progress, line_length, memory_order_relaxed);
            current = line_end + 1;
        } while (current <= end && !th_info->force_stop);

        free(buffer);
        if (exit_found_flag)
        {
            atomic_store_explicit(th_info->report_found, true, memory_order_relaxed);
            pthread_exit(exit_buffer);
        }
        pthread_exit(NULL);
    pthread_cleanup_pop(0);
}

/// If 'CRACK_FOUND' was returned, memory allocated in '*ret_found' should be freed manually.\n
/// If 'CRACK_NOT_FOUND' was returned, '*ret_found' is equal to NULL.\n
/// Otherwise, '*ret_found' value is undefined. \n
/// If 'NULL' is passed as 'ret_found', value is not set at all. \n
/// If 'test' value is set to 'true' threads keep working even if password was found and only first
/// 'test_bytes' bytes of a file are used for testing or less if a file is not long enough.\n
/// To test entire file, function should be called with 'test = true' and 'test_bytes = -1'\n
/// If 'test' value is set to 'false', 'test_bytes' value is ignored
short crack(const char *salted_hash,
            const char *pswd_path,
            int n_threads,
            char **ret_found,
            bool test,
            size_t test_bytes)
{
    if (n_threads <= 0)
        return CRACK_ERR;
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
    if (test && test_bytes < file_length)
        file_length = test_bytes;
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
    // printf("file_length = %lu\n", file_length);
    // printf("approx_pack_size = %lu\n", approx_pack_size);
    struct ThreadInfo *th_info = calloc(n_threads, sizeof *th_info);
    if (th_info == NULL)
    {
        fprintf(stderr, "calloc error\n");
        return CRACK_ERR;
    }

    _Atomic size_t progress = 0;
    _Atomic bool found = false;
    // const size_t main_tid = pthread_self();
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
        desalinate2(salted_hash, &th_info[created].salt, &th_info[created].hash);
        th_info[created].mapped = mapped + pack_start_id;
        th_info[created].report_found = &found;
        th_info[created].progress = &progress;
        th_info[created].length = pack_end_id - pack_start_id + 1;
        th_info[created].stopped = false;
        th_info[created].force_stop = false;
        // args[created].main_tid = main_tid;
        // args[created].id = created;
        th_info[created].stop_on_found = !test;
        if (pthread_create(&th_info[created].tid, NULL, crack_worker, &th_info[created]) != 0)
        {
            fprintf(stderr, "pthread_create error\n");
            for (int j = 0; j < created; j++)
            {
                pthread_join(th_info[j].tid, NULL);
                free_arg(&th_info[j]);
            }
            free_arg(&th_info[created]);
            free(th_info);
            // free(threads);
            return CRACK_ERR;
        }
        created++;
    }

    const float print_fps = 24.0f;
    const int bars = 30;
    int threads_stopped = 0;
    while (threads_stopped < created)
    {
        print_progress(atomic_load_explicit(&progress, memory_order_relaxed), file_length, bars, print_fps);
        threads_stopped = 0;
        if (atomic_load_explicit(&found, memory_order_relaxed))
        {
            // printf("force stopping\n");
            for (int i = 0; i < created; i++)
            {
                th_info[i].force_stop = true;
                // printf("%d, force stop = %d\n", i, th_info[i].force_stop);
            }
        }
        for (int i = 0; i < created; i++)
        {
            if (th_info[i].stopped == true)
            {
                threads_stopped++;
            }
        }
    }

    char *found_pswd = NULL;
    for (int i = 0; i < created; i++)
    {
        pthread_join(th_info[i].tid, (void**) &found_pswd);
        // printf("ret_found: [%s]", *ret_found);
        free_arg(&th_info[i]);
        if (found_pswd != NULL && ret_found != NULL)
            *ret_found = found_pswd;
        // printf("%lu finished with return: %s\n", threads[i], *ret_found);
        // printf("done: %lu, to_do: %lu\n", atomic_load_explicit(&progress, memory_order_relaxed), file_length);
    }

    munmap(mapped, file_length);
    free(th_info);
    print_progress(1, 1, bars, print_fps);
    // printf("\n");
    if (found)
        return CRACK_FOUND;
    else
    {
        if (ret_found != NULL)
            *ret_found = NULL;
        return CRACK_NOT_FOUND;
    }
}

int main(const int argc, char *argv[])
{
    char *salted_hash = NULL;
    char *pswd_path = NULL;
    int n_threads = -1;
    parse_argv(argc, argv, &salted_hash, &pswd_path, &n_threads);
    const int max_threads = (int) sysconf(_SC_NPROCESSORS_ONLN);

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    if (n_threads == -1)
    {
        int best_thread = -1;
        float best_time = -1.0f;
        struct timespec test_start, test_end;
        printf("Testing up to %d threads\n", max_threads);
        for (int i = 1; i <= max_threads; i++)
        {
            clock_gettime(CLOCK_MONOTONIC, &test_start);
            printf("Thread %d:\n", i);
            if (crack(salted_hash, pswd_path, i, NULL, true, 8192) == CRACK_ERR)
                err(EXIT_FAILURE, "\ncrack_error\n");
            clock_gettime(CLOCK_MONOTONIC, &test_end);
            const float test_elapsed = (float) (test_end.tv_sec - test_start.tv_sec) +
                                       (float) (test_end.tv_nsec - test_start.tv_nsec) / 1e9;
            printf(" [%.3fs]", test_elapsed);
            if (i == 1)
            {
                best_time = test_elapsed;
                best_thread = i;
                printf(" - new best");
            }
            if (test_elapsed < best_time)
            {
                best_time = test_elapsed;
                best_thread = i;
                printf(" - new best");
            }
            printf("\n");
        }
        printf("Best time for %d threads (%.3fs)\n", best_thread, best_time);
    }
    else
    {
        if (n_threads > max_threads) n_threads = max_threads;
        char *found_pass = NULL;
        const short crack_result = crack(salted_hash, pswd_path, n_threads, &found_pass, false, 0);
        printf("\n");
        switch (crack_result)
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
    clock_gettime(CLOCK_MONOTONIC, &end);
    const float elapsed = (float) (end.tv_sec - start.tv_sec) +
                          (float) (end.tv_nsec - start.tv_nsec) / 1e9;
    printf("\nFinished in %.2fs\n", elapsed);
    return 0;
}
