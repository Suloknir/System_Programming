#include <stdio.h>
#include <err.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
// #include <crypt.h>
// #include <time.h>

void print_progress(size_t done, size_t to_do, const int max_bars)
{
    const float fraction_done = (float) done / to_do;
    const int bars_to_print = fraction_done * max_bars;
    printf("\r[");
    for (int i = 0; i < bars_to_print; i++)
        printf("=");
    for (int i = 0; i < max_bars - bars_to_print; i++)
        printf(" ");
    printf("]%7.2f%%", fraction_done * 100);
    fflush(stdout);
}

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

void thread_crack(int id, char *pswd, size_t length) {}

bool crack(const char *salted_hash, const char *pswd_path, int n_threads) //todo: refactor that awfulness
{
    int fd = open(pswd_path, O_RDONLY);
    if (fd == -1)
        err(EXIT_FAILURE, "open error\n");
    struct stat sb;
    if (fstat(fd, &sb) == -1)
        err(EXIT_FAILURE, "fstat error\n");
    size_t file_length = sb.st_size;
    if (file_length == 0) return false;

    char *pswd = mmap(NULL, file_length, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (pswd == MAP_FAILED)
        err(EXIT_FAILURE, "mmap error\n");
    const char *const start_file = pswd;
    const char *const end_file = pswd + file_length;
    size_t approx_pack_size = file_length / n_threads;
    if (approx_pack_size == 0) approx_pack_size = 1;
    printf("file_length = %lu\n", file_length);
    printf("approximate pack size = %lu\n", approx_pack_size);
    size_t next_start_pack_id = 0;
    int spawned_threads = 0;
    for (int i = 0; i < n_threads; i++)
    {
        size_t start_pack_id = next_start_pack_id;
        size_t end_pack_id = (i + 1) * approx_pack_size - 1;
        if (end_pack_id <= start_pack_id) continue;
        if (start_pack_id >= file_length) break;
        if (end_pack_id < file_length - 1 && pswd[end_pack_id] != '\n')
        {
            char *next_line = memchr(&pswd[end_pack_id], '\n', file_length - end_pack_id);
            if (next_line != NULL && next_line != end_file - 1)
                end_pack_id = next_line - start_file;
            else
            {
                end_pack_id = file_length - 1;
                i = n_threads - 1; //to stop after just that thread
                printf("\n-----BREAKING AFTER %d----\n", i);
            }
        }
        // if (i == n_threads - 1)
        //     end_pack_id = file_length - 1;
        printf("--- %d: [start_id: %lu] [end_id: %lu] [end == '\\n' ? %d] [start = '%c']\n", i, start_pack_id, end_pack_id,
               pswd[end_pack_id] == '\n',
               pswd[start_pack_id]);
        spawned_threads++;
        for (size_t j = start_pack_id; j <= end_pack_id; j++)
        {
            printf("%c", pswd[j]);
        }
        next_start_pack_id = end_pack_id + 1;
    }
    printf("\nSpawned Threads: %d\n", spawned_threads);
    munmap(pswd, file_length);
    return false;
}

int main(const int argc, char *argv[])
{
    char *salted_hash = NULL;
    char *pswd_path = NULL;
    int n_threads = -1;
    parse_argv(argc, argv, &salted_hash, &pswd_path, &n_threads);
    // const int max_threads = (int) sysconf(_SC_NPROCESSORS_ONLN);
    if (n_threads == -1)
    {
        //todo: find best nr of threads
        //print progress after every thread tested. print_progress(i, max_threads)
    }
    else
    {
        // if (n_threads > max_threads) n_threads = max_threads;
        crack(salted_hash, pswd_path, n_threads);
    }

    return 0;
}
