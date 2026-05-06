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

bool crack(const char *salted_hash, const char* pswd_path, int n_threads)
{
    int fd = open(pswd_path, O_RDONLY);
    if (fd == -1)
        err(EXIT_FAILURE, "open error\n");

    struct stat sb;
    if (fstat(fd, &sb) == -1)
        err(EXIT_FAILURE, "fstat error\n");
    char* pswd = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (pswd == MAP_FAILED)
        err(EXIT_FAILURE, "mmap error\n");
    
    printf("First character: '%c'", pswd[0]);
    munmap(pswd, sb.st_size);
    return false;
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
    }
    else
    {
        if (n_threads > max_threads) n_threads = max_threads;
        crack(salted_hash, pswd_path, n_threads);
    }

    return 0;
}
