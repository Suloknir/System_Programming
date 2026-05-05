#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <crypt.h>
#include <string.h>

void parse_argv(const int argc, char *const*argv, char **ret_hash, char **ret_filename, int *ret_n_threads)
{
    *ret_hash = NULL;
    *ret_filename = NULL;
    *ret_n_threads = -1;
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
                *ret_filename = optarg;
                break;
            case 'n':
                char *endptr;
                const int val = (int) strtol(optarg, &endptr, 0);
                if (endptr == optarg || val < 1)
                {
                    fprintf(stderr, "%s: option '%c' requires number >= 1 as an argument\n", argv[0], ret);
                    exit(EXIT_FAILURE);
                }
                *ret_n_threads = val;
                break;
            case '?':
                fprintf(stderr, "%s: Option '%c' requires argument\n", argv[0], optopt);
                exit(EXIT_FAILURE);
                break;
            default:
                abort();
        }
    }
    if (*ret_hash == NULL || *ret_filename == NULL)
    {
        fprintf(stderr, "Parameters 'p', 'f' are mandatory\n");
        fprintf(stderr, "Usage: %s -p [hashed password] -f [file] -n [n threads]\n", argv[0]);
        exit(EXIT_FAILURE);
    }
}

int main(const int argc, char *argv[])
{
    char *hash_to_find, *pswd_file;
    int n_threads;
    parse_argv(argc, argv, &hash_to_find, &pswd_file, &n_threads);
    printf("hash_to_find: %s\n", hash_to_find);
    printf("file: %s\n", pswd_file);
    printf("N_threads: %d\n", n_threads);
    return 0;
}
