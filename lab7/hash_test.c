#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <crypt.h>
#include <string.h>

int main(const int argc, char *argv[])
{
    int ret;
    char *salt = NULL;
    char *password = NULL;
    opterr = 0;
    while ((ret = getopt(argc, argv, "s:p:")) != -1)
    {
        switch (ret)
        {
            case 's':
                salt = optarg;
                break;
            case 'p':
                password = optarg;
                break;
            case '?':
                fprintf(stderr, "%s: Option '%c' requires argument\n", argv[0], optopt);
                exit(EXIT_FAILURE);
                break;
            default:
                abort();
        }
    }
    if (salt == NULL || password == NULL)
    {
        fprintf(stderr, "%s: Parameters 's' (salt), 'p' (password) are mandatory\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    struct crypt_data data;
    data.initialized = 0;
    char *hash_func = "$6$";
    size_t buf_len = strlen(salt) + strlen(hash_func) + 1;
    char *buffer = malloc(buf_len * sizeof(char));
    if (buffer == NULL)
        perror("malloc error");
    snprintf(buffer, buf_len, "%s%s", hash_func, salt);
    const char *hash = crypt_r(password, buffer, &data);
    free(buffer);
    if (hash == NULL)
        perror("crypt_r error\n");
    printf("Hashed password: %s\n", hash);
    return 0;
}
