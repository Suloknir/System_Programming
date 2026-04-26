#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

int main(const int argc, char *argv[])
{
    int ret;
    char *salt = NULL;
    char *to_hash = NULL;
    opterr = 0;
    while ((ret = getopt(argc, argv, "s:h:")) != -1)
    {
        switch (ret)
        {
            case 's':
                salt = optarg;
                break;
            case 'h':
                to_hash = optarg;
                break;
            case '?':
                fprintf(stderr, "%s: Option '%c' requires argument\n", argv[0], optopt);
                exit(EXIT_FAILURE);
                break;
            default:
                abort();
        }
    }
    if (salt == NULL || to_hash == NULL)
    {
        fprintf(stderr, "%s: Parameters 's', 'h' are mandatory\n", argv[0]);
        exit(EXIT_FAILURE);
    }
}
