#include <stdio.h>
#include <utmpx.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include "usrgrps.h"

int main(int argc, char* argv[])
{
    bool showGroups = false;  
    int ret;
    while ((ret = getopt(argc, argv, "g")) != -1)
    {
        switch (ret)
        {
            case 'g':
                showGroups = true;
                break;
        }
    }
    struct utmpx* user = NULL;
    setutxent();
    while ((user = getutxent()) != NULL)
    {
        if (user->ut_type == USER_PROCESS)
        {
            printf("%s", user->ut_user);
            if (!showGroups)
            {
                printf("\n");
                continue;
            }
            struct passwd* pw = getpwnam(user->ut_user);
            if (pw == NULL)
            {
                fprintf(stderr, "ERR: getpwnam(): Inapriopriate username");
                exit(EXIT_FAILURE);
            }
            __gid_t* groups = getUserGroups(pw->pw_uid);
            int ngroups = sizeof(groups) / sizeof(__gid_t);
            printf(" [");
            fflush(stdout);
            for (int i = 0; i < ngroups; i++)
            {
                struct group* gr = getgrgid(groups[i]);
                if (gr == NULL)
                {
                    fprintf(stderr, "ERR: getgrgid(): Inapriopriate __gid_t = %d\n", groups[i]);
                    if (groups != NULL)
                        free(groups);
                    exit(EXIT_FAILURE);
                }
                printf("%s", gr->gr_name);
                if (i != ngroups - 1)
                    printf(", ");
                fflush(stdout);
            }
            printf("]");
            fflush(stdout);
            if (groups != NULL)
                free(groups);
            printf("\n");
        }
    }
    endutxent();
}