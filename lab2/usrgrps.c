#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pwd.h>
#include "usrgrps.h"


__gid_t* getUserGroups(__uid_t userId)
{
    __gid_t* result = NULL;
    struct passwd* pw = getpwuid(userId);
    if (pw == NULL)
    {
        fprintf(stderr, "ERR: getpwuid(): Inapriopriate __uid_t = %d\n", userId);
        exit(EXIT_FAILURE);
    }
    int ngroups = 0;
    getgrouplist(pw->pw_name, pw->pw_gid, result, &ngroups);
    if (ngroups > 0)
    {
        result = (__gid_t*)malloc(sizeof(__gid_t) * ngroups);
        if (result == NULL)
        {
            fprintf(stderr, "ERR: malloc error\n");
            exit(EXIT_FAILURE);
        }
        getgrouplist(pw->pw_name, pw->pw_gid, result, &ngroups);
    }
    return result;
}
