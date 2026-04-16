#include <stdio.h>
#include <utmpx.h>

int main(void)
{
    struct utmpx* user = NULL;
    setutxent();
    while ((user = getutxent()) != NULL)
    {
        if (user->ut_type == USER_PROCESS)
            printf("%d (%s)\n", user->ut_pid, user->ut_user);
    }
    endutxent();
}