// gcc ./lab3.c -o lab3 -lsystemd
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <grp.h>
#include <systemd/sd-bus.h>
#include <dlfcn.h>


int main(int argc, char* argv[])
{
    __gid_t* (*getUserGroups)(__uid_t, int*) = NULL;
    bool showGroups = false;
    bool showIds = false;
    int ret;
    while ((ret = getopt(argc, argv, "gi")) != -1)
    {
        switch (ret)
        {
            case 'g':
                showGroups = true;
                break;
            case 'i':
                showIds = true;
                break;
        }
    }
    
    sd_bus* bus = NULL;
    sd_bus_message* reply = NULL;
    int r;
    r = sd_bus_open_system(&bus); 
    if(r < 0)
    {
        fprintf(stderr, "ERR: sd_bus_open_system error\n");
        exit(r);
    }
    r = sd_bus_call_method(
        bus,
        "org.freedesktop.login1",
        "/org/freedesktop/login1",
        "org.freedesktop.login1.Manager",
        "ListSessions",
        NULL,
        &reply,
        "");
    if(r < 0)
    {
        fprintf(stderr, "ERR: ListSessions invocation error\n");
        sd_bus_unref(bus);
        exit(r);
    }
    r = sd_bus_message_enter_container(reply, 'a', "(susso)");
    if (r < 0)
    {
        fprintf(stderr, "ERR: Error while opening a container\n");
        sd_bus_message_unref(reply);
        sd_bus_unref(bus);
        exit(r);
    }

    void* handle;
    if (showGroups) 
    {
        handle = dlopen("./libusrgrps.so", RTLD_NOW);
        if (!handle)
        {
            char* errorMsg = dlerror();
            fprintf(stderr, "ERR: Error occured while loading shared library: %s\n", errorMsg);
            showGroups = false;
        }
        else
        {
            *(void**) &getUserGroups = dlsym(handle, "getUserGroups");
            if (getUserGroups == NULL)
            {
                char* errorMsg = dlerror();
                fprintf(stderr, "ERR: Error occured while loading getUserGroups function: %s\n", errorMsg);
                dlclose(handle);
                showGroups = false;
            }
        }
    }
    
    while ((r = sd_bus_message_enter_container(reply, 'r', "susso")) > 0)
    {
        sd_bus_message_skip(reply, "s");
        uint32_t userId;
        char* userName;
        sd_bus_message_read_basic(reply, 'u', &userId);
        sd_bus_message_read_basic(reply, 's', &userName);
        sd_bus_message_skip(reply, "so");
        sd_bus_message_exit_container(reply);

        printf("%s", userName);
        fflush(stdout);
        if (showIds)
            printf(" (%d)", userId);
        if (!showGroups)
        {
            printf("\n");
            continue;
        }

        int ngroups;
        __gid_t* groups = getUserGroups(userId, &ngroups);
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
        if (groups != NULL)
            free(groups);
        printf("\n");
    }
    if (showGroups)
        dlclose(handle);
    sd_bus_message_exit_container(reply);
    sd_bus_message_unref(reply);
    sd_bus_unref(bus);
}