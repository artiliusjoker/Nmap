#include "../include/nmap.h"

void *ThreadRoutine(void *args)
{
    thread_tra *arguments = (thread_tra *)args;
    // Do its work
    __host__ *temp = arguments->hostList;
    for (size_t i = 0; i < arguments->numOfHosts; ++i)
    {
        if(temp == NULL)
        {
            free(arguments);
            return NULL;
        }
        ScanArp(temp);
        temp = temp->next;
    }
    return NULL;
}

void CreateThread(thread **list, __host__ *hosts, int pid, int hostsNum)
{
    (*list)[pid].hostList = hosts;
    (*list)[pid].numOfHosts = hostsNum;
    (*list)[pid].pid = pid;
    thread_tra *arguments = (thread_tra *)malloc(sizeof(thread_tra));
    arguments->hostList = hosts;
    arguments->numOfHosts = hostsNum;
    if (pthread_create(&((*list)[pid].id), NULL, ThreadRoutine, arguments) == 0)
    {
        // Thread executing
    }
    else
    {
        fprintf(stdout, "Unable to create thread : %i", pid);
    }
}