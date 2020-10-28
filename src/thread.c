#include "../include/nmap.h"

void *ThreadRoutine(void *hosts)
{
    // Do its work
    struct icmp *newPacket = InitPingPacket();
    Ping((__host__ *)hosts, newPacket);
    return NULL;
}

void CreateThread(thread *list, __host__ *hosts, int pid, int hostsNum)
{
    list[pid].hostList = hosts;
    list[pid].numOfHosts = hostsNum;
    list[pid].pid = pid;

    if (pthread_create(&(list[pid].id), NULL, ThreadRoutine, hosts) == 0)
    {
    }
    else
    {
        printf("Error: Unable to create sniffer thread\n");
    }
}