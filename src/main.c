#include "../include/nmap.h"

// List of hosts to check
__host__ *head = NULL;
// Size of above list
int hostsSize;

// Mutex Lock to avoid race condition
pthread_mutex_t lock;

// Current pid
pid_t currentPid;

// Driver code
int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        fprintf(stderr, "Enter 2 arguments only. \"StudentID Network/inputSubnetMask\"\n");
        exit(0);
    }
    currentPid = getpid();
    char *inputAddress = GetInfoFromStr(argv[1], NETWORK_ADDR);
    char *inputSubnetMask = GetInfoFromStr(argv[1], SUBNET_MASK);
    char *resolved;
    struct sockaddr_in *sockAddr_in;

    sockAddr_in = DnsLookUp(inputAddress, &resolved);

    uint32_t networkLong = htonl(sockAddr_in->sin_addr.s_addr);
    uint32_t netmaskLong = SubnetMaskToUint32_t(inputSubnetMask);
    // Create list of hosts in a network to scan
    GetAdressPool(networkLong, netmaskLong);
    // Calculate how many thread to be used
    int div = hostsSize / MAX_THREAD_POOL_SIZE;
    int remainder = hostsSize % MAX_THREAD_POOL_SIZE;
    // Begin pinging
    __host__ *temp = head;

    // If div = 0 use less port
    if (div == 0)
    {
        thread *listThreads = calloc(hostsSize, sizeof(thread));
        for (size_t i = 0; i < hostsSize; ++i)
        {
            if (temp == NULL)
                break;
            listThreads[i].threadTotal = i + 1;
            CreateThread(listThreads, temp, i, 1);
            temp = temp->next;
        }
        for (size_t i = 0; i < listThreads[0].threadTotal; ++i)
        {
            int s = pthread_join(listThreads[i].id, NULL);
        }
        free(listThreads);
    }
    // else one thread will handle more than one socket
    else
    {
    }
    // Join threads
    // End program
    pthread_mutex_destroy(&lock);
    FreeListHosts(head);
    FreeString(inputAddress);
    FreeString(inputSubnetMask);
    free(sockAddr_in);
    return 1;
}