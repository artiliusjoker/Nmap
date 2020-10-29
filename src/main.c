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
    currentPid = getpid() & 0xffff;
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
    __host__ *temp = head;      // Head of linked list
    thread *listThreads = NULL; // Thread array
    int numOfThreads = 0;
    // If div = 0 use less port
    if (div == 0)
    {
        listThreads = calloc(hostsSize, sizeof(thread));
        for (size_t i = 0; i < hostsSize; ++i)
        {
            if (temp == NULL)
                break;
            numOfThreads = hostsSize;
            CreateThread(&listThreads, temp, i, 1);
            temp = temp->next;
        }
    }
    // else one thread will handle more than one socket
    else
    {
        int i = 0;
        int r = 0;
        int threadIndex = 0;
        int hostsPerThread;
        listThreads = calloc(MAX_THREAD_POOL_SIZE, sizeof(thread));

        while (threadIndex < MAX_THREAD_POOL_SIZE)
        {
            r = hostsSize - i;
            hostsPerThread = r > div  ? (div + 1): div;
            numOfThreads = MAX_THREAD_POOL_SIZE;
            CreateThread(&listThreads, temp, threadIndex, hostsPerThread);
            i += hostsPerThread;
            ++threadIndex;
            for (size_t j = 0; j < hostsPerThread; ++j)
            {
                if (temp == NULL)
                    break;
                temp = temp->next;
            }
            if (temp == NULL)
                break;
        }
    }
    // Join threads
    for (size_t i = 0; i < numOfThreads; ++i)
    {
        int s = pthread_join(listThreads[i].id, NULL);
        if (s == 0)
        {
            fprintf(stdout, "Thread : %i done \n", i);
        }
        else if (s != 0)
        {
            // Cannot join thread
        }
    }
    // End program, cleaning garbage
    free(listThreads);
    pthread_mutex_destroy(&lock);
    FreeListHosts(head);
    FreeString(inputAddress);
    FreeString(inputSubnetMask);
    free(sockAddr_in);
    return 1;
}

void WriteResultsToFile(char * result)
{
     // creating file pointer to work with files
    FILE *fp;

    // opening file in writing mode
    fp = fopen("1712695.txt", "a");

    if (fp == NULL) {
        perror("Error in opening file !");
        return;
    }
    fprintf(fp, "%s \n", result);
    fclose(fp);
}