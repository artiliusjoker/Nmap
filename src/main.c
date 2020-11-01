#include "../include/nmap.h"

// List of hosts to check
__host__ *head = NULL;
// Size of above list
int hostsSize;

// Mutex Lock to avoid race condition
pthread_mutex_t lock;

// Current pid
pid_t currentPid;

int numHostsFound = 0;

pcap_if_t * defaultInterface = NULL;

// Driver code
int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        fprintf(stderr, "Enter 2 arguments only. \"StudentID Network/inputSubnetMask\"\n");
        exit(0);
    }
    // Get interface to capture
    defaultInterface = GetInterface();
    if(defaultInterface == NULL)
    {
        fprintf(stderr, "No interface to be captured !");
        exit(0);
    }
    // Timer
    struct timespec time_start, time_end;
    long timeExecuted;
    // Pid id 16 bit
    currentPid = getpid() & 0xffff;
    // Tokenize the input into NetAddr and Subnet mask
    char *inputAddress = GetInfoFromStr(argv[1], NETWORK_ADDR);
    char *inputSubnetMask = GetInfoFromStr(argv[1], SUBNET_MASK);
    struct sockaddr_in *inputNetworkAddress;
    // char * to sockaddr_in
    inputNetworkAddress = GetAddressInfo(inputAddress);
    // Change to unit32_t
    uint32_t networkLong = htonl(inputNetworkAddress->sin_addr.s_addr);
    uint32_t netmaskLong = SubnetMaskToUint32_t(inputSubnetMask);
    // Create list of hosts in a network to scan
    GetAdressPool(networkLong, netmaskLong);
    // Calculate how many thread to be used
    int div = hostsSize / MAX_THREAD_POOL_SIZE;
    int remainder = hostsSize % MAX_THREAD_POOL_SIZE;
    // Begin pinging
    clock_gettime(CLOCK_MONOTONIC, &time_start);
    __host__ *temp = head;      // Head of linked list of hosts list
    thread *listThreads = NULL; // Thread array
    int numOfThreads = 0;
    // If div = 0 use less threads
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
            // Joined
        }
        else if (s != 0)
        {
            // Cannot join thread
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &time_end);
    timeExecuted = time_end.tv_sec - time_start.tv_sec;

    fprintf(stdout, "Nmap done : %i IP addresses (%i hosts up) scanned in %i seconds\n", hostsSize, numHostsFound, timeExecuted);
    // End program, cleaning garbage
    // Free list threads
    free(listThreads);
    pthread_mutex_destroy(&lock);
    FreeListHosts(head);
    FreeString(inputAddress);
    FreeString(inputSubnetMask);
    free(inputNetworkAddress);
    pcap_freealldevs(defaultInterface);
    return EXIT_SUCCESS;
}
// Utilities
// Def function to write to file
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
    FreeString(result);
}
// References
// https://www.geeksforgeeks.org/ping-in-c/
// Get address from hostname
struct sockaddr_in *GetAddressInfo(char * hostName){
    // Initialize
    struct sockaddr_in *socketAddrIn = NULL;
    socketAddrIn = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
    memset(socketAddrIn, 0, sizeof(struct sockaddr_in));

    struct hostent *hostEntity; 
    
    if ((hostEntity = gethostbyname(hostName)) == NULL) 
    { 
        perror("Error in DNS lookup !");
        exit(EXIT_FAILURE);
    }
    // Copy result from host entity
    socketAddrIn->sin_family = hostEntity->h_addrtype; 
    socketAddrIn->sin_addr.s_addr  = *(uint32_t*)hostEntity->h_addr;
    return socketAddrIn;
}
pcap_if_t *GetInterface(){
    pcap_if_t *defaultInterface = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];

    if(pcap_findalldevs(&defaultInterface,errbuf) != 0)
    {
        perror("Cannot find any device to capture incoming packets !");
        return (NULL);
    }
    return defaultInterface;
}