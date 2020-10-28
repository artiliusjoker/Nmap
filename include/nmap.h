#ifndef	nmap
#define	nmap

#include <stdio.h> 
#include <netdb.h> 
#include <unistd.h> 
#include <string.h> 
#include <stdlib.h> 
#include <time.h> 
#include <fcntl.h> 
#include <signal.h> 
#include <time.h>
#include <pthread.h>
#include <arpa/inet.h> 
#include <netinet/ip_icmp.h> 
#include <netinet/in.h> 
#include <netinet/in_systm.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <sys/types.h> 
#include <sys/socket.h> 

#include "constants.h"
#include "mystring.h"

// Structs
// Each host is a struct
typedef struct host
{
    struct sockaddr_in *hostAddress;
    struct host * next;   
}__host__;

typedef struct t_Thread
{   
    __host__ *hostList;
    pthread_t id;
    int numOfHosts;
    int pid;
    int threadTotal; // Total number of threads
}thread;

// Other functions
// Resolve hostnames from IP addresses
struct sockaddr_in *DnsLookUp(char *, char **);
// Resolve IP addresses from hostnames
char *DnsReverseLookup(char *);
// Get addresses pool from net address and subnet mask
void GetAdressPool(uint32_t , uint32_t );
/*  
    Subnet mask (char *) to unit32_t 
    Converts /XX (char*) to network byte order in uint32_t 
*/
uint32_t SubnetMaskToUint32_t(char *);

/* 
    Function to define a host

*/
// Linked List functions
void AddHost(__host__ **, __host__ *);
__host__ *NewHost(char * ipAddress);
void FreeHost(__host__ *);
void FreeListHosts(__host__ *);

/* 
    Function to create threads

*/
void * ThreadRoutine(void *threadHandler);
void CreateThread(thread *,__host__ *, int, int);

/* 
    Function to create ICMP packet, send and receive messages

*/
struct icmp * InitPingPacket();
void Ping(__host__ *, struct icmp *);
void ReceiveReply(int sockFd, __host__ *);
unsigned short checkSum(unsigned short *, int);

// Global variables
extern int hostsSize;
extern __host__ * head;
extern pthread_mutex_t lock;
extern pid_t currentPid;

#endif	/* nmap */