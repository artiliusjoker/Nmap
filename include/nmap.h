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
#include <arpa/inet.h> 
#include <netinet/ip_icmp.h> 
#include <netinet/in.h> 
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <sys/types.h> 
#include <sys/socket.h> 

#include "constants.h"
#include "mystring.h"

// Other functions
// Resolve hostnames from IP addresses
struct sockaddr_in *DnsLookUp(char *, char **);
// Resolve IP addresses from hostnames
char *DnsReverseLookup(char *);
// Get addresses pool from net address and subnet mask
char ** GetAdressPool(uint32_t , uint32_t );
/*  
    Subnet mask (char *) to unit32_t 
    Converts /XX (char*) to network byte order in uint32_t 
*/
uint32_t SubnetMaskToUint32_t(char *);

/* 
    Function and structs to define a host

*/
// Each host is a struct
typedef struct host
{
    struct sockaddr_in *hostAddress;
    struct host * next;   
}__host__;
// Functions 
void Ping(struct host);
char * ReceiveReply();
// Linked List functions
void AddHost(__host__ **, __host__ *);
__host__ *NewHost(char * ipAddress);
void FreeHost(__host__ *);
void FreeListHosts(__host__ *);

/* 
    Function and structs to create threads

*/
typedef struct t_Thread
{   
    __host__ *hostList;
    pthread_t id;
    int numOfHosts;
    int pid;
};
void * ThreadRoutine(void *threadHandler);
void CreateThread(__host__ *, int, int);
void InitThreadPool();

extern int hostsSize;
extern __host__ * head;

#endif	/* nmap */