#ifndef nmap
#define nmap

#include <stdio.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "constants.h"
#include "../libpcap/pcap/pcap.h"

// Each host is stored in a struct
typedef struct host
{
    struct sockaddr_in *hostAddress;
    struct host *next;
} __host__;
// Each thread is stored in a struct
typedef struct t_Thread
{
    __host__ *hostList;
    pthread_t id;
    int numOfHosts;
    int pid;
} thread;

// helper functions

// Write to file
void WriteResultsToFile(char *);
// Get input
char *GetInfoFromStr(char *, int);
// Free string
void FreeString(char *);
// Get interface
pcap_if_t *GetInterface();
// Get address info in sockaddr_in from host name
struct sockaddr_in *GetAddressInfo(char *);
/* 
    ** Get addresses to be scanned from net address and subnet mask
    ** First arg : IP address in Network byte order (unsigned int 32 bit)
    ** Second arg : Mask in Network byte order (unsigned int 32 bit)
    // References
    https://stackoverflow.com/questions/41316678/finding-host-address-range-in-c
*/
void GetAdressPool(uint32_t, uint32_t);
/*  
    ** Subnet mask (char *) to unit32_t 
    ** Converts /XX (char*) to network byte order in uint32_t 
*/
uint32_t SubnetMaskToUint32_t(char *);

/* 
    Function to define a host
    // Linked List functions
*/
void AddHost(__host__ **, __host__ *);
__host__ *NewHost(char *ipAddress);
void FreeHost(__host__ *);
void FreeListHosts(__host__ *);

/* 
    Functions related to threading
    Struct below : arguments for thread routine
*/
typedef struct thread_routine_args
{
    __host__ *hostList;
    int numOfHosts;
} thread_tra;
void *ThreadRoutine(void *);
void CreateThread(thread **, __host__ *, int, int);

/* 
    Functions related to ICMP protocol
*/
struct icmp *InitPingPacket();
void Ping(__host__ *, struct icmp *);
void ReceiveReply(int sockFd, __host__ *);
// Simple checksum algoritm
unsigned short checkSum(unsigned short *, int);
/* 
    Functions related to Packets
*/
size_t CreatePacket(char *, struct sockaddr_in *, struct sockaddr_in *, int);

typedef struct psuedo_tcp
{
    uint32_t srcAddr;
    uint32_t dstAddr;
    uint8_t zero;
    uint8_t protocol;
    uint16_t TCP_len;
} p_tcp;

// Scan
void Scan(__host__ *);

// Global variables
// Number of hosts to be scanned
extern int hostsSize;
// Head of Linked list of Hosts
extern __host__ *head;
// Global thread mutex lock
extern pthread_mutex_t lock;
// This Pid is used to put in ID field in ICMP packets (16 bit);
extern pid_t currentPid;
// Number of hosts found
extern int numHostsFound;
// Interface to be used
extern pcap_if_t *defaultInterface;

#endif /* nmap */