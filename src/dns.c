#include "../include/nmap.h"

// References
// https://www.geeksforgeeks.org/ping-in-c/
// Resolve hostnames from IP addresses
struct sockaddr_in *DnsLookUp(char * hostName, char **resultIpAddress){
    // Initialize
    struct sockaddr_in *socketAddrIn =NULL;
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
    socketAddrIn->sin_port = htons (PORT_NO); 
    socketAddrIn->sin_addr.s_addr  = *(long*)hostEntity->h_addr;
    // Option to get IP address in char*
    if(resultIpAddress != NULL)
    {
        // Result resultIpAddress
        *resultIpAddress = (char *) malloc (sizeof(char) * NI_MAXHOST);
        strcpy(*resultIpAddress, inet_ntoa(*(struct in_addr *)hostEntity->h_addr)); 
    }
    return socketAddrIn;
}

// References
// https://www.geeksforgeeks.org/ping-in-c/
// Resolve IP addresses from hostnames
char *DnsReverseLookup(char * hostName){
    char * resultIp;
    return resultIp;
}

