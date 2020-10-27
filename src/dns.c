#include "../include/nmap.h"

// References
// https://www.geeksforgeeks.org/ping-in-c/
void DnsLookUp(char * ipAddress, struct sockaddr_in * socketAddrIn, char **hostName){
    memset(socketAddrIn, 0, sizeof(struct sockaddr_in));
    struct hostent *hostEntity; 
    
    if ((hostEntity = gethostbyname(ipAddress)) == NULL) 
    { 
        perror("Error in DNS lookup !");
        exit(EXIT_FAILURE);
    }
    // Copy result from host entity
    (*socketAddrIn).sin_family = hostEntity->h_addrtype; 
    (*socketAddrIn).sin_port = htons (PORT_NO); 
    (*socketAddrIn).sin_addr.s_addr  = *(long*)hostEntity->h_addr;

    // Result hostname
    *hostName = (char *) malloc (sizeof(char) * NI_MAXHOST);
    strcpy(*hostName, inet_ntoa(*(struct in_addr *)hostEntity->h_addr)); 
}

// References
// https://www.geeksforgeeks.org/ping-in-c/
char *DnsReverseLookup(char * hostName){
    char * resultIp;
    return resultIp;
}

