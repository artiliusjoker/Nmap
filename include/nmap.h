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

// ping packet structure 
struct ping_pkt 
{ 
    struct icmphdr hdr; 
    char msg[PING_PKT_S-sizeof(struct icmphdr)]; 
};

// Function declarations

// Resolve hostnames from IP addresses
void DnsLookUp(char *, struct sockaddr_in *, char **);

// Resolve IP addresses from hostnames
char *DnsReverseLookup(char *);


unsigned short checksum(void *b, int len);
void intHandler(int dummy);
char *dns_lookup(char *addr_host, struct sockaddr_in *addr_con);
char* reverse_dns_lookup(char *ip_addr);
void send_ping(int ping_sockfd, struct sockaddr_in *ping_addr, 
            char *ping_dom, char *ping_ip, char *rev_host);


#endif	/* network */