#include "../include/nmap.h"
/*
    2 types of ICMP packets to be used
    ICMP Reply Request
    ICMP timestamps Request

    2 types of TCP packets to be used
    TCP SYN to port 443
    TCP ACK to port 80
*/
static struct icmp *CreateICMP(int type)
{
    struct icmp *icmp;
    char *buffer = (char *)malloc((ICMP_PKT_SIZE));

    // Initialize Icmp packet
    icmp = (struct icmp *)buffer;
    icmp->icmp_code = 0;
    icmp->icmp_id = currentPid;
    icmp->icmp_seq = 0;
    icmp->icmp_type = type;
    if (type == ICMP_ECHO)
    {
        bzero(icmp + 8, 12);
    }
    else if (type == ICMP_TIMESTAMP)
    {
        gettimeofday((struct timeval *)(icmp + 8), NULL);
        bzero(icmp + 12, 8);
    }
    // Calculate checksum
    icmp->icmp_cksum = checkSum((uint16_t *)icmp, ICMP_PKT_SIZE);
    return icmp;
}

/*
    Ref
    https://github.com/rbaron/raw_tcp_socket/blob/master/raw_tcp_socket.c
*/
static struct tcphdr *CreateTCPhdr(int type, int srcPort, int desPort,struct sockaddr_in *source, struct sockaddr_in *des)
{
    struct tcphdr *newTCPhdr;
    p_tcp *psuedoHeader = (p_tcp *) malloc(sizeof(p_tcp));

    char *buffer = (char *)malloc( sizeof(struct tcphdr));
    // Initialize TCP header
    newTCPhdr = (struct tcphdr *)buffer;

    //Populate
    newTCPhdr->source = htons(srcPort); //16 bit in nbp format of source port
    newTCPhdr->dest = htons(desPort);   //16 bit in nbp format of destination port
    newTCPhdr->seq = 0x0;               //32 bit sequence number, initially set to zero
    newTCPhdr->ack_seq = 0x0;           //32 bit ack sequence number, depends whether ACK is set or not
    newTCPhdr->doff = 5;                //4 bits: 5 x 32-bit words on tcp header
    newTCPhdr->res1 = 0;                //4 bits: Not used
    newTCPhdr->cwr = 0;                 //Congestion control mechanism
    newTCPhdr->ece = 0;                 //Congestion control mechanism
    newTCPhdr->urg = 0;                 //Urgent flag
    newTCPhdr->ack = 0;                 //Acknownledge
    newTCPhdr->psh = 0;                 //Push data immediately
    newTCPhdr->rst = 0;                 //RST flag
    newTCPhdr->syn = 1;                 //SYN flag
    newTCPhdr->fin = 0;                 //Terminates the connection
    newTCPhdr->window = htons(155);     //0xFFFF; //16 bit max number of databytes
    newTCPhdr->check = 0;               //16 bit check sum. Can't calculate at this point
    newTCPhdr->urg_ptr = 0;             //16 bit indicate the urgent data. Only if URG flag is set

    // Pseudo header for checksum
    psuedoHeader->dstAddr = des->sin_addr.s_addr;
    psuedoHeader->srcAddr = source->sin_addr.s_addr;
    psuedoHeader->zero = 0; // placeholder
    psuedoHeader->TCP_len = htons(sizeof(struct tcphdr));
    psuedoHeader->protocol = IPPROTO_TCP;
    // Checksum
    newTCPhdr->check = checkSum((unsigned short*)psuedoHeader , sizeof(p_tcp));
    free(psuedoHeader);
    return newTCPhdr;
}

void CreatePacket(char *buffer, struct sockaddr_in *source, struct sockaddr_in *des, int type)
{
    struct ip *ip = (struct ip *)buffer;
    // Same IP header for all types
    ip->ip_src = source->sin_addr;
    ip->ip_dst = des->sin_addr;
    ip->ip_v = 4;
    ip->ip_hl = sizeof(struct ip) >> 2;
    ip->ip_tos = 0;
    ip->ip_id = htons(currentPid);
    ip->ip_ttl = 64;
    ip->ip_sum = 0; /* calculate later */

    int protocolLength = 0;
    if (type == ICMP_TIMESTAMP || type == ICMP_ECHO)
    {
        struct icmp *icmp = (struct icmp *)(ip + 1);
        struct icmp *newPacket = CreateICMP(type);
        protocolLength = sizeof(newPacket);
        memcpy(icmp, newPacket, protocolLength);
        ip->ip_p = IPPROTO_ICMP;
        free(newPacket);
    }
    else if (type == TCP_ACK_80 || type == TCP_SYN_443)
    {
        return;
        ip->ip_p = IPPROTO_TCP;
        struct tcphdr *tcpHeader = (struct iphdr *)(ip + 1);
        //struct tcph * newTcpHeader = CreateTCPhdr();
    }
    else
    {
        fprintf(stderr, "ERR: unknown packet type\n");
        return;
    }
    ip->ip_len = sizeof(struct ip) + protocolLength;
    ip->ip_sum = checkSum((unsigned short *)ip, ip->ip_len);
}