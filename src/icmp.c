#include "../include/nmap.h"
/*
 ** Compute the internet checksum
 */
unsigned short checkSum(unsigned short *ptr, int nbytes)
{
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum = 0;
    while (nbytes > 1)
    {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1)
    {
        oddbyte = 0;
        *((u_char *)&oddbyte) = *(u_char *)ptr;
        sum += oddbyte;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    answer = (short)~sum;
    return (answer);
}

struct icmp *InitPingPacket()
{
    struct icmp *icmp;
    char *sendBuffer = (char *)malloc((ICMP_PKT_SIZE) * sizeof(char));

    // Initialize Icmp packet
    icmp = (struct icmp *)sendBuffer;
    icmp->icmp_type = ICMP_ECHO;
    icmp->icmp_code = 0;
    icmp->icmp_id = currentPid;
    icmp->icmp_seq = 0;
    memset(icmp->icmp_data, 0xa5, ICMP_PKT_SIZE - 8); /* fill with pattern */

    // Calculate checksum
    icmp->icmp_cksum = checkSum((uint16_t *)icmp, ICMP_PKT_SIZE);

    return icmp;
}

void Ping(__host__ *host, struct icmp *packetToSend)
{
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (fd < 0)
    {
        perror("Error in init socket !");
        return;
    }

    struct timeval timeval_Timeout;
    timeval_Timeout.tv_sec = RECEIVE_TIMEOUT;
    timeval_Timeout.tv_usec = 0;
    // setting timeout of socket
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeval_Timeout, sizeof(timeval_Timeout));

    struct sockaddr *destAddr = (struct sockaddr *)host->hostAddress;
    
    if (sendto(fd, packetToSend, ICMP_PKT_SIZE, 0, destAddr, sizeof(struct sockaddr)) < 0)
    {
        perror("Error in sending packet !");
        return;
    };
    //pthread_mutex_unlock(&lock);

    ReceiveReply(fd, host);

    free(packetToSend);
}

void ReceiveReply(int sockFd, __host__ *hostSended)
{
    pthread_mutex_lock(&lock);

    struct sockaddr *sourceAddress = (struct sockaddr *)hostSended->hostAddress;
    struct msghdr msg;
    struct iovec iov;
    ssize_t messageSize;

    char receiveBuffer[ICMP_PKT_RCV_SIZE];
    char controlBuffer[ICMP_PKT_RCV_SIZE];

    struct sockaddr_in source;
    int len = sizeof(source);
    //fprintf(stdout, "%s \n", inet_ntoa(hostSended->hostAddress->sin_addr));
    messageSize = recvfrom(sockFd, receiveBuffer, ICMP_PKT_RCV_SIZE, 0, &source, &len);
    if (messageSize > 0)
    {
        if (source.sin_addr.s_addr == hostSended->hostAddress->sin_addr.s_addr)
        {
            fprintf(stdout, "%s \n", inet_ntoa(source.sin_addr));
        }
    }
    pthread_mutex_unlock(&lock);
    // iov.iov_base = receiveBuffer;
    // iov.iov_len = sizeof(receiveBuffer);
    // msg.msg_name = sourceAddress;
    // msg.msg_iov = &iov;
    // msg.msg_iovlen = 1;
    // msg.msg_control = controlBuffer;

    // msg.msg_namelen = sizeof(struct sockaddr);
    // msg.msg_controllen = sizeof(controlBuffer);

    // messageSize = recvmsg(sockFd, &msg, 0);
    // if (messageSize < 0)
    // {
    //     return;
    // }
    // else
    // {
    //     int ipHeaderLength, icmpHeaderLength;
    //     struct ip *ip;
    //     struct icmp *icmp;

    //     ip = (struct ip *)receiveBuffer; /* start of IP header */
    //     ipHeaderLength = ip->ip_hl << 2; /* length of IP header */
    //     if (ip->ip_p != IPPROTO_ICMP)
    //         return; /* not ICMP */
    //     // Check correct packet
    //     // char temp[IPV4_ADDR_SIZE];
    //     // strcpy(temp, inet_ntoa(hostSended->hostAddress->sin_addr));
    //     // if (strcmp(inet_ntoa(ip->ip_src), temp) != 0)
    //     // {
    //     //     return;
    //     // }
    //     icmp = (struct icmp *)(receiveBuffer + ipHeaderLength); /* start of ICMP header */
    //     if ((icmpHeaderLength = messageSize - ipHeaderLength) < 8)
    //         return; /* malformed packet */

    //     if (icmp->icmp_type == ICMP_ECHOREPLY)
    //     {
    //         if (icmp->icmp_id != currentPid)
    //             return; /* not a response to our ECHO_REQUEST */
    //         if (icmpHeaderLength < 16)
    //             return; /* not enough data to use */
    //         fprintf(stdout, "%s \n", inet_ntoa(ip->ip_src));
    //     }
    // }
}
