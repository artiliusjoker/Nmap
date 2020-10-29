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
    struct sockaddr *destAddr = (struct sockaddr *)host->hostAddress;

    if (sendto(fd, packetToSend, ICMP_PKT_SIZE, 0, destAddr, sizeof(struct sockaddr)) < 0)
    {
        perror("Error in sending packet !");
        return;
    };
    // Receive ICMP_REPLY
    ReceiveReply(fd, host);

    free(packetToSend);
}

void ReceiveReply(int sockFd, __host__ *hostSended)
{
    struct sockaddr_in *sourceAddress = hostSended->hostAddress;
    ssize_t messageSize;

    char receiveBuffer[ICMP_PKT_RCV_SIZE];

    // counting timeout of socket
    struct timespec time_start, time_end;
    uint32_t seconds;

    // Receive packets
    struct sockaddr_in source;
    int addressLength = sizeof(source);
    clock_gettime(CLOCK_MONOTONIC, &time_start);
    while (1)
    {
        messageSize = recvfrom(sockFd, receiveBuffer, ICMP_PKT_RCV_SIZE, 0, &source, &addressLength);
        if (messageSize > 0)
        {
            // Check ip correct respond, then write to file
            if (source.sin_addr.s_addr == sourceAddress->sin_addr.s_addr)
            {
                char *result = (char *)malloc(sizeof(inet_ntoa(source.sin_addr)));
                strcpy(result, inet_ntoa(source.sin_addr));
                WriteResultsToFile(result);
                break;
            }
            clock_gettime(CLOCK_MONOTONIC, &time_end);
            seconds = time_end.tv_sec - time_start.tv_sec;
            if(seconds >= RECEIVE_TIMEOUT)
                break;
        }
    }
}
