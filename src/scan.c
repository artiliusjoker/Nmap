#include "../include/nmap.h"

static void SendPacket(struct sockaddr_in *source, struct sockaddr_in *des, int type)
{
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd < 0)
    {
        perror("Error in init socket !");
        return;
    }
    char *buffer;

    if (!(buffer = (char *)malloc(1024)))
    {
        return;
    }
    int packetSize = CreatePacket(buffer, source, des, type);
    if (packetSize <= 0)
    {
        perror("Error in creating packet !");
        return;
    }
    fprintf(stdout, "%i \n", packetSize);
    int sended = -1;
    if ((sended = sendto(fd, buffer, packetSize, 0, (struct sockaddr *)des, sizeof(struct sockaddr))) < 0)
    {
        fprintf(stdout, "Send not good !\n");
    }
    else
    {
        fprintf(stdout, "Send good !\n");
    }
    free(buffer);
    close(fd);
    return;
}

static void SniffPacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
}

void Scan(__host__ *host)
{
    struct sockaddr_in *destAddr = host->hostAddress;
    struct sockaddr_in *sourceAddr = (struct sockaddr_in *)defaultInterface->addresses->next->addr;
    SendPacket(sourceAddr, destAddr, ICMP_ECHO);
}