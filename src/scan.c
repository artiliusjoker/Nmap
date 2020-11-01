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
    printf("enter sniff \n");
    return;
}

void Scan(__host__ *host)
{
    // PCAP lib
    pcap_t *handle;
    char filter[50];
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program filter_compiled;
    bpf_u_int32 network;
    bpf_u_int32 subnet;
    // Get net/mask infos
    pthread_mutex_lock(&lock);
    if (pcap_lookupnet(defaultInterface->name, &network, &subnet, errbuf) < 0)
    {
        printf("Error: Unable to get net/mask informations\n");
        return;
    }
    pthread_mutex_unlock(&lock);

    struct sockaddr_in *destAddr = host->hostAddress;
    struct sockaddr_in *sourceAddr = (struct sockaddr_in *)defaultInterface->addresses->next->addr;
    // Prepare to capture packets (lock threads because use same interface)
    //pthread_mutex_lock(&lock);
    // Open device for live capture
    if ((handle = pcap_open_live(defaultInterface->name, BUFSIZ, 1, 1, errbuf)) == NULL)
    {
        fprintf(stderr, "Error: Unable to open %s for live capture: %s\n", defaultInterface->name, errbuf);
        return;
    }
    // Get IP of interface
    char sourceInChar[IPV4_ADDR_SIZE];
    strcpy(sourceInChar, inet_ntoa(sourceAddr->sin_addr));
    sprintf(filter, "src host %s and dst host %s",host->addressString, sourceInChar);

    // Compile pcap filter expression
    if (pcap_compile(handle, &filter_compiled, filter, 0, subnet) == -1)
    {
        printf("Error: Unable to compile pcap filter\n");
        pcap_close(handle);
        return;
    }

    // Set pcap filter expression
    if (pcap_setfilter(handle, &filter_compiled) == -1)
    {
        printf("Error: Unable to set pcap filter\n");
        pcap_close(handle);
        return;
    }

    // No longer need once pcap_setfilter is called
    pcap_freecode(&filter_compiled);
    //pthread_mutex_unlock(&lock);

    SendPacket(sourceAddr, destAddr, ICMP_ECHO);
    // Dispatch incoming packets
    //pcap_dispatch(handle, 2, SniffPacket, NULL);
   
    pcap_close(handle);
}