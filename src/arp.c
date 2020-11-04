#include "../include/nmap.h"
void ScanArp(__host__ *host)
{
    // Create packet
    arp_packet newPacket;
    struct ifreq *interfaceRequest = GetInterface();
    // Ethernet
    memset(newPacket.ether.ether_dhost, 0xFF, ETH_ALEN);
    memcpy(&(newPacket.ether.ether_shost), interfaceRequest->ifr_hwaddr.sa_data, ETH_ALEN);
    newPacket.ether.ether_type = htons(ETHERTYPE_ARP);
    // ARP fields
    newPacket.arp.ar_hrd = htons(ARPHRD_ETHER);
    newPacket.arp.ar_pro = htons(ETHERTYPE_IP);
    newPacket.arp.ar_hln = ETHER_ADDR_LEN;
    newPacket.arp.ar_pln = sizeof(newPacket.sender_ip);
    newPacket.arp.ar_op = htons(ARPOP_REQUEST);
    // Sender info
    memcpy(&newPacket.sender_mac, interfaceRequest->ifr_hwaddr.sa_data, ETH_ALEN);
    struct sockaddr_in *sin = (struct sockaddr_in *)&interfaceRequest->ifr_addr;
    newPacket.sender_ip = htonl(sin->sin_addr.s_addr);
    // Destination info
    memset(newPacket.target_mac, 0, ETH_ALEN);
    newPacket.target_ip = host->hostAddress->sin_addr.s_addr;
    // Fill padding with 0
    memset(newPacket.padding, 0, sizeof(newPacket.padding));

    // Send packet
    pthread_mutex_lock(&lock);
    int fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (fd < 0)
    {
        perror("Error in init socket !");
        return;
    }
    pthread_mutex_unlock(&lock);
    struct sockaddr_ll sa_ll;
    sa_ll.sll_family = AF_PACKET;
    sa_ll.sll_protocol = htons(ETH_P_ARP);
    sa_ll.sll_ifindex = if_nametoindex("eth0");
    sa_ll.sll_hatype = ARPHRD_ETHER;
    sa_ll.sll_pkttype = PACKET_BROADCAST;
    sa_ll.sll_halen = 0;
    memcpy(sa_ll.sll_addr, newPacket.sender_mac, 6 * sizeof(uint8_t));
    // Send packets
    int result = sendto(fd, &newPacket, sizeof(newPacket), 0, (struct sockaddr *)&sa_ll, sizeof(sa_ll));
    if (result < 0)
    {
        fprintf(stdout, "Cannot send ARP packet !!!\n");
    }

    // Receive packets

    // int i, sd, status;
    // uint8_t *ether_frame;
    // arp_hdr *arphdr;

    // // Allocate memory for various arrays.
    // ether_frame = allocate_ustrmem(IP_MAXPACKET);

    // // Listen for incoming ethernet frame from socket sd.
    // // We expect an ARP ethernet frame of the form:
    // //     MAC (6 bytes) + MAC (6 bytes) + ethernet type (2 bytes)
    // //     + ethernet data (ARP header) (28 bytes)
    // // Keep at it until we get an ARP reply.
    // arphdr = (arp_hdr *)(ether_frame + 6 + 6 + 2);
    // while (((((ether_frame[12]) << 8) + ether_frame[13]) != ETH_P_ARP) || (ntohs(arphdr->opcode) != ARPOP_REPLY))
    // {
    //     if ((status = recv(sd, ether_frame, IP_MAXPACKET, 0)) < 0)
    //     {
    //         if (errno == EINTR)
    //         {
    //             memset(ether_frame, 0, IP_MAXPACKET * sizeof(uint8_t));
    //             continue; // Something weird happened, but let's try again.
    //         }
    //         else
    //         {
    //             perror("recv() failed:");
    //             exit(EXIT_FAILURE);
    //         }
    //     }
    // }

    struct sockaddr_in *sourceAddress = host->hostAddress;
    ssize_t messageSize;

    char receiveBuffer[ICMP_PKT_RCV_SIZE];

    // Timeout
    struct timeval tv;
    tv.tv_sec = RECEIVE_TIMEOUT;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv);

    messageSize = recv(fd, receiveBuffer, ICMP_PKT_RCV_SIZE, 0);
    //messageSize = recvfrom(fd, receiveBuffer, ICMP_PKT_RCV_SIZE, 0, &source, &addressLength);
    if (messageSize > 0)
    {
        char *result = (char *)malloc(IPV4_ADDR_SIZE);
        strcpy(result, inet_ntoa(source.sin_addr));
        // Lock to avoid race condition
        pthread_mutex_lock(&lock);
        // Actions in lock
        ++numHostsFound;
        fprintf(stdout, "Host : %s is up \n", result);
        WriteResultsToFile(result);
        // Unlock
        pthread_mutex_unlock(&lock);
    }
    close(fd);
}