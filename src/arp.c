#include "../include/nmap.h"

// Struct to receive ARP reply
struct ether_arp
{
    // Default fields in arphdr
    unsigned short arp_hrd;
    unsigned short arp_pro;
    unsigned char arp_hln;
    unsigned char arp_pln;
    unsigned short arp_op;
    // Fields to get source address
    unsigned char arp_sha[6];
    unsigned char arp_spa[4];
    unsigned char arp_tha[6];
    unsigned char arp_tpa[4];
};

void ScanArp(__host__ *host)
{
    // Create packet

    arp_packet newPacket;
    struct ifreq *interfaceRequest = GetInterface(); // Get interface for source info
    // Ethernet
    memset(newPacket.ether.ether_dhost, 0xFF, ETH_ALEN);
    memcpy(&(newPacket.ether.ether_shost), interfaceRequest->ifr_hwaddr.sa_data, ETH_ALEN);
    newPacket.ether.ether_type = htons(ETHERTYPE_ARP);
    // ARP header fields
    newPacket.arp.ar_hrd = htons(ARPHRD_ETHER);
    newPacket.arp.ar_pro = htons(ETHERTYPE_IP);
    newPacket.arp.ar_hln = ETHER_ADDR_LEN;
    newPacket.arp.ar_pln = sizeof(newPacket.sender_ip);
    newPacket.arp.ar_op = htons(ARPOP_REQUEST);
    // Sender info
    memcpy(&newPacket.sender_mac, interfaceRequest->ifr_hwaddr.sa_data, ETH_ALEN); // MAC address of interface
    struct sockaddr_in *sin = (struct sockaddr_in *)&interfaceRequest->ifr_addr;
    newPacket.sender_ip = htonl(sin->sin_addr.s_addr); // IP address of interface
    // Destination info
    memset(newPacket.target_mac, 0, ETH_ALEN);                // Unknown MAC
    newPacket.target_ip = host->hostAddress->sin_addr.s_addr; // Know IP of destination
    // Fill padding with 0
    memset(newPacket.padding, 0, sizeof(newPacket.padding)); // Default padding

    // Send packet
    pthread_mutex_lock(&lock); // Lock to avoid identical file descriptors
    int fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (fd < 0)
    {
        perror("Error in init socket !");
        return;
    }
    pthread_mutex_unlock(&lock);
    struct sockaddr_ll device;
    device.sll_family = PF_PACKET;
    device.sll_protocol = htons(ETH_P_ARP);
    device.sll_ifindex = if_nametoindex("eth0");
    device.sll_hatype = ARPHRD_ETHER;
    device.sll_pkttype = PACKET_BROADCAST;
    device.sll_halen = 0;
    memcpy(device.sll_addr, newPacket.sender_mac, 6 * sizeof(uint8_t));
    // Send packets
    int result = sendto(fd, &newPacket, sizeof(newPacket), 0, (struct sockaddr *)&device, sizeof(device));
    if (result < 0)
    {
        fprintf(stdout, "Cannot send ARP packet !!!\n");
        // So don't receive packets
        close(fd);
        return;
    }
    // Receive packets
    // Timeout option
    struct timeval tv;
    tv.tv_sec = RECEIVE_TIMEOUT;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv);

    // Buffer to receive from kernel
    ssize_t messageSize;
    char *receiveBuffer = (char *)malloc(ICMP_PKT_RCV_SIZE);
    memset(receiveBuffer, 0, ICMP_PKT_RCV_SIZE);
    struct ether_arp *arp_frame;
    arp_frame = (struct ether_arp *)(receiveBuffer + 14); // Skip ethernet

    messageSize = recv(fd, receiveBuffer, ICMP_PKT_RCV_SIZE, 0);
    if (messageSize > 0)
    {
        // Host online
        if ((ntohs(arp_frame->arp_op) == ARPOP_REPLY))
        {
            char ipFrom[IPV4_ADDR_SIZE];
            snprintf(ipFrom, sizeof(ipFrom), "%d.%d.%d.%d", 
                    arp_frame->arp_spa[0], // First octet
                    arp_frame->arp_spa[1], // Second octet
                    arp_frame->arp_spa[2], // Third octet
                    arp_frame->arp_spa[3]);// Last octet
            char hostSended[IPV4_ADDR_SIZE];
            strcpy(hostSended, inet_ntoa(host->hostAddress->sin_addr));
            int compare = strcmp(ipFrom, hostSended);
            if (compare == 0) // Correct response from host we sended
            {
                // Lock to avoid race condition when write to file
                pthread_mutex_lock(&lock);
                ++numHostsFound;
                fprintf(stdout, "Host : %s is up, found by sending ARP request \n", ipFrom);
                WriteResultsToFile(ipFrom);
                pthread_mutex_unlock(&lock);
            }
        }
    }
    free(receiveBuffer);
    close(fd);
}