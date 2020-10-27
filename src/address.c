#include "../include/nmap.h"

uint32_t SubnetMaskToUint32_t(char * subnetMask){
    uint32_t result = 0;
    int sm = atoi(subnetMask);

    for (int i = 31; i > (31 - sm); --i)
    {
        result |= 1UL << i;
    }
    return result;
}

// Tham khao
// https://stackoverflow.com/questions/41316678/finding-host-address-range-in-c
char **GetAdressPool(uint32_t ipAddress, uint32_t subnetMask)
{
    // Get number of 1 bits base on Subnet mask
    int numbits = 0;
    uint32_t temp = subnetMask;
    for (; temp != 0; temp >>= 1)
    {
        if (temp & 0x01)
        {
            numbits++;
        }
    }

    // Start host and end host
    // Exclude broadcast and gateway host ?
    unsigned long hoststart;
    unsigned long hostend;
    hoststart = 1;
    hostend = (1 << (32 - numbits)) - 1;

    // Use AND bitwise operator to get the real network address (in case wrong input)
    uint32_t network = ipAddress & subnetMask;

    // Calculate all host addresses in the range
    for (unsigned i = hoststart; i <= hostend; i++)
    {
        uint32_t hostIp;
        int octet1, octet2, octet3, octet4;
        char newHost[IPV4_ADDR_SIZE];

        hostIp = network + i;
        octet1 = (hostIp & 0xff000000) >> 24;
        octet2 = (hostIp & 0x00ff0000) >> 16;
        octet3 = (hostIp & 0x0000ff00) >> 8;
        octet4 = (hostIp & 0x000000ff);
        snprintf(newHost, sizeof(newHost), "%d.%d.%d.%d", octet1, octet2, octet3, octet4);
        printf("%s\n", newHost);
    }
    return NULL;
}