#include "../include/nmap.h"

__host__ * head = NULL;

int main(int argc, char *argv[])
{
    if(argc != 2){
        fprintf(stderr,"Enter 2 arguments only. \"StudentID Network/inputSubnetMask\"\n");
        exit(0);
    }
    char *inputAddress = GetInfoFromStr(argv[1], NETWORK_ADDR);
    char *inputSubnetMask = GetInfoFromStr(argv[1], SUBNET_MASK);
    char *resolved;
    struct sockaddr_in *sockAddr_in; 

    sockAddr_in = DnsLookUp(inputAddress, &resolved);

    uint32_t networkLong = htonl(sockAddr_in->sin_addr.s_addr);
    uint32_t netmaskLong = SubnetMaskToUint32_t(inputSubnetMask);
    // Create list of hosts in a network to scan
    GetAdressPool(networkLong, netmaskLong);



    // End program
    //FreeListHosts(head);
    FreeString(inputAddress);
    FreeString(inputSubnetMask);
    free(sockAddr_in);
    return 1;
}