// Define constants and enum used in this project
#ifndef constants
#define constants

// Define the Packet Constants 
// icmp max packet size to send in bytes
#define ICMP_PKT_SIZE 64
// icmp max packet size to receive in bytes
#define ICMP_PKT_RCV_SIZE 2048
  
// Time to wait for reply
#define RECEIVE_TIMEOUT 1  
  
// Type of address
#define NETWORK_ADDR 1
#define SUBNET_MASK 2
// Address size
#define IPV4_ADDR_SIZE 16

// Enum boolean implemented
typedef enum { False, True } boolean; 

// Max threads
#define MAX_THREAD_POOL_SIZE 32

#endif