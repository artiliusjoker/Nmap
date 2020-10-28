// Define constants and enum used in this project
#ifndef constants
#define constants

// Define the Packet Constants 
// ping packet size 
#define PING_PKT_S 64 
   
// Automatic port number 
#define PORT_NO 0  
  
// Automatic port number 
#define PING_SLEEP_RATE 1000000 x 
  
// Gives the timeout delay for receiving packets 
// in seconds 
#define RECV_TIMEOUT 1  
  
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