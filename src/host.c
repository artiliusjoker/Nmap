#include "../include/nmap.h"

// void Ping(struct host){

// }
void AddHost(__host__ ** head, __host__ * newHost){
    __host__ *tempHost;

	if (!*head)
	{
		*head = newHost;
	}
	else
	{
		tempHost = *head;
		while (tempHost->next)
			tempHost = tempHost->next;
		tempHost->next = newHost;
    }
}

__host__ *NewHost(char * ipAddress){
    __host__ * newHost;
    struct sockaddr_in * tempSockAddr = NULL;

    newHost = (__host__ *) malloc(sizeof(__host__));
    if(!newHost)
    {
        perror("Unable to malloc new host");
        return NULL;
    }
    tempSockAddr = DnsLookUp(ipAddress, NULL);
    if(tempSockAddr == NULL){
        perror("Unable to malloc new host (creating sockaddr_in)");
        return NULL;
    }
    newHost->hostAddress = tempSockAddr;
    newHost->next = NULL;
    return newHost;
}

void FreeHost(__host__ * host){
    if (!host)
		return ;
	if (host->hostAddress != NULL)
	{
		free(host->hostAddress);
		host->hostAddress = NULL;
	}
	free(host);
	host = NULL;
}

void FreeListHosts(__host__ * head){
    __host__	*tempHost;
	__host__	*next;

	if (!head)
		return;

	tempHost = head;
	while (tempHost->next)
	{
		next = tempHost->next;
		FreeHost(tempHost);
		tempHost = next;
	}
	if (tempHost)
	{
		FreeHost(tempHost);
		tempHost = NULL;
	}
}

char * ReceiveReply(){

}