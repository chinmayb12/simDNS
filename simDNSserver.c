#include<stdio.h>
#include<stdint.h>
#include<stdlib.h>
#include<arpa/inet.h>
#include<sys/socket.h>
#include<unistd.h>
#include<netinet/in.h>
#include<netinet/if_ether.h>
#include<string.h>
#include<sys/select.h>
#include<net/ethernet.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <netinet/ip.h>
#include <netdb.h>
#include <time.h>

#define INTERFACE "wlp3s0"
// #define INTERFACE "enp2s0"
#define p 0.3

typedef struct query{
    uint16_t ID;
    uint8_t MessageType;
    uint8_t NumQueries;
    struct{
        uint32_t DomainSize;
        char DomainName[32];
    } QueryStrings[8];
    
} simDNSquery;


typedef struct queryresponse{
    uint16_t ID;
    uint8_t MessageType;
    uint8_t NumResponses;
    struct{
        uint8_t found;
        uint32_t IP;
    } QueryStrings[8];
} simDNSresponse;


int dropmessage(float prob){
    // Always different random number
    srand(time(0));
    float r = (float)rand()/(float)(RAND_MAX);
    // printf("Random number: %f\n", r);
    if(r < prob){
        printf("message dropped\n");
        return 1;
    }
    return 0;
}

int verifychecksum(struct iphdr* ip_header, int len){
    unsigned short* buffer = (unsigned short*)ip_header;
    int sum = 0;
    for(int i = 0; i < len/2; i++){
        sum += buffer[i];
    }
    while(sum >> 16){
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return sum == 0xFFFF;
}


void computechecksum(struct iphdr* ip_header, int len){
    unsigned short* buffer = (unsigned short*)ip_header;
    int sum = 0;
    for(int i = 0; i < len/2; i++){
        sum += buffer[i];
    }
    while(sum >> 16){
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum = ~sum;
    ip_header->check = (unsigned short)sum;
}

int main(){
    int sockfd;
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(sockfd < 0){
        perror("Socket creation failed");
        exit(1);
    }

    struct sockaddr_ll serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sll_family = AF_PACKET;
    serv_addr.sll_protocol = htons(ETH_P_ALL);
    serv_addr.sll_ifindex = if_nametoindex(INTERFACE);


    if(bind(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0){
        perror("Socket bind failed");
        exit(1);
    }

    struct sockaddr saddr;
    int saddr_len = sizeof(saddr);
    unsigned char packet[65535];

    while(1){
        int length = recvfrom(sockfd, packet,65535, 0, (struct sockaddr*)&saddr, &saddr_len);
        if(length < 0){
            perror("Packet receive failed");
            exit(1);
        }

        struct ethhdr* eth = (struct ethhdr*)packet;
        struct iphdr* ip = (struct iphdr*)(packet + sizeof(struct ethhdr));

        if(ntohs(eth->h_proto) == ETH_P_IP){

            if(ip->protocol == 254){
                
                int drop = dropmessage(p);
                if(drop){
                    continue;
                }
                simDNSquery* query = (simDNSquery*)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));

                int flag = verifychecksum(ip,sizeof(struct iphdr));

                if(flag == 0){
                    printf("Checksum verification failed\n");
                    continue;
                }

                // printf("Received a DNS query\n");
                // printf("ID: %d\n", ntohs(query->ID));
                // printf("MessageType: %d\n", query->MessageType);
                // printf("NumQueries: %d\n", query->NumQueries);
                // for(int i = 0; i < query->NumQueries; i++){
                //     printf("DomainSize: %d\n", ntohl(query->QueryStrings[i].DomainSize));
                //     printf("DomainName: %s\n", query->QueryStrings[i].DomainName);
                // }
                unsigned char packet[1500];

                // Source IP address
                struct sockaddr_in source;
                source.sin_addr.s_addr = ip->saddr;

                // Destination IP address
                struct sockaddr_in dest;
                dest.sin_addr.s_addr = ip->daddr;

                // Ethernet header source and destination MAC address
                struct ethhdr* eth_header = (struct ethhdr*)packet;
                memcpy(eth_header->h_source, eth->h_dest, 6);
                memcpy(eth_header->h_dest, eth->h_source, 6);

                // IP header
                struct iphdr* ip_header = (struct iphdr*)(packet + sizeof(struct ethhdr));
                ip_header->ihl = 5;
                ip_header->version = 4;
                ip_header->tos = 0;
                ip_header->tot_len = sizeof(struct iphdr) + sizeof(simDNSresponse);
                ip_header->id = 123;
                ip_header->frag_off = 0;
                ip_header->ttl = 255;
                ip_header->protocol = 254;
                ip_header->saddr = ip->daddr;
                ip_header->daddr = ip->saddr;

                computechecksum(ip_header, sizeof(struct iphdr));

                // simDNS response



                simDNSresponse* response = (simDNSresponse*)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));

                response->ID = query->ID;
                response->MessageType = 1;
                response->NumResponses = query->NumQueries;

                // Extract the domain names from the query
                for(int i = 0; i < query->NumQueries; i++){
                    char domain[32];
                    for(int j = 0; j < ntohl(query->QueryStrings[i].DomainSize); j++){
                        domain[j] = query->QueryStrings[i].DomainName[j];
                    }
                    domain[ntohl(query->QueryStrings[i].DomainSize)] = '\0';

                    // Get the IP address of the domain
                    struct hostent* host = gethostbyname(domain);
                    if(host == NULL){
                        response->QueryStrings[i].found = 0;
                        continue;
                    }

                    struct in_addr** addr_list = (struct in_addr**)host->h_addr_list;
                    response->QueryStrings[i].found = 1;
                    response->QueryStrings[i].IP  = addr_list[0]->s_addr;

                    // printf("Domain: %s\n", domain);
                    // printf("IP: %s\n", inet_ntoa(*addr_list[0]));
                }

                // printf("Sending response\n");
                int ret = sendto(sockfd, packet, sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(simDNSresponse), 0, &saddr, saddr_len);
                if(ret < 0){
                    perror("Packet send failed");
                    exit(1);
                }

            }
        }


    }
    return 0;
}