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
#include <netinet/ip_icmp.h>

#define INTERFACE "wlp3s0"
// #define INTERFACE "enp2s0"

#define TIMEOUT 20




typedef struct query{
    uint16_t ID;
    uint8_t MessageType;
    uint8_t NumQueries;
    struct{
        uint32_t DomainSize;
        char DomainName[32];
    } QueryStrings[8];
    
} simDNSquery;


typedef struct query_st{
    int occupied;
    int num_sent;
    simDNSquery query;
} query_st;


query_st IDTable[INT16_MAX];

typedef struct queryresponse{
    uint16_t ID;
    uint8_t MessageType;
    uint8_t NumResponses;
    struct{
        uint8_t found;
        uint32_t IP;
    } QueryStrings[8];
} simDNSresponse;



int checkquery(char* user_input){

    char user_input2[1024];
    strcpy(user_input2, user_input);
    char *token = strtok(user_input2, " ");
    token = strtok(NULL, " ");
    int N = strtol(token, NULL, 10);
    int i = 8;
    int j = 0;

    while(i < strlen(user_input)){
        char domain[32];
        int k = 0;
        while(user_input[i] != ' ' && i < strlen(user_input)){
            domain[k] = user_input[i];
            k++;
            i++;
        }
        domain[k] = '\0';
        i++;
        j++;
        if(k < 3 || k > 31){
            printf("ERR: Domain name should be between 3 and 31 characters\n");
            return 0;
        }
        if(domain[0] == '-' || domain[k-1] == '-'){
            printf("ERR: Domain name cannot start or end with a hyphen\n");
            return 0;
        }

        for(int l = 0; l < k-1; l++){
            if(domain[l] == '-' && domain[l+1] == '-'){
                printf("ERR: Domain name cannot have two consecutive hyphens\n");
                return 0;
            }
        }


        for(int l = 0; l < k; l++){
            if((domain[l] < 'a' || domain[l] > 'z') && (domain[l] < 'A' || domain[l] > 'Z') && (domain[l] < '0' || domain[l] > '9') && domain[l] != '.' && domain[l] != '-'){
                printf("ERR: Domain name can only contain alphanumeric characters and hyphens\n");
                return 0;
            }
        }
    }

}


void constructSIMDNSquery(char* user_input, simDNSquery* query){

    char user_input2[1024];
    strcpy(user_input2, user_input);
    char *token = strtok(user_input2, " ");
    token = strtok(NULL, " ");
    int N = strtol(token, NULL, 10);
    int i = 8;
    int j = 0;

    // Generate ID for the query not in the table
    uint16_t ID = rand() % INT16_MAX;

    while(IDTable[ID].occupied == 1){
        ID = rand() % INT16_MAX;
    }

    IDTable[ID].occupied = 1;
    IDTable[ID].num_sent = 1;

    query->ID = htons(ID);
    query->MessageType = 0;
    query->NumQueries = N;


    IDTable[ID].query.ID = ID;
    IDTable[ID].query.MessageType = 0;
    IDTable[ID].query.NumQueries = N;

    // printf("ID: %d\n", ID);
    // printf("NumQueries: %d\n", query->NumQueries);
    // printf("MessageType: %d\n", query->MessageType);

    while(i < strlen(user_input)){
        char domain[32];
        int k = 0;
        while(i < strlen(user_input) && user_input[i] != ' '){
            domain[k] = user_input[i];
            k++;
            i++;
        }
        i++;
        query->QueryStrings[j].DomainSize = htonl(k);
        IDTable[ID].query.QueryStrings[j].DomainSize = k;
        // printf("DomainSize: %d\n", k);
        // printf("DomainName: ");
        for(int l = 0; l < k; l++){
            query->QueryStrings[j].DomainName[l] = domain[l];
            IDTable[ID].query.QueryStrings[j].DomainName[l] = domain[l];
            // printf("%c", domain[l]);
        }
        j++;
        // printf("\n");
    }

}

void constructSIMDNSquery2(simDNSquery query, simDNSquery* query2){

    query2->ID = ntohs(query.ID);
    query2->MessageType = 0;
    query2->NumQueries = query.NumQueries;

    for(int i = 0; i < query.NumQueries; i++){
        query2->QueryStrings[i].DomainSize = ntohl(query.QueryStrings[i].DomainSize);
        for(int j = 0; j < query.QueryStrings[i].DomainSize; j++){
            query2->QueryStrings[i].DomainName[j] = query.QueryStrings[i].DomainName[j];
        }
    }

}


void computechecksum(struct iphdr* ip_header, int len){

    const uint16_t *addr = (const uint16_t *)ip_header;
    uint32_t sum = 0;

    // Sum up 16-bit words
    while (len > 1) {
        sum += *addr++;
        len -= 2;
    }

    // If len is odd, add the remaining byte
    if (len == 1) {
        sum += *((uint8_t *)addr);
    }

    // Fold 32-bit sum to 16 bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    sum = ~sum;
    ip_header->check = (uint16_t)sum;
}

int main(){

    memset(IDTable, 0, sizeof(IDTable));

    int sockfd;
    unsigned char packet[65535];

    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(sockfd < 0){
        perror("Socket creation failed");
        exit(1);
    }

    struct ethhdr* eth_header = (struct ethhdr*)packet;
    struct iphdr* ip_header = (struct iphdr*)(packet + sizeof(struct ethhdr));

    struct sockaddr_ll saddr;
    saddr.sll_family = AF_PACKET;
    saddr.sll_protocol = htons(ETH_P_ALL);
    saddr.sll_ifindex = if_nametoindex(INTERFACE);
    saddr.sll_halen = 6;

    int saddr_len = sizeof(saddr);


    // Source MAC address
    struct ifreq ifr;

    strcpy(ifr.ifr_name, INTERFACE);
    if(ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0){
        perror("ioctl failed");
        exit(1);
    }

    unsigned char dest_mac[6];
    char dest_mac_str[18];
    printf("Enter destination MAC address: \n");
    fgets(dest_mac_str, 18, stdin);
    dest_mac_str[strcspn(dest_mac_str, "\n")] = '\0';

    // strcpy(dest_mac_str, "00:0c:29:4f:8e:5f");

    for(int i = 0; i < 6; i++){
        dest_mac[i] = strtol(dest_mac_str + i*3, NULL, 16);
    }
    
    memcpy(eth_header->h_source, ifr.ifr_hwaddr.sa_data, 6);
    memcpy(eth_header->h_dest, dest_mac, 6);

    memcpy(saddr.sll_addr, dest_mac, 6);


    eth_header->h_proto = htons(ETH_P_IP);


    // IP header
    ip_header->ihl = 5;
    ip_header->version = 4;
    ip_header->tos = 0;
    ip_header->tot_len = htons(sizeof(struct iphdr) + sizeof(simDNSquery));
    // printf("Total length: %d\n", ip_header->tot_len);
    ip_header->id = 123;
    ip_header->frag_off = 0;
    ip_header->ttl = 64;
    ip_header->protocol = 254;
    ip_header->saddr = inet_addr("10.145.80.27");
    ip_header->daddr = inet_addr("10.145.80.27");

    computechecksum(ip_header, sizeof(struct iphdr));



    fd_set readfds;

    struct timeval timeout;
    timeout.tv_sec = TIMEOUT;
    char user_input[1024];
    memset(user_input, '\0', sizeof(user_input));


    memset(IDTable, 0, sizeof(IDTable));

    int f = 1;
    int first = 1;
    while(1){

        if(f==1){
            printf("\n");
            printf("Enter query string: \n");
            f = 0;
        }

        FD_ZERO(&readfds);
        FD_SET(sockfd, &readfds);
        FD_SET(STDIN_FILENO, &readfds);
        int maxfd = STDIN_FILENO;
        if(STDIN_FILENO < sockfd){
            maxfd = sockfd;
        }

        int ret = select(maxfd+1, &readfds, NULL, NULL, &timeout);

        if(ret < 0){
            perror("Select failed");
            exit(1);
        }

        if(ret == 0){
            timeout.tv_sec = TIMEOUT;

            for(int i = 0; i < INT16_MAX; i++){
                if(IDTable[i].occupied == 1){
                    if(IDTable[i].num_sent < 3){
                        simDNSquery* query = (simDNSquery *)malloc(sizeof(simDNSquery));

                        // Create a DNS query message
                        constructSIMDNSquery2(IDTable[i].query, query);

                        memcpy(packet + sizeof(struct ethhdr) + sizeof(struct iphdr), query, sizeof(simDNSquery));
                        int ret = sendto(sockfd, packet,sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(simDNSquery), 0, (struct sockaddr*)&saddr, saddr_len);
                        if(ret < 0){
                            perror("Sendto failed");
                            exit(1);
                        }
                        IDTable[i].num_sent++;
                    }
                    else{
                        printf("\n");
                        printf("Query ID: %d\n", i);
                        printf("Failed to get a response after 3 attempts\n");
                        IDTable[i].occupied = 0;
                        IDTable[i].num_sent = 0;
                        f = 1;
                    }
                }
            }
        }

        if(FD_ISSET(sockfd, &readfds)){

            unsigned char packet_recv[65535];
            int len = recvfrom(sockfd, packet_recv, 1500, 0, (struct sockaddr*)&saddr, &saddr_len);
            if(len < 0){
                perror("Receive failed");
                exit(1);
            }

            struct ethhdr* eth = (struct ethhdr*)packet_recv;
            struct iphdr* ip = (struct iphdr*)(packet_recv + sizeof(struct ethhdr));

            // // Check if it is ICMP packet
            // if(ip->protocol == 1){
            //     struct icmphdr* icmp = (struct icmphdr*)(packet_recv + sizeof(struct ethhdr) + sizeof(struct iphdr));
            //     printf("Received an ICMP packet\n");
            //     printf("Type: %d\n", icmp->type);
            //     printf("Code: %d\n", icmp->code);
            // }

            // printf(" Bool %d\n", ip->protocol == 254 && strcmp(inet_ntoa(*(struct in_addr*)&ip->saddr),"10.145.27.193") == 0);
            if(ip->protocol == 254 && strcmp(inet_ntoa(*(struct in_addr*)&ip->saddr),"10.145.80.27") == 0){    
                // printf("Received a DNS response\n");
                simDNSresponse* response = (simDNSresponse*)(packet_recv + sizeof(struct ethhdr) + sizeof(struct iphdr));

                if(response->MessageType == 1){
                    int ID = ntohs(response->ID);


                    if(IDTable[ID].occupied == 1){
                        printf("\n");
                        printf("Query ID: %d\n", ID);
                        printf("Total query strings: %d\n", response->NumResponses);
                        for(int i = 0; i < response->NumResponses; i++){
                            for(int j = 0; j < IDTable[ID].query.QueryStrings[i].DomainSize; j++){
                                printf("%c", IDTable[ID].query.QueryStrings[i].DomainName[j]);
                            }
                            printf(" - ");
                            if(response->QueryStrings[i].found == 1){
                                printf("%s\n", inet_ntoa(*(struct in_addr*)&response->QueryStrings[i].IP));

                            }
                            else{
                                printf("NOT FOUND\n");
                            }

                        }

                        IDTable[ID].occupied = 0;
                        IDTable[ID].num_sent = 0;
                        f = 1;
                        memset(user_input, '\0', sizeof(user_input));

                    }
                }
            }

        }

        if(FD_ISSET(STDIN_FILENO, &readfds)){

            if(first == 1){
                fgets(user_input, 1000, stdin);
                first = 0;
            }
            fgets(user_input, 1000, stdin);
            user_input[strcspn(user_input, "\n")] = '\0';

            // Check if it is EXIT command
            if(strcmp(user_input, "EXIT") == 0){
                printf("Exiting...\n");
                break;
            }

            char user_input2[1024];
            memset(user_input2, '\0', sizeof(user_input2));
            // printf("User input: %s\n", user_input);
            strcpy(user_input2, user_input);
            char *token = strtok(user_input2, " ");
            token = strtok(NULL, " ");
            int N = strtol(token, NULL, 10);
            // printf("N: %d\n", N);
            if(N > 8){
                printf("ERR: N should be less than or equal to 8\n");
                memset(user_input, '\0', sizeof(user_input));
                f = 1;
                continue;
            }


            int fl = checkquery(user_input);
            if(fl == 0){            
                memset(user_input, '\0', sizeof(user_input));
                f = 1;
                continue;
            }

            simDNSquery* query = (simDNSquery *)malloc(sizeof(simDNSquery));

            // Create a DNS query message
            constructSIMDNSquery(user_input, query);

            // Send the query message
            memcpy(packet + sizeof(struct ethhdr) + sizeof(struct iphdr), query, sizeof(simDNSquery));
            // memcpy(packet + sizeof(struct iphdr), query, sizeof(simDNSquery));

            // printf("Total length: %ld\n",sizeof(struct iphdr) + sizeof(simDNSquery));
            // printf("Total length: %ld\n", sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(simDNSquery));
            int ret = sendto(sockfd, packet, sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(simDNSquery), 0, (struct sockaddr*)&saddr, saddr_len);
            // int ret = sendto(sockfd, packet, sizeof(struct iphdr) + sizeof(simDNSquery), 0, (struct sockaddr*)&saddr, saddr_len);
            // printf("Ret %d\n", ret);

            if(ret < 0){
                perror("Sendto failed");
                exit(1);
            }
            
            memset(user_input, '\0', sizeof(user_input));
            f = 1;
        }

    }
}