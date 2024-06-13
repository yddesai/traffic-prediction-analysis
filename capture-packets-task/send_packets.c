#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <pcap.h>

#define MAX_PACKET_SIZE 65535

struct arp_entry {
    struct in_addr ip;
    unsigned char mac[ETH_ALEN];
};

int arp_ip_lookup(char* mac_addr, char* dest_ip) {
    char command[255];
    // sprintf char array mac addr  ( const char* mac_addr, char* dest_ip)
    // add : in mac addr
    strcat(mac_addr, ":");

    printf("arp -a | grep %s", mac_addr);
    sprintf(command, "arp -a | grep %s", mac_addr);
    FILE* arp = popen(command, "r");
    if (arp == NULL) {
        printf("Failed to run command\n");
        return -1;
    }

    char output[255];
    while (fgets(output, sizeof(output), arp) != NULL) {
        
        char* ipStart = strchr(output, '(');
        if (ipStart != NULL) {
            ipStart++; // Move past the '('
            char* ipEnd = strchr(ipStart, ')');
            // if (ipEnd != NULL) {
            //     *ipEnd = '\0'; // Null-terminate the IP address string
            //     printf("IP Address: %s\n", ipStart);
            //     break; // Exit the loop once the IP address is found
            // }
            //store ip in char array
            strcpy(dest_ip, ipStart);
        }
    }
    pclose(arp);
    return 0;
}



void send_packet(const unsigned char *dest_mac, const char *source_ip) {
    char errbuf[PCAP_ERRBUF_SIZE];
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    char packet[MAX_PACKET_SIZE];
    int packet_size;

    printf("--- Send Packet using libpcap ---\n");
    int dest_port, source_port;
    printf("Destination Port: ");
    scanf("%d", &dest_port);
    printf("Source Port: ");
    scanf("%d", &source_port);

    pcap_t *handle = pcap_open_live("wlp2s0", MAX_PACKET_SIZE, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        return;
    }

    // IP header
    ip_header = (struct iphdr *)packet;
    ip_header->ihl = 5;
    ip_header->version = 4;
    ip_header->tos = 0;
    ip_header->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    ip_header->id = htons(54321);
    ip_header->frag_off = 0;
    ip_header->ttl = 255;
    ip_header->protocol = IPPROTO_TCP;
    ip_header->check = 0;
    ip_header->saddr = inet_addr(source_ip);
    
    ip_header->daddr = inet_addr("destination_ip"); 

    // TCP header
    tcp_header = (struct tcphdr *)(packet + sizeof(struct iphdr));
    tcp_header->source = htons(source_port);
    tcp_header->dest = htons(dest_port);
    tcp_header->seq = 0;
    tcp_header->ack_seq = 0;
    tcp_header->doff = 5;
    tcp_header->syn = 1;
    tcp_header->window = htons(5840);
    tcp_header->check = 0;
    tcp_header->urg_ptr = 0;

    packet_size = sizeof(struct iphdr) + sizeof(struct tcphdr);

    
    struct ether_header *eth_header = (struct ether_header *)packet;
    memcpy(eth_header->ether_dhost, dest_mac, ETH_ALEN);

    if(pcap_sendpacket(handle, (const u_char *)packet, packet_size) != 0){
        fprintf(stderr, "pcap_sendpacket error: %s\n", pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }
    printf("Packet sent successfully\n");

    pcap_close(handle);
}

int main(int argc, char *argv[]){
    char dest_mac[ETH_ALEN];
    char dest_ip[INET_ADDRSTRLEN];

    printf("Destination MAC: ");
    int i;
    for (i = 0; i < ETH_ALEN; i++) {
        scanf("%2hhx", &dest_mac[i]);
        if (i < ETH_ALEN - 1)
            scanf(":");
    }

    // ARP Lookup 
    if (arp_ip_lookup(( char *)dest_mac, dest_ip) == 0) {
        
        for (i = 0; i < strlen(dest_ip); i++) {
            printf("%c", dest_ip[i]);
        }
        printf("\n");
        send_packet(dest_mac, dest_ip);
    } else {
        printf("ARP lookup failed\n");
    }

    return EXIT_SUCCESS;
}
