#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include "protocol/all.h"
#include "packet.h"






void usage()
{
    printf("syntax: pcap_text <interface\n");
    printf("sample: pcap_text wlan0\n");
}

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        usage();
        return -1;
    }

    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    while (true)
    {
        struct pcap_pkthdr *header;
        const u_char *packet;
        int res = pcap_next_ex(handle, &header, &packet);
        const ether_header *eth = (ether_header *)packet;
        int packetIndex = sizeof(ether_header);
        
        if (res == 0)
            continue;
        if (res == -1 || res == -2)
            break;

        printf("%u bytes captured\n", header->caplen);
        printf("%02X:%02X:%02X:%02X:%02X:%02X\n", eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
        printf("%02X:%02X:%02X:%02X:%02X:%02X\n", eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

        if (ntohs(eth->ether_type) == ETHERTYPE_ARP)
        {
            
            const arp_header* arp = (arp_header*)(packet + packetIndex);
            printf("sender_mac_address:  ");
            printMacAddress(arp->sender_mac);
            printf("target_mac_address:  ");
            printMacAddress(arp->target_mac);
            printf("sender_ip:  \n");
            printIPAddress(arp->sender_ip);
            printf("target_ip:  ");
            printIPAddress(arp->target_ip);
            
            printf("ARP\n");

            
        }
        else if (ntohs(eth->ether_type) == ETHERTYPE_IP)
        {
            const ip_header *iph = (ip_header *)(packet + packetIndex);
            packetIndex += sizeof(ip_header);
            printf("IPv4\n");
            printf("ip src:  ");
            printIPAddress(iph->ip_src);
            printf("\n");
            printf("ip dest:  ");
            printIPAddress(iph->ip_dst);
            printf("\n");

            if (iph->ip_p == IPPROTO_TCP)
            {
                const tcp_header *tcp = (tcp_header *)(packet + packetIndex);
                packetIndex += sizeof(tcp_header);
                printf("TCP SRC PORT: ");
                printTCPPort(ntohs(tcp->th_sport));
                printf("\n");
                printf("TCP DEST PORT:  ");
                printTCPPort(ntohs(tcp->th_dport));
                printf("\n");
                uint32_t tcp_size = (ntohs(iph->ip_len)) - ((iph->ip_hl + tcp->th_off) * 4);
                if (tcp_size > 0)
                {
                    printf("=============\n");
                    printPacket(packet + packetIndex, tcp_size);
                    printf("=============\n");
                }
            }
            else if(iph->ip_p == IPPROTO_UDP){
                const udphdr *udp = (udphdr *)(packet+packetIndex);
                packetIndex += sizeof(udphdr);
                printf("UDP SRC PORT: ");
                printUDPPort(ntohs(udp->source));
                printf("\n");
                printf("UDP DEST PORT: ");
                printUDPPort(ntohs(udp->dest));
                printf("\n");
                uint32_t udp_size = (ntohs(iph->ip_len))-(ntohs(udp->len));
                if(udp_size > 0){
                    printf("==============\n");
                    printPacket(packet + packetIndex, udp_size);
                    printf("==============\n");
                }
                
            }
        }
        else if (ntohs(eth->ether_type) == ETHERTYPE_AARP)
        {
            printf("type: arp\n");
        }
    }
    pcap_close(handle);
    return 0;
}

void packetParse(ether_header *eth, const u_char *packet, int *packetIndex)
{
    eth = (ether_header *)packet;
    *packetIndex = *packetIndex + sizeof(ether_header);
}
