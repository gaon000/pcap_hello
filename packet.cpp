#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include "protocol/all.h"

void printPacket(const unsigned char *p, uint32_t size)
{
    int len = 0;
    while (len < size)
    {
        printf("%02X ", *(p++));
        if (!(++len % 16))
        {
            printf("\n");
        }
    }
    if (size % 16)
    {
        printf("\n");
    }
}
void printTCPPort(uint16_t port)
{
    printf("%d", port);
}

void printUDPPort(__be16 port){
    printf("%d", port);
}

void printMacAddress(mac_addr mac){
    printf("%02X:%02X:%02X:%02X:%02X:%02X\n", mac.oui[0], mac.oui[1], mac.oui[2],mac.oui[3],mac.oui[4],mac.oui[5]);
}

void printIPAddress(ip_addr ipAddr)
{
    printf("%d.%d.%d.%d", ipAddr.a, ipAddr.b, ipAddr.c, ipAddr.d);
}