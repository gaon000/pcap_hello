#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include "protocol/all.h"
#include <stdlib.h>
#include <string.h>
const char *HTTP_METHOD_HTTP = "HTTP";
const char *HTTP_METHOD_GET = "GET";
const char *HTTP_METHOD_POST = "POST";
const char *HTTP_METHOD_PUT = "PUT";
const char *HTTP_METHOD_DELETE = "DELETE";
const char *HTTP_METHOD_CONNECT = "CONNECT";
const char *HTTP_METHOD_OPTIONS = "OPTIONS";
const char *HTTP_METHOD_TRACE = "TRACE";
const char *HTTP_METHOD_PATCH = "PATCH";
void *HTTP_METHOD[] = {(void *)HTTP_METHOD_HTTP, (void *)HTTP_METHOD_GET, (void *)HTTP_METHOD_OPTIONS, (void *)HTTP_METHOD_POST, (void *)HTTP_METHOD_TRACE, (void *)HTTP_METHOD_PATCH, (void *)HTTP_METHOD_PUT, (void *)HTTP_METHOD_DELETE, (void *)HTTP_METHOD_CONNECT};

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

bool checkHTTPMethod(const uint8_t *data, const char *httpMethod, uint32_t size)
{
    int httpMethodSize = strlen(httpMethod);
    if (size <= httpMethodSize)
    {
        return false;
    }
    return memcmp(data, httpMethod, httpMethodSize) == 0;
}

bool isHTTPProtocol(const uint8_t *p, uint32_t size)
{
    for (int i = 0; i < (sizeof(HTTP_METHOD) / sizeof(void *)); i++)
    {
        bool isFind = checkHTTPMethod(p, (const char *)HTTP_METHOD[i], size);
        if (isFind)
        {
            return isFind;
        }
    }
    return false;
}
void printTCPData(const unsigned char *p, uint32_t size)
{
    int len = 0;
    while (len < size)
    {
        printf("%c", *(p++));
    }
}
void printTCPPort(uint16_t port)
{
    printf("%d", port);
}

void printUDPPort(__be16 port)
{
    printf("%d", port);
}

void printMacAddress(mac_addr mac)
{
    printf("%02X:%02X:%02X:%02X:%02X:%02X\n", mac.oui[0], mac.oui[1], mac.oui[2], mac.oui[3], mac.oui[4], mac.oui[5]);
}

void printIPAddress(ip_addr ipAddr)
{
    printf("%d.%d.%d.%d", ipAddr.a, ipAddr.b, ipAddr.c, ipAddr.d);
}
