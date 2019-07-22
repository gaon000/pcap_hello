#include<pcap.h>
#include<stdio.h>
#include<stdint.h>
#define ETH_ALEN        6

struct ether_header
{
  uint8_t  ether_dhost[ETH_ALEN];	/* destination eth addr	*/
  uint8_t  ether_shost[ETH_ALEN];	/* source ether addr	*/
  uint16_t ether_type;		        /* packet type ID field	*/
} __attribute__ ((__packed__));

void usage(){
    printf("syntax: pcap_text <interface\n");
    printf("sample: pcap_text wlan0\n");
}

int main(int argc, char* argv[]){
    if (argc != 2){
        usage();
        return -1;
    }
    
char * dev = argv[1];
char errbuf[PCAP_ERRBUF_SIZE];
pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
if (handle == NULL){
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
}

while(true){
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    const ether_header * eth = (ether_header*)packet;

    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("%u bytes captured\n", header -> caplen);
    printf("%02X:%02X:%02X:%02X:%02X:%02X\n",eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);


}
pcap_close(handle);
return 0;
}




