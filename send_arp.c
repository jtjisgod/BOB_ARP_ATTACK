#include <stdlib.h>
#include <stdio.h>
#include <pcap/pcap.h>

typedef struct etherhdr{
  char dstMac[6];
  char srcMac[6];
  char etherType[2];
} ETHERHDR;

typedef struct arphdr{
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

    dev = pcap_lookupdev(errbuf);

  /* Error 제어 { */
    if (dev == NULL) { fprintf(stderr, "Couldn't find default device: %s\n", errbuf); return(2); }
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) { fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf); net = 0; mask = 0; }
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) { fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf); return(2); }
  /*}*/

    ARPHDR sendHdr;

    // u_char dstMac[7] = "\x00\x50\x56\xc0\x00\x08";
    u_char dstMac[7] = "\xe4\x42\xa6\xa1\xa7\x98";
    u_char srcMac[7] = "\x00\x0c\x29\x15\xef\x90";

    memcpy(sendHdr.eh.dstMac, dstMac, 6);
    memcpy(sendHdr.eh.srcMac, srcMac, 6);
    memcpy(sendHdr.eh.etherType, "\x08\x06", 2); // ARP


    memcpy(sendHdr.ht, "\x00\x01", 2);
    memcpy(sendHdr.pt, "\x08\x00", 2);
    memcpy(sendHdr.hal, "\x06", 1);
    memcpy(sendHdr.pal, "\x04", 1);
    memcpy(sendHdr.op, "\x00\x02", 2);

    memcpy(sendHdr.sha, dstMac, 6);
    memcpy(sendHdr.spa, "\xc0\xa8\xee\x82", 4); //C0A8EE82
    memcpy(sendHdr.dha, srcMac, 6);
    memcpy(sendHdr.dpa, "\xc0\xa8\xee\x82", 4);


    int i;

    memset(packet, 0x00, 100);
    memcpy(packet, (void *)&sendHdr, sizeof(sendHdr));

    pcap_sendpacket(handle, packet, 60);

    return;
}
