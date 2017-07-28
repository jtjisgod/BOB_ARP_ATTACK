#include <stdlib.h>
#include <stdio.h>
#include <pcap/pcap.h>

void main(int argc, char **argv)
{
    pcap_t *handle;					/* Session handle */
    char *dev;						/* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
    struct bpf_program fp;			/* The compiled filter */
    char filter_exp[] = "port 80";	/* The filter expression */
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
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) { fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle)); return(2); }
    if (pcap_setfilter(handle, &fp) == -1) { fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle)); return(2); }
  /*}*/


    /* Supposing to be on ethernet, set mac destination to 1:1:1:1:1:1 */
    packet[0]=1;
    packet[1]=1;
    packet[2]=1;
    packet[3]=1;
    packet[4]=1;
    packet[5]=1;

    /* set mac source to 2:2:2:2:2:2 */
    packet[6]=2;
    packet[7]=2;
    packet[8]=2;
    packet[9]=2;
    packet[10]=2;
    packet[11]=2;

    int i;

    /* Fill the rest of the packet */
    for(i=12;i<100;i++)
    {
        packet[i]=i%256;
    }

    pcap_sendpacket(handle, packet, sizeof(packet));

    return;
}
