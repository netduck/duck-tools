#include <stdio.h>

#include "dot11.h"
#include "csa.h"
#include "channel_hopper.h"

int Wireless_Channel[58] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                            11, 12, 13, 14, 15, 16, 17, 18, 20, 24,
                            28, 32, 36, 40, 44, 48, 52, 56, 60, 64,
                            68, 72, 76, 80, 84, 88, 92, 96, 100, 104,
                            108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
                            149, 153, 157, 161, 165, 169, 173, 177};

Param param = {
    .dev_ = NULL};

int main(int argc, char *argv[])
{
    if (!parse(&param, argc, argv))
        return -1;

    unsigned char *Interface = argv[1];

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_live(Interface, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL)
    {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }
    int i = 0;
    while (1)
    {
        int ChangeCh = Wireless_Channel[i];
        if (i < 58)
        {
            i++;
        }
        else
        {
            i = 0;
        }
        const u_char *packet;
        struct pcap_pkthdr *header;
        int csaCh;
        channel_hopping(Interface, ChangeCh);
        CapturePacket(pcap, &packet, &header);
        // PtData(packet,header->caplen);
        if (isCSA(packet, header->caplen,csaCh))
        {
            // printf("Be CAP : %d\n",header->caplen);
            // PtData(packet,header->caplen); //FcS 캡쳐됨 4바이트 제거 바람
            sendCSA(pcap,packet,ChangeCh,Interface,csaCh,header->caplen);
            // exit(1);
        }
        else
        {
            // printf("Not CSA : %d\n",header->caplen);
        }
    }
    pcap_close(pcap);
    return 0;
}