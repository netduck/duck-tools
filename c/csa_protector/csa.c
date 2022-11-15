#include "csa.h"
#include "dot11.h"
#include "channel_hopper.h"
#include <unistd.h>

#define CSA_TAG_NUM 0x25
#define FRAME_LEN 24
#define FIXED_PARA_LEN 12

bool isCSA(const u_char *packet, int caplen, int *csaCh)
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
                *csaCh = *(packet_ + i + 3);
                //printf("input csaCh : %d\n", *(packet_ + i + 3));
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
    //printf("CSA ch : %d\nChangeCh : %d\n", csaCh, ChangeCh);
    
    u_char *send_packet;
    send_packet = (u_char *)malloc(sizeof(u_char) * (caplen - 4));
    memcpy(send_packet, packet, caplen - 4);
    *(send_packet + 16) = 0x00; // fcs

    Radio *rad = (Radio *)packet;
    int taglen = caplen - rad->hdr_len - FRAME_LEN - FIXED_PARA_LEN - 4;
    send_packet += (rad->hdr_len + FRAME_LEN + FIXED_PARA_LEN);

    for (int i = 0; i < taglen;)
    {
        Tag *tag = (Tag *)(send_packet + i);
        // printf("[send_tag num : %d]\n",tag->tag_number);
        if (tag->tag_number == CSA_TAG_NUM)
        {
            *(send_packet + i + 3) = ChangeCh;
            //printf("send Ch : %d\n", *(send_packet + i + 3));
            break;
        }
        i += tag->tag_length + 2;
    }
    send_packet -= (rad->hdr_len + FRAME_LEN + FIXED_PARA_LEN);
    int packet_count = 0;

    for (int j = 1; j <= 30; j++)
    {
        channel_hopping(Interface, csaCh); // CSA가 날린 채널로 이동
        for (int i = 0; i < 4; i++)
        {
            printf("[%d] send packet ch[%d]-> ch[%d] !!! \n", ++packet_count,csaCh,ChangeCh);

            // PtData(send_packet,caplen-4);

            if (pcap_sendpacket(pcap, send_packet, caplen - 4) != 0)
            {
                fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(pcap));
                exit(1);
            }
        }
        channel_hopping(Interface, ChangeCh); // 원래 채널로 이동
        for (int i = 0; i < 4; i++)
        {
            printf("[%d] send packet ch[%d] -> ch[%d] !!! \n", ++packet_count,ChangeCh,ChangeCh);

            // PtData(send_packet,caplen-4);

            if (pcap_sendpacket(pcap, send_packet, caplen - 4) != 0)
            {
                fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(pcap));
                exit(1);
            }
        }
    }
}