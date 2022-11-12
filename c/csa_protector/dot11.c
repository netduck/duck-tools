#ifndef dot11
#include "dot11.h"
#endif

void usage()
{
    printf("syntax: csa_protector <interface> <STAmac> <ch>\n");
    printf("sample: csa_protector wlan0 11:22:33:44:55:66 13\n");
}

bool parse(Param *param, int argc, char *argv[])
{
    if (argc != 2)
    {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

void PtData(const u_char *packet, int caplen)
{
    printf("CAPLEN : %d\n",caplen);
    for (int i = 0; i < caplen; i++)
    {
        if (i % 8 == 0 && i != 0 && i % 16 != 0)
        {
            printf("| ");
        }
        if (i % 16 == 0 && i != 0)
        {
            printf("\n");
        }
        *(packet + i) < 16 ? printf("0%x ", *(packet + i)) : printf("%x ", *(packet + i));
    }
    printf("\n");
}

void Mac_(const char *arr, u_char *mac_addr)
{
    int a;
    if (strlen(arr) != 17)
    {
        printf("Maclen error!!\n");
    }
    char cpyarr[18];
    memcpy(cpyarr, arr, 17);
    for (int i = 0; i < 6; i++) //입력Mac값의 콜론 제거
    {
        cpyarr[i * 3 + 2] = '\0';
        sscanf((const char *)&cpyarr[3 * i], "%x", &a);
        mac_addr[i] = (u_char)a;
    }
}

const u_char *JumpRadio(const u_char *packet)
{
    // u_char *packet_2=packet;
    if (packet == NULL)
    {
        printf("packet is NULL!!!\n");
        exit(1);
    }
    Radio *rad = (Radio *)packet;

    return packet + (rad->hdr_len);
}

void CapturePacket(pcap_t *pcap, const u_char **packet, struct pcap_pkthdr **header)
{

    int res = pcap_next_ex(pcap, header, packet);
    if (res == 0)
        return;
    if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
    {
        printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
        return;
    }
}

bool isBeacon(const u_char *packet)
{
    Radio *rad;
    rad = (Radio *)packet;
    // printf("rev : %d\npad : %d\n len:%d\n",rad->hdr_rev,rad->hdr_pad,rad->hdr_len);
    BeaconHd *bec;
    bec = (BeaconHd *)(packet + rad->hdr_len);
    if (htons(bec->type) == 0x8000)
    {
        return true;
    }
    else
    {
        return false;
    }
}