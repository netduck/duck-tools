#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
typedef struct radiotap
{
    u_char hdr_rev;
    u_char hdr_pad;
    u_short hdr_len;
    u_char present_flag[12]; //이 길이 가변이라 보내는 놈의 안테나길이에 따라 가변임
    u_char flags;
} Radio;
typedef struct Dot11
{
    u_char Version : 2;
    u_char Type : 2;
    u_char Subtype : 4;
    u_char Flags;
    u_short Dur;
    u_char STAMac[6];
    u_char APMac[6];
    u_char BSSID[6];
    u_short FSnumber;
} Dot;
typedef struct tagged_parameters
{
    u_char tag_number;
    u_char tag_length;
} Tag;

void checkPacket(const char *Interface)
{

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
        checkCSA(packet, header->caplen);
        checkDeauth(packet);
    }
}

bool checkDeauth(const u_char *packet)
{
    Radio *rad;
    rad = (Radio *)packet;
    packet += rad->hdr_len; // radio tap jump

    Dot *dot;
    dot = (Dot *)packet;
    if (dot->Type == 0x0 && dot->Subtype == 0x1100)
    {
        return true;
    }
}
bool checkCSA(const u_char *packet, const u_int32_t packetlen)
{
    Radio *rad;
    rad = (Radio *)packet;
    u_int32_t taglen = packetlen - rad->hdr_len - 24 - 12;

    packet += rad->hdr_len;
    packet += 24 + 12;

    for (int i = 0; i < taglen;)
    {
        Tag *tag;
        tag = (Tag *)packet;
        if (tag->tag_number == 0x25)
        {
            return true;
        }
        i += tag->tag_length + 2;
    }
}
void mallocElement();
void updateList();

void usage()
{
    printf("syntax: duck_detector <interface>\n");
    printf("sample: duck_detector wlan0\n");
}

typedef struct
{
    char *dev_;
} Param;

Param param = {
    .dev_ = NULL};

typedef struct attackList
{
    u_char *mac;
    u_char *attackType;
    uint8_t pwr;
} attackList;

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

void showInit()
{
    system("clear");
    printf("              Mac    Atk  PWR\n\n");
}

void showList(int *listCnt, struct attackList *list)
{
    showInit();
    for (int i = 0; i < (*listCnt); i++)
    {
        printf("%s  %5s  -%d\n", (list + i)->mac, (list + i)->attackType, (list + i)->pwr);
    }
}

int main(int argc, char *argv[])
{
    if (!parse(&param, argc, argv))
        return -1;
    struct attackList atkList[5];
    int cnt = 2;
    atkList[0].mac = "aa:bb:cc:dd:ee:ff";
    atkList[0].attackType = "CSA";
    atkList[0].pwr = 10;
    atkList[1].mac = "11:22:33:44:55:66";
    atkList[1].attackType = "DAuth";
    atkList[1].pwr = 20;
    showList(&cnt, atkList);
}