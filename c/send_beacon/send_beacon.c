#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#pragma pack(1)
#define MAC_ADDR_LEN    6
#define SSID_LEN        12
#define SSID_TAG_NUM    0

struct RadioTap
{
        uint8_t     version;
        uint8_t     pad;
        uint16_t    len;
        uint32_t    present;
};

struct Dot
{
        uint16_t    type;
        uint16_t    duration;
        u_char      dest[MAC_ADDR_LEN];
        u_char      src[MAC_ADDR_LEN];
        u_char      bssid[MAC_ADDR_LEN];
        uint16_t    fsNum;
};

struct DotManagement
{
        uint64_t    timestamp;
        uint16_t    interval;
        uint16_t    cap;
};

struct SSIDTag
{
        u_char     tag_number;
        u_char     ssid_len;
        u_char     ssid_name[SSID_LEN];
};

struct RateTag
{
        u_char      tag_number;
        u_char      tag_len;
        u_char      rate1;
        u_char      rate2;
        u_char      rate3;
        u_char      rate4;
        u_char      rate5;
        u_char      rate6;
        u_char      rate7;
        u_char      rate8;
};

struct DsTag
{
        u_char      tag_number;
        u_char      tag_len;
        u_char      channel;
};

struct TrafficTag
{
        u_char      tag_number;
        u_char      tag_len;
        u_char      DTIMc;
        u_char      DTIMperiod;
        u_char      Bitmap;
        u_char      virtualBitmap;
};

struct CountryTag
{
        u_char      tag_number;
        u_char      tag_len;
        u_char      code1;
        u_char      code2;
        u_char      env;
        u_char      info1;
        u_char      info2;
        u_char      info3;
};

struct TPCtag
{
        u_char      tag_number;
        u_char      tag_len;
        u_char      power;
        u_char      link;
};

struct ERPtag
{
        u_char      tag_number;
        u_char      tag_len;
        u_char      info;
};

struct extRateTag
{
        u_char      tag_number;
        u_char      tag_len;
        u_char      rate1;
        u_char      rate2;
        u_char      rate3;
        u_char      rate4;
};

struct RSNTag
{
        u_char      tag_number;
        u_char      tag_len;
        uint16_t    version;
        uint32_t    groupSuite;
        uint16_t    pairwiseCount;
        uint32_t    pairwiseSuite;
        uint16_t    authCount;
        uint32_t    authSuite;
        uint16_t    capable;
};

struct QBSStag
{
        u_char      tag_number;
        u_char      tag_len;
        uint16_t    station;
        u_char      channel;
        uint16_t    capacity;
};

struct RMtag
{
        u_char      tag_number;
        u_char      tag_len;
        u_char      rm1;
        u_char      rm2;
        u_char      rm3;
        u_char      rm4;
        u_char      rm5;
};

struct HTtag
{
        u_char      tag_number;
        u_char      tag_len;
        uint16_t    info;
        u_char      MPDU;
        uint64_t    Rx1;
        uint64_t    Rx2;
        uint16_t    HT;
        uint32_t    TxBF;
        u_char      ASEL;
};

struct HTinfoTag
{
        u_char      tag_number;
        u_char      tag_len;
        u_char      channel;
        u_char      HT1;
        uint16_t    HT2;
        uint16_t    HT3;
        uint64_t      Rx1;
        uint64_t      Rx2;
};

struct BSStag
{
        u_char      tag_number;
        u_char      tag_len;
        uint16_t    passiveDwell;
        uint16_t    activeDwell;
        uint16_t    interval;
        uint16_t    passiveChannel;
        uint16_t    activeChannel;
        uint16_t    delay;
        uint16_t    thresholds;
};

struct extCapaTag
{
        u_char      tag_number;
        u_char      tag_len;
        u_char      capa1;
        u_char      capa2;
        u_char      capa3;
        u_char      capa4;
        u_char      capa5;
        u_char      capa6;
        u_char      capa7;
        uint16_t    capa8;
        u_char      capa9;
};

struct VHTcapaTag
{
        u_char      tag_number;
        u_char      tag_len;
        uint32_t    info;
        uint64_t    set;
};

struct VHTopTag
{
        u_char      tag_number;
        u_char      tag_len;
        u_char      info1;
        u_char      info2;
        u_char      info3;
        uint16_t    map;
};

struct HEcapaTag
{
        u_char      tag_number;
        u_char      tag_len;
        u_char      ext_tag_number;
        u_char      MACinfo[6];
        u_char      PHYinfo[11];
        u_char      set[4];
        u_char      thresholds[4];
};

struct HEopTag
{
        u_char      tag_number;
        u_char      tag_len;
        u_char      ext_tag_number;
        u_char      operation[3];
        u_char      info;
        u_char      set[2];

};

struct EDCAtag
{
        u_char      tag_number;
        u_char      tag_len;
        u_char      ext_tag_number;
        u_char      Qosinfo;
        u_char      BE[3];
        u_char      BK[3];
        u_char      VI[3];
        u_char      VO[3];
};

struct vendorTag1
{
        u_char      tag_number;
        u_char      tag_len;
        u_char      oui[3];
        u_char      oui_type;
        u_char      vendor_data[45];
};

struct vendorTag2
{
        u_char      tag_number;
        u_char      tag_len;
        u_char      oui[3];
        u_char      oui_type;
        u_char      vendor_data[22];
};

struct vendorTag3
{
        u_char      tag_number;
        u_char      tag_len;
        u_char      oui[3];
        u_char      oui_type;
        u_char      vendor_data[5];
};

struct vendorTag4
{
        u_char      tag_number;
        u_char      tag_len;
        u_char      oui[3];
        u_char      oui_type;
        u_char      wme_type;
        u_char      wme_version;
        u_char      wme_info;
        u_char      reserved;
        u_char      Ac1[4];
        u_char      Ac2[4];
        u_char      Ac3[4];
        u_char      Ac4[4];
};

struct BeaconFrame{
        struct RadioTap         RT;
        struct Dot              dot;
        struct DotManagement    dotManage;
        struct SSIDTag          ssid;
        struct RateTag          rate;
        struct DsTag            channel;
        struct TrafficTag       traffic;
        struct CountryTag       country;
        struct TPCtag           tpc;
        struct ERPtag           erp;
        struct extRateTag       extRate;
        struct RSNTag           rsn;
        struct QBSStag          qbss;
        struct RMtag            rm;
        struct HTtag            ht;
        struct HTinfoTag        htinfo;
        struct BSStag           bss;
        struct extCapaTag       capa;
        struct VHTcapaTag       vht_capa;
        struct VHTopTag         vht_op;
        struct HEcapaTag        he_capa;
        struct HEopTag          he_op;
        struct EDCAtag          edca;
        struct vendorTag1       vendor1;
        struct vendorTag2       vendor2;
        struct vendorTag3       vendor3;
        struct vendorTag4       vendor4;
};

void mac(u_char *mac_addr, const char *arr){
        int a;
        char cpyarr[18];

        if (strlen(arr) != 17)
        {
                printf("Maclen error!!\n");
        }

        memcpy(cpyarr, arr, 17);

        for (int i = 0; i < 6; i++) //입력Mac값의 콜론 제거
        {
                cpyarr[i * 3 + 2] = '\0';
                sscanf((const char *)&cpyarr[3 * i], "%x", &a);
                mac_addr[i] = (u_char)a;
        }
}

void setSSID(struct BeaconFrame *BF, const char *ssid){
        BF->ssid.tag_number = SSID_TAG_NUM;
        BF->ssid.ssid_len = strlen(ssid);
	memset(BF->ssid.ssid_name, 0, SSID_LEN);
        memcpy(BF->ssid.ssid_name, ssid, BF->ssid.ssid_len);
}

void setRate(struct BeaconFrame *BF){
        BF->rate.tag_number = 0x01;
        BF->rate.tag_len = 0x08;
        BF->rate.rate1 = 0x8c;
        BF->rate.rate2 = 0x12;
        BF->rate.rate3 = 0x18;
        BF->rate.rate4 = 0x24;
        BF->rate.rate5 = 0xb0;
        BF->rate.rate6 = 0x48;
        BF->rate.rate7 = 0x60;
        BF->rate.rate8 = 0x6c;
        // BF->rate.rate1 = 0x82;
        // BF->rate.rate2 = 0x84;
        // BF->rate.rate3 = 0x8b;
        // BF->rate.rate4 = 0x96;
        // BF->rate.rate5 = 0x24;
        // BF->rate.rate6 = 0x30;
        // BF->rate.rate7 = 0x48;
        // BF->rate.rate8 = 0x6c;
}

void setDs(struct BeaconFrame *BF){
        BF->channel.tag_number = 0x03;
        BF->channel.tag_len = 0x01;
        BF->channel.channel = 0x0d;
}

void setTraffic(struct BeaconFrame *BF){
        BF->traffic.tag_number = 0x05;
        BF->traffic.tag_len = 0x04;
        BF->traffic.DTIMc = 0x00;
        BF->traffic.DTIMperiod = 0x01;
        BF->traffic.Bitmap = 0x00;
        BF->traffic.virtualBitmap = 0x00;
}

void setCountry(struct BeaconFrame *BF){
        BF->country.tag_number = 0x07;
        BF->country.tag_len = 0x06;
        BF->country.code1 = 0x4b;
        BF->country.code2 = 0x52;
        BF->country.env = 0x04;
        BF->country.info1 = 0x01;
        BF->country.info2 = 0x0d;
        BF->country.info3 = 0x14;
}

void settpc(struct BeaconFrame *BF){
        BF->tpc.tag_number = 0x23;
        BF->tpc.tag_len = 0x02;
        BF->tpc.power = 0x11;
        BF->tpc.link = 0x00;
}

void seterp(struct BeaconFrame *BF){
        BF->erp.tag_number = 0x2a;
        BF->erp.tag_len = 0x01;
        BF->erp.info = 0x04;
}

void setextRateTag(struct BeaconFrame *BF){
        BF->extRate.tag_number = 0x32;
        BF->extRate.tag_len = 0x04;
        BF->extRate.rate1 = 0x0c;
        BF->extRate.rate2 = 0x12;
        BF->extRate.rate3 = 0x18;
        BF->extRate.rate4 = 0x60;
}

void setRSNTag(struct BeaconFrame *BF){
        BF->rsn.tag_number = 0x30;
        BF->rsn.tag_len = 0x14;
        BF->rsn.version = 0x0001;
        BF->rsn.groupSuite = 0x04ac0f00;
        BF->rsn.pairwiseCount = 0x0001;
        BF->rsn.pairwiseSuite = 0x04ac0f00;
        BF->rsn.authCount = 0x0001;
        BF->rsn.authSuite = 0x02ac0f00;
        BF->rsn.capable = 0x008c;
}
void setQBSStag(struct BeaconFrame *BF){
        BF->qbss.tag_number = 0x0b;
        BF->qbss.tag_len = 0x05;
        BF->qbss.station = 0x0001;
        BF->qbss.channel = 0x36;
        BF->qbss.capacity = 0x0000;
}

void setRMtag(struct BeaconFrame *BF){
        BF->rm.tag_number = 0x46;
        BF->rm.tag_len = 0x05;
        BF->rm.rm1 = 0x32;
        BF->rm.rm2 = 0x00;
        BF->rm.rm3 = 0x00;
        BF->rm.rm4 = 0x00;
        BF->rm.rm5 = 0x00;
}

void setHTtag(struct BeaconFrame *BF){
        BF->ht.tag_number = 0x2d;
        BF->ht.tag_len = 0x1a;
        BF->ht.info = 0x19ef;
        BF->ht.MPDU = 0x17;
        BF->ht.Rx1 = 0xffff;
        BF->ht.Rx2 = 0x00;
        BF->ht.HT = 0x00;
        BF->ht.TxBF = 0x00;
        BF->ht.ASEL = 0x00;
}

void setHTinfoTag(struct BeaconFrame *BF){
        BF->htinfo.tag_number = 0x3d;
        BF->htinfo.tag_len = 0x16;
        BF->htinfo.channel = 0x0d;
        BF->htinfo.HT1 = 0x08;
        BF->htinfo.HT2 = 0x04;
        BF->htinfo.HT3 = 0x00;
        BF->htinfo.Rx1 = 0x00; 
        BF->htinfo.Rx2 = 0x00; 
}

void setBSStag(struct BeaconFrame *BF){
        BF->bss.tag_number = 0x4a;
        BF->bss.tag_len = 0x0e;
        BF->bss.passiveDwell = 0x14;
        BF->bss.activeDwell = 0x0a;
        BF->bss.interval = 0x012c;
        BF->bss.passiveChannel = 0xc8;
        BF->bss.activeChannel = 0x14;
        BF->bss.delay = 0x05;
        BF->bss.thresholds = 0x19;
}

void setextCapaTag(struct BeaconFrame *BF){
        BF->capa.tag_number = 0x7f;
        BF->capa.tag_len = 0x0a;
        BF->capa.capa1 = 0x05;
        BF->capa.capa2 = 0x00;
        BF->capa.capa3 = 0x08;
        BF->capa.capa4 = 0x00;
        BF->capa.capa5 = 0x00;
        BF->capa.capa6 = 0x00;
        BF->capa.capa7 = 0x00;
        BF->capa.capa8 = 0x01c0;
        BF->capa.capa9 = 0x40;
}

void setVHTcapaTag(struct BeaconFrame *BF){
        BF->vht_capa.tag_number = 0xbf;
        BF->vht_capa.tag_len = 0x0c;
        BF->vht_capa.info = 0x0f8179b1;
        BF->vht_capa.set = 0x2000fffa0000fffa;
}

void setVHTopTag(struct BeaconFrame *BF){
        BF->vht_op.tag_number = 0xc0;
        BF->vht_op.tag_len = 0x05;
        BF->vht_op.info1 = 0x00;
        BF->vht_op.info2 = 0x0d;
        BF->vht_op.info3 = 0x00;
        BF->vht_op.map = 0x00;
}
void setHEcapaTag(struct BeaconFrame *BF){
        BF->he_capa.tag_number = 0xff;
        BF->he_capa.tag_len = 0x1a;
        BF->he_capa.ext_tag_number = 0x23;
        mac(BF->he_capa.MACinfo,"05:00:08:12:00:10");
        BF->he_capa.PHYinfo[0] = 0x22;
        BF->he_capa.PHYinfo[1] = 0x20;
        BF->he_capa.PHYinfo[2] = 0x02;
        BF->he_capa.PHYinfo[3] = 0xc0;
        BF->he_capa.PHYinfo[4] = 0x0d;
        BF->he_capa.PHYinfo[5] = 0x41;
        BF->he_capa.PHYinfo[6] = 0x81;
        BF->he_capa.PHYinfo[7] = 0x08;
        BF->he_capa.PHYinfo[8] = 0x00;
        BF->he_capa.PHYinfo[9] = 0x8c;
        BF->he_capa.PHYinfo[10] = 0x00;
        BF->he_capa.set[0] = 0xfa; 
        BF->he_capa.set[1] = 0xff; 
        BF->he_capa.set[2] = 0xfa; 
        BF->he_capa.set[3] = 0xff; 
        BF->he_capa.thresholds[0] = 0x19; 
        BF->he_capa.thresholds[1] = 0x1c; 
        BF->he_capa.thresholds[2] = 0xc7; 
        BF->he_capa.thresholds[3] = 0x71; 
}
void setHEopTag(struct BeaconFrame *BF){
        BF->he_op.tag_number = 0xff;
        BF->he_op.tag_len = 0x07;
        BF->he_op.ext_tag_number = 0x24;
        BF->he_op.operation[0] = 0x04;
        BF->he_op.operation[1] = 0x00;
        BF->he_op.operation[2] = 0x01;
        BF->he_op.info = 0x39;
        BF->he_op.set[0] = 0xfc;
        BF->he_op.set[1] = 0xff;
}
void setEDCAtag(struct BeaconFrame *BF){
        BF->edca.tag_number = 0xff;
        BF->edca.tag_len = 0x0e;
        BF->edca.ext_tag_number = 0x26;
        BF->edca.Qosinfo = 0x04;
        BF->edca.BE[0] = 0x00;
        BF->edca.BE[1] = 0xa4;
        BF->edca.BE[2] = 0x08;
        BF->edca.BK[0] = 0x20;
        BF->edca.BK[1] = 0xa4;
        BF->edca.BK[2] = 0x08;
        BF->edca.VI[0] = 0x40;
        BF->edca.VI[1] = 0x43;
        BF->edca.VI[2] = 0x08;
        BF->edca.VO[0] = 0x60;
        BF->edca.VO[1] = 0x32;
        BF->edca.VO[2] = 0x08;
}
void setvendorTag1(struct BeaconFrame *BF){
        BF->vendor1.tag_number = 0xdd;
        BF->vendor1.tag_len = 0x31;
        BF->vendor1.oui[0] = 0xf8;
        BF->vendor1.oui[1] = 0x32;
        BF->vendor1.oui[2] = 0xe4;
        BF->vendor1.oui_type = 0x01;
        BF->vendor1.vendor_data[0] = 0x01;
        BF->vendor1.vendor_data[1] = 0x01;
        BF->vendor1.vendor_data[2] = 0x02;
        BF->vendor1.vendor_data[3] = 0x01;
        BF->vendor1.vendor_data[4] = 0x00;
        BF->vendor1.vendor_data[5] = 0x03;
        BF->vendor1.vendor_data[6] = 0x14;
        BF->vendor1.vendor_data[7] = 0xa8;
        BF->vendor1.vendor_data[8] = 0x37;
        BF->vendor1.vendor_data[9] = 0x29;
        BF->vendor1.vendor_data[10] = 0x3f;
        BF->vendor1.vendor_data[11] = 0x87;
        BF->vendor1.vendor_data[12] = 0x32;
        BF->vendor1.vendor_data[13] = 0x9e;
        BF->vendor1.vendor_data[14] = 0x00;
        BF->vendor1.vendor_data[15] = 0x03;
        BF->vendor1.vendor_data[16] = 0x99;
        BF->vendor1.vendor_data[17] = 0xdd;
        BF->vendor1.vendor_data[18] = 0x7f;
        BF->vendor1.vendor_data[19] = 0x01;
        BF->vendor1.vendor_data[20] = 0x56;
        BF->vendor1.vendor_data[21] = 0x7d;
        BF->vendor1.vendor_data[22] = 0xf1;
        BF->vendor1.vendor_data[23] = 0x63;
        BF->vendor1.vendor_data[24] = 0x91;
        BF->vendor1.vendor_data[25] = 0xd7;
        BF->vendor1.vendor_data[26] = 0x1f;
        BF->vendor1.vendor_data[27] = 0x07;
        BF->vendor1.vendor_data[28] = 0x04;
        BF->vendor1.vendor_data[29] = 0x5a;
        BF->vendor1.vendor_data[30] = 0x3d;
        BF->vendor1.vendor_data[31] = 0x3b;
        BF->vendor1.vendor_data[32] = 0x9c;
        BF->vendor1.vendor_data[33] = 0x12;
        BF->vendor1.vendor_data[34] = 0x04;
        BF->vendor1.vendor_data[35] = 0xf0;
        BF->vendor1.vendor_data[36] = 0xf4;
        BF->vendor1.vendor_data[37] = 0x00;
        BF->vendor1.vendor_data[38] = 0x00;
        BF->vendor1.vendor_data[39] = 0x13;
        BF->vendor1.vendor_data[40] = 0x01;
        BF->vendor1.vendor_data[41] = 0x01;
        BF->vendor1.vendor_data[42] = 0x15;
        BF->vendor1.vendor_data[43] = 0x01;
        BF->vendor1.vendor_data[44] = 0x00;
}
void setvendorTag2(struct BeaconFrame *BF){
        BF->vendor2.tag_number = 0xdd;
        BF->vendor2.tag_len = 0x1a;
        BF->vendor2.oui[0] = 0x00;
        BF->vendor2.oui[1] = 0x90;
        BF->vendor2.oui[2] = 0x4c;
        BF->vendor2.oui_type = 0x04;
        BF->vendor2.vendor_data[0] = 0x18;
        BF->vendor2.vendor_data[1] = 0xbf;
        BF->vendor2.vendor_data[2] = 0x0c;
        BF->vendor2.vendor_data[3] = 0xb1;
        BF->vendor2.vendor_data[4] = 0x79;
        BF->vendor2.vendor_data[5] = 0x81;
        BF->vendor2.vendor_data[6] = 0x0f;
        BF->vendor2.vendor_data[7] = 0xfa;
        BF->vendor2.vendor_data[8] = 0xff;
        BF->vendor2.vendor_data[9] = 0x00;
        BF->vendor2.vendor_data[10] = 0x00;
        BF->vendor2.vendor_data[11] = 0xfa;
        BF->vendor2.vendor_data[12] = 0xff;
        BF->vendor2.vendor_data[13] = 0x00;
        BF->vendor2.vendor_data[14] = 0x20;
        BF->vendor2.vendor_data[15] = 0xc0;
        BF->vendor2.vendor_data[16] = 0x05;
        BF->vendor2.vendor_data[17] = 0x00;
        BF->vendor2.vendor_data[18] = 0x0d;
        BF->vendor2.vendor_data[19] = 0x00;
        BF->vendor2.vendor_data[20] = 0x00;
        BF->vendor2.vendor_data[21] = 0x00;
}
void setvendorTag3(struct BeaconFrame *BF){
        BF->vendor3.tag_number = 0xdd;
        BF->vendor3.tag_len = 0x09;
        BF->vendor3.oui[0] = 0x00;
        BF->vendor3.oui[1] = 0x10;
        BF->vendor3.oui[2] = 0x18;
        BF->vendor3.oui_type = 0x02;
        BF->vendor3.vendor_data[0] = 0x01;
        BF->vendor3.vendor_data[1] = 0x00;
        BF->vendor3.vendor_data[2] = 0x9c;
        BF->vendor3.vendor_data[3] = 0x00;
        BF->vendor3.vendor_data[4] = 0x00;
}
void setvendorTag4(struct BeaconFrame *BF){
        BF->vendor4.tag_number = 0xdd;
        BF->vendor4.tag_len = 0x18;
        BF->vendor4.oui[0] = 0x00;
        BF->vendor4.oui[1] = 0x50;
        BF->vendor4.oui[2] = 0xf2;
        BF->vendor4.oui_type = 0x02;
        BF->vendor4.wme_type = 0x01;
        BF->vendor4.wme_version = 0x01;
        BF->vendor4.wme_info = 0x80;
        BF->vendor4.reserved = 0x00;
        BF->vendor4.Ac1[0] = 0x03;
        BF->vendor4.Ac1[1] = 0xa4;
        BF->vendor4.Ac1[2] = 0x00;
        BF->vendor4.Ac1[3] = 0x00;
        BF->vendor4.Ac2[0] = 0x27;
        BF->vendor4.Ac2[1] = 0xa4;
        BF->vendor4.Ac2[2] = 0x00;
        BF->vendor4.Ac2[3] = 0x00;
        BF->vendor4.Ac3[0] = 0x42;
        BF->vendor4.Ac3[1] = 0x43;
        BF->vendor4.Ac3[2] = 0x5e;
        BF->vendor4.Ac3[3] = 0x00;
        BF->vendor4.Ac4[0] = 0x62;
        BF->vendor4.Ac4[1] = 0x32;
        BF->vendor4.Ac4[2] = 0x2f;
        BF->vendor4.Ac4[3] = 0x00;
}

void setTag(struct BeaconFrame *BF, const char *ssid){
        
        setRate(BF);
        setDs(BF);
        setTraffic(BF);
        setCountry(BF);
        settpc(BF);
        seterp(BF);
        setextRateTag(BF);
        setQBSStag(BF);
        setRMtag(BF);
        setRSNTag(BF);
        setHTtag(BF);
        setHTinfoTag(BF);
        setBSStag(BF);
        setextCapaTag(BF);
        setVHTcapaTag(BF);
        setVHTopTag(BF);
        setHEcapaTag(BF);
        setHEopTag(BF);
        setEDCAtag(BF);
        setvendorTag1(BF);
        setvendorTag2(BF);
        setvendorTag3(BF);
        setvendorTag4(BF);

}

void setBeaconFrame(struct BeaconFrame *BF, const char *ssid, const char *src)
{
        memset(BF, 0, sizeof(struct BeaconFrame));

        BF->RT.len = 0x8;

        BF->dot.type = 0x80;
        mac(BF->dot.dest, "ff:ff:ff:ff:ff:ff");
        mac(BF->dot.src,src);
        memcpy(BF->dot.bssid, BF->dot.src, 6);

        BF->dotManage.interval = 0x0064;
        BF->dotManage.cap = 0x1411;
        setSSID(BF,ssid);
}

int main(int argc,char *argv[]){
    char errbuf[PCAP_ERRBUF_SIZE];
    unsigned char *Interface = argv[1];
    // const char *src = argv[2];
    const char *src = "24:4b:fe:ac:1e:f0";
    const char *ssid = "KITRI_DEV2.4";

    struct BeaconFrame BF;
    setBeaconFrame(&BF,ssid,src);
    setTag(&BF,ssid);

    pcap_t *pcap = pcap_open_live(Interface, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL)
    {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", Interface, errbuf);
        return -1;
    }
    while(1)
        pcap_sendpacket(pcap, (char *)&BF, sizeof(BF));
}