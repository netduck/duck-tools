#pragma once

#include <stdlib.h>
#include <string.h>
#define dot11

#include <pcap.h>
#include <stdbool.h>

typedef struct Radiotap_hdr
{
    u_char hdr_rev;          // Header revision
    u_char hdr_pad;          // Header Header pad
    u_short hdr_len;         // Header length
    u_char present_flag[12]; //이 길이 가변이라 보내는 놈의 안테나길이에 따라 가변임
    u_char flags;
} __attribute__((packed)) Radio;

//이후 무슨 패킷 캡쳐할지 프레임 달라짐

typedef struct wlan_Beacon_hdr
{
    // u_char type;                    //Type/Subtype
    u_short type;                   // Frame Control Field, [1000 ....] : subtype-8, [.... 00..] : Management frame, [.... ..00] : version
    u_short dur;                    // Duration
    u_char mac_des[6];   // Destination address
    u_char mac_src[6];   // Source address
    u_char mac_bssid[6]; // BSS Id
    u_int Seq_num : 12;             // Sequence number
    u_char Frag_num : 4;            // Fragment number
} BeaconHd;

typedef struct tagged_parameters
{
    u_char tag_number;
    u_char tag_length;
} Tag;


typedef struct
{
    char *dev_;
} Param;


void usage();

bool parse(Param *param, int argc, char *argv[]);

void PtData(const u_char *packet, int caplen);

void Mac_(const char *arr, u_char mac_addr[6]);

const u_char *JumpRadio(const u_char *packet);

void CapturePacket(pcap_t *pcap, const u_char **packet, struct pcap_pkthdr **header);

bool isBeacon(const u_char *packet);