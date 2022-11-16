#pragma once

#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>


#ifndef OPTION_H
#include "option.h"
#endif

#define MAC_ADDR_LEN 6
#define ARGV_MAX_LEN DEFAULT_ARGV_LEN + 6 // option_len * 2

extern int Wireless_Channel[58];


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
} Tag;

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

typedef struct
{
    char *dev_;
} Param;

extern Param param;


bool parse(Param *param, int argc, char *argv[]);
void usage();

void Mac_(const char *arr, u_char mac_addr[6]);
bool isBeacon(const u_char *packet);
bool arrncmp(const char *arr1, const char *arr2, int len);
void expArray(u_char *packet, int len, int pivot); //배열 공간 생성
void PtData(const u_char *packet, u_char caplen);
int csaATK(const unsigned char *Input_STA_MAC, Opt *opt);
