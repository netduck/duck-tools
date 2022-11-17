#pragma once

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>


extern bool is_Op;

extern bool Op_i;

extern bool Op_s;

extern bool Op_c;

extern bool Op_t;

extern bool Op_d;

extern bool Op_a;

extern bool Op_x;


extern const char *optstring;
typedef struct Option
{
    unsigned int Op_f_ch;   // Fixed Channel
    unsigned int Op_t_time; // Time
    char Op_d_stamac[6];    // ATK Type <STA mac> unicast
    unsigned char *Interface;
    unsigned char *Input_AP_MAC;
    unsigned char *Input_SSID;
} Opt;

int optionParse(int argc, char *argv[], Opt *opt); //사용시 argv 뒤집힘 주의