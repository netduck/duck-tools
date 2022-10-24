#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define DEFAULT_ARGV_LEN 4

bool is_Op = false;
bool Op_c = false;
bool Op_t = false;
bool Op_d = false;
bool Op_a = false;
const char *optstring = "c:t:d:a:";
typedef struct Option
{
    unsigned int Op_c_ch;   // Change Channel
    unsigned int Op_t_time; // Time
    char Op_d_stamac[6];    // ATK Type <STA mac> unicast
    char Op_a_apmac[6];     // AP mac
} Opt;

int optionParse(int argc, char *argv[], Opt *opt) //사용시 argv 뒤집힘 주의
{
    char option = 1;
    while (-1 != (option = getopt(argc, argv, optstring)))
    {
        switch (option)
        {
        case 'c':
            is_Op = true;
            opt->Op_c_ch = atoi(optarg);
            Op_c = true;

            break;
        case 't':

            is_Op = true;
            opt->Op_t_time = atoi(optarg);
            Op_t = true;
            break;
        case 'd':
            is_Op = true;
            strcpy(opt->Op_d_stamac, optarg);
            Op_d = true;
            break;
        case 'a':
            is_Op = true;
            strcpy(opt->Op_a_apmac, optarg);
            Op_a = true;
            break;
        case '?':
            printf("%s option doesn't exist!!!\n", optarg);
            return -1;
        default:
            printf("option error!!!\n");
            return -1;
        }
    }
}
