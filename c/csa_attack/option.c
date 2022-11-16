#include "option.h"
const char *optstring = "i:s:c:t:d:a:x:";

bool is_Op = false;

bool Op_i = false;

bool Op_s = false;

bool Op_c = false;

bool Op_t = false;

bool Op_d = false;

bool Op_a = false;

bool Op_x = false;

int optionParse(int argc, char *argv[], Opt *opt) //사용시 argv 뒤집힘 주의
{

    char option = 1;
    while (-1 != (option = getopt(argc, argv, optstring)))
    {
        switch (option)
        {
        case 'i':
            is_Op = true;
            opt->Interface=optarg;
            Op_i = true;
            break;
        case 's':
            is_Op = true;
            opt->Input_SSID = optarg;
            Op_s = true;
            break;
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
            opt->Input_AP_MAC = optarg;
            Op_a = true;
            break;
        case 'x':
            is_Op = true;
            if(strcmp("kill-them-all",optarg)==0){
            Op_x = true;
            printf("Now, Kill the all NetWork!!!\n");
            }
            else{
                printf("Plz, Check the argument again, did you input \'kill-them-all??\'\n");
            }
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