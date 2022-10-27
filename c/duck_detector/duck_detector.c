#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>

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
    u_char mac[6];
    u_char *attackType;
    uint8_t pwr;
};

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

void showList();
void showInit(){
    system("clear");
    printf("Mac                Atk    PWR\n\n");
}

int main(int argc, char *argv[])
{
    if (!parse(&param, argc, argv))
        return -1;
    showInit();
    while(1)
        sleep(1);
}