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
    u_char *mac;
    u_char *attackType;
    uint8_t pwr;
}attackList;
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

void showInit(){
    system("clear");
    printf("              Mac    Atk  PWR\n\n");
}

void showList(int*listCnt,struct attackList*list){
    showInit();
    for(int i=0;i<(*listCnt);i++){
        printf("%s  %5s  -%d\n",(list+i)->mac,(list+i)->attackType,(list+i)->pwr);
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
    showList(&cnt,atkList);
}