#include "csa_attack.h"
#include "option.h"
#define OPTION_H



int main(int argc, char *argv[])
{
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    

    Opt opt;

    optionParse(argc, argv, &opt);
    if (!parse(&param, argc, argv))
        return -1;

    unsigned char *Input_STA_MAC;
    
    

    if (Op_d)
    {
        Input_STA_MAC = "ff:ff:ff:ff:ff:ff";
    }
    else
    {
        Input_STA_MAC = opt.Op_d_stamac;
    }



    csaATK(Input_STA_MAC, &opt);
}