// gcc -o example example.c channel_hopper.c iwlib.c -lm
#include "channel_hopper.h"
#include <stdio.h>

void main(void)
{
	if(!channel_hopping("mon0", 149))
		printf("Good\n");
}
