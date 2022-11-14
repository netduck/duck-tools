/*
 *
 *	Channel Hopper
 *
 */
#include <math.h>
#include <unistd.h>
#include <sys/types.h>

#include "iwlib.h"
#include "channel_hopper.h"

int channel_hopping(
		char*	iface,
		double	channel /* channel or freq */
		)
{
	struct iwreq	wrq;
	int		skfd;

	if(!is_root())
	{
		fprintf(stderr, "Channel Hopper : U R Not Root %d\n", geteuid());
		exit(-1);
	}
	
	if((skfd = iw_sockets_open()) < 0)
	{
		fprintf(stderr, "Channel Hopper : iw_sockets_open Error\n");
		exit(-1);
	}


	iw_float2freq(channel, &(wrq.u.freq));
	wrq.u.freq.flags = IW_FREQ_FIXED;
	
	if(iw_set_ext(skfd, iface, SIOCSIWFREQ, &wrq) < 0)
	{
		fprintf(stderr, "Channel Hopper : iw_set_ext Error\n");
		exit(-1);
	}

	iw_sockets_close(skfd);

	return 0;
}

int is_root(void)
{
	return (geteuid()==0) ? 1 : 0 ; 
}

