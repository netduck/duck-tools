#pragma once
#include <stdbool.h>
#include <stdlib.h>

#include<pcap.h>

bool isCSA(const u_char *packet, int caplen, int *csaCh);

void sendCSA(pcap_t *pcap, const u_char *packet, int ChangeCh, unsigned char *Interface, int csaCh, int caplen);
