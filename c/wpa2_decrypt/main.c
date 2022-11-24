// gcc -o main main.c -lssl -lcrypto
#include <stdio.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <string.h>

#include "crypto.h"

#define DK_LEN		256
#define ITER		4096
#define EAPOL_LEN	151
#define KEY_VER		0x8a

unsigned char anonce[] = {
"x84\xe7\x50\x7d\x60\xed\x6b\xd8\xa8\x38\x75" 	\
"x35\x9e\x88\x7c\x3c\xd2\xed\x08\x4c\x9b\x05" 	\
"xfd\x58\xcb\x50\xac\x54\x45\xad\x40\xf1" 	\
};

unsigned char snonce[] = {
"x62\xb7\x58\x7c\xb8\x72\x06\x85\x41\x56\x96" 	\
"xf9\x9f\x7e\x6b\x5e\xfd\x09\x39\xe3\x8d\x88"	\
"x43\x32\x9a\x7d\x25\xf8\xac\x5a\xfc\x7b" 	\
};

unsigned char mic[] = \
"x46\xbe\xf8\x6f\x0b\xe1\x11\x0d\xd5\x7d\xfb\xef\xa9\x71\xc2\xbd";

unsigned char eapol[] = {
"x01\x03\x00\x75\x02\x01\x0a\x00\x00\x00\x00\x00" \
"x00\x00\x00\x00\x01\x62\xb7\x58\x7c\xb8\x72\x06\x85\x41\x56\x96" \
"xf9\x9f\x7e\x6b\x5e\xfd\x09\x39\xe3\x8d\x88\x43\x32\x9a\x7d\x25" \
"xf8\xac\x5a\xfc\x7b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
"x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
"x00\x00\x00\x00\x00" \
"x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
"x00\x16\x30\x14\x01\x00\x00\x0f\xac\x04\x01" \
"x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x02\x80\x00"
};

unsigned char cipher[] = {
"x68\xc8\xa7\x74\x43\x30\xde\xca\xda\x79\x00\x54" \
"x0e\x27\xb7\x8c\xa9\x98\xaf\xde\xe8\x8a\x87\x93\xef\xf9\x0f\xec" \
"x5d\x22\x4f\xa6\x42\xb2\xe8\x8b\x6f\xb7\x8f\x3c\x17\x23\xc7\xdb" \
"x86\xa5\x8f\x38\xd9\x69\xd0\xba\xd5\xca\xee\x00\x41\x4e\xd2\x3e" \
"xa3\x3f\xfb\xf8\xbe\x21\x4d\x50\x98\x8b\x8f\xd9\x88\x7a\x0f\x49" \
"x08\xeb\xb7\x14\xb7\xf0\x39\x05\xb5\x95\x45\x03\x63\x4e\x76\xb5" \
"x99\xfa\x15\xd4\x43\xfa\xd4\xbb\xd5\x88\x12\x4a\xcc\xb4\x8c\x02" \
"xd6\x31\xe7\x35\xaa\x58\xdb\x57\xe7\xa0\x32\x4a\x4c\xa9\x89\x4b" \
"x75\xcb\x78\x1f\x03\x9b\x16\x8a\x50\xdb\x05\x48\x07\x6e\x02\xd1" \
"xd7\xb6\x11\xd8\x8d\x55\x3b\xa8\xe4\x48\x8c\x07\xf3\x1f\x97\x76" \
"xbe\x0f\x42\xa6\x7e\xea\x53\xc5\x2b\xb2\xde\x25\xdd\xcb\x88\x72" \
"x0c\x93\x04\x90\x0d\x69\x1d\x8e\x8d\x0b\x9b\x65\x29\x5a\xa1\x43" \
"xcb\x61\x53\xec\xe8\xb8\x9f\x6c\xe3\x3f\x9e\x30\xc8\x92\xa5\x38" \
"x3a\x69\x16\x9c\xaf\xf7\x96\xec\x49\x33\x0c\x9d\x15\x56\x0b\xb6" \
"x41\x45\x4b\xa4\x27\xb8\xbd\xa1\x47\xe9\xc9\xde\xe0\x51\x15\x32" \
"xde\x49\xa6\x4a\xce\x92\xb5\xd3\xdb\x3c\x79\x56\x8a\xf3\x3a\x14" \
"x6f\xce\x20\x88\xbb\x7c\x62\xe1\xc9\xfb\x76\xa9\x0c\xe9\xd7\x73" \
"x42\x83\x84\x25\x39\x99\x80\x59\xcb\x4f\xa0\xb0\x9b\x4e\x84\x3b" \
"xee\x8b\x09\xa6\xe8\x74\x0f\x4b\xac\x5f\x14\x51\x14\x95\x81\x12" \
"x90\xb8\x62\x25\xc3\x4b\xd8\x76\x79\x80\x23\xaf\xb5\xfb\x7d\x13" \
"xc3\x62\x92\x64\x51\x60\x74\x30\xbe\x3d\xec\x4e\x4c\xbc"
};

unsigned char apmac[] = 	"x64\xe5\x99\x7a\xe9\x64";
unsigned char stamac[] =	"xe4\xf8\x9c\x67\xe4\xcc";


int main(void)
{
	u_char *ssid = "test-ap";
	u_char *pass = "abcdefgh";
	u_char pmk[40];

	struct WPA_ST_info *st_info = (struct WPA_ST_info*)malloc(sizeof(struct WPA_ST_info));

	calc_pmk(pass, ssid, pmk);

	memset(st_info, 0, sizeof(struct WPA_ST_info));
	memcpy(st_info->stmac, stamac, 6);
	memcpy(st_info->bssid, apmac, 6);
	memcpy(st_info->anonce, anonce, 32);
	memcpy(st_info->snonce, snonce, 32);
	st_info->eapol_size = 121;
	memcpy(st_info->eapol, eapol, st_info->eapol_size);
	memcpy(st_info->keymic, mic ,16);
	st_info->keyver = KEY_VER;
	if(!calc_ptk(st_info, pmk))
	{
		fprintf(stderr, "MIC Check Failed\n");
		exit(-1);
	}
	decrypt_ccmp(cipher, 330, st_info->ptk + 32);

	free(st_info);

	return 0;
}
