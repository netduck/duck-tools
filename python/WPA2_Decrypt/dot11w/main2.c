// gcc -o main main.c -lssl -lcrypto
#include <stdio.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "crypto.h"
// 802.11w
#include "supplicant/common.h"
#include "supplicant/sha256.h"
#include "supplicant/os.h"

#define DK_LEN		256
#define	PMK_LEN		DK_LEN/8

unsigned char PTK[48];

void Hex2Array(const char *hex_str, uint8_t *array){
	size_t i, array_size = strlen(hex_str)/2;
	char t[3];

	for(i = 0; i < array_size; i++){
		memcpy(t, (hex_str + i*2), 2);
		t[2] = '\0';
		*(array + i) = (uint8_t)strtoul(t, NULL, 16);
	}
	return array_size;
}
int main(int argc, char *argv[])
{	
	unsigned char PMK[64];
	unsigned char data[76];
	Hex2Array(argv[1], PMK);
	Hex2Array(argv[2], data);	
	sha256_prf(PMK, PMK_LEN, "Pairwise key expansion", data, 76, PTK, 48);
	for(int i=0; i<48; i++)
		printf("%02x", PTK[i]);
	return 0;
}
