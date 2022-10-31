#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <string.h>

int main(){
    u_char *pass = "abcdefgh";
    int passLen = strlen(pass);
    u_char *ssid = "test-ap";
    int ssidLen = strlen(ssid);
    int iter = 4096;
    int keylen = 256;
    u_char *outPut;
    int a;
    a =PKCS5_PBKDF2_HMAC_SHA1(pass,passLen,ssid,ssidLen,iter,keylen,outPut);
	return 0;
}

// int PKCS5_PBKDF2_HMAC_SHA1(const char *pass, int passlen,
//                            const unsigned char *salt, int saltlen, int iter,
//                            int keylen, unsigned char *out);