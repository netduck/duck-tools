all: wpa2_decrypt

wpa2_decrypt: wpa2_decrypt.c
		gcc -o wpa2_decrypt wpa2_decrypt.c -lssl -lcrypto

clean:
		rm -f wpa2_decrypt *.o
