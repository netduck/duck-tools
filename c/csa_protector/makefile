all : csa_protector

csa_protector : main.c
		gcc -o csa_protector main.c dot11.c csa.c channel_hopper.c iwlib.c -lpcap -lm

clean:
		rm -f csa_protector
