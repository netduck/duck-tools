all : csa_attack

csa_attack : main.c
		gcc -o csa_attack main.c csa_attack.c option.c iwlib.c channel_hopper.c -lpcap -lm -pthread

clean:
		rm -f csa_attack
