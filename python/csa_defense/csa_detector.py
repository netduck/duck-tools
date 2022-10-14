from scapy.all import *

def PacketHandler(packet):
    if packet.haslayer(Dot11Elt):
        elt = packet.getlayer(Dot11Elt)
        while elt != None:
            if elt.ID == 37:
                print("\x1b[41m[!] CSA Attack Detection                                           \x1b[0m")
                if packet.haslayer(RadioTap):
                    radio = packet.getlayer(RadioTap)
                    print('\x1b[36;49m[*] signal -> \x1b[0m'+str(radio.dBm_AntSignal)+'dBm\x1b[0m\n\n')

            elt = elt.payload.getlayer(Dot11Elt)
            
print("\x1b[36;49m[*] CSA Attack Detector \x1b[0m")
sniff(iface="mon0", prn = PacketHandler)
