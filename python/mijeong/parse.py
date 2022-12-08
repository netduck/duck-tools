from scapy.all import *
import binascii

class PARSER:
    def __init__(self, sta_mac, ap_mac):
        self.sta_mac = sta_mac
        self.ap_mac = ap_mac
        self.packets = None
        self.Anonce = None
        self.Snonce = None
        self.AP_MAC = None
        self.STA_MAC = None
        self.mics = list()
        self.data = list()
        self.enc_type = None
        self.satisfied= [0,0,0,0]
    
    def all_satisfied(self):
        if self.satisfied[0] == 1 and self.satisfied[1] ==1 and self.satisfied[2] == 1 and self.satisfied[3] == 1:
            return True
        return False
    
    def get_info(self, packet):
        pkt = packet
        elt = pkt.getlayer(Dot11Elt)
        dot11 = pkt.getlayer(Dot11)
        # 802.11w, 802.11i를 구분하기 위함
        if pkt.haslayer(Dot11AssoReq):
            if pkt[Dot11AssoReq][Dot11EltRSN][AKMSuite].fields['suite'] == 6:
                self.enc_type = 3
            elif pkt[Dot11AssoReq][Dot11EltRSN][AKMSuite].fields['suite'] == 2:
                self.enc_type = 2
        
        if pkt.haslayer(EAPOL):
            if (dot11.addr1 == self.ap_mac and dot11.addr2 == self.sta_mac) or (dot11.addr1==self.sta_mac and dot11.addr2 == self.ap_mac):
                
                # Check DS Status
                #print(int(binascii.b2a_hex(pkt[EAPOL].load[1:2]),16))
                if pkt[Dot11FCS].FCfield.value & 0x2 == 0x2:
                    # Check Secure bit
                    if int(binascii.b2a_hex(pkt[EAPOL].load[1:2]),16) & 0x02 == 0:
                        # EAPOL1
                        self.AP_MAC = pkt.addr2.replace(':', '')
                        self.STA_MAC = pkt.addr1.replace(':', '')
                        self.Anonce = binascii.b2a_hex(pkt.load[13:45])
                        self.satisfied[0] = 1
                    else:
                        # EAPOL3
                        mic = binascii.b2a_hex(pkt.load[77:93])
                        self.mics.append(mic)
                        data = binascii.hexlify(bytes(pkt[EAPOL]))
                        data = data.replace(mic, b"0"*32)
                        data = binascii.a2b_hex(data)
                        self.data.append(data)
                        self.satisfied[2] = 1
                else:
                    if int(binascii.b2a_hex(pkt[EAPOL].load[1:2]),16) & 0x02 == 0:
                        # EAPOL2
                        self.Snonce = binascii.b2a_hex(pkt.load[13:45])
                        mic = binascii.b2a_hex(pkt.load[77:93])
                        self.mics.append(mic)
                        data = binascii.hexlify(bytes(pkt[EAPOL]))
                        data = data.replace(mic, b"0"*32)
                        data = binascii.a2b_hex(data)
                        self.data.append(data)
                        self.satisfied[1] = 1
                    else:
                        #EAPOL4
                        mic = binascii.b2a_hex(pkt.load[77:93])
                        self.mics.append(mic)
                        data = binascii.hexlify(bytes(pkt[EAPOL]))
                        data = data.replace(mic, b"0"*32)
                        data = binascii.a2b_hex(data)
                        self.data.append(data)
                        self.satisfied[3] = 1
        return False
