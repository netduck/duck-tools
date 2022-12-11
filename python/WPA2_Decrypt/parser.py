from scapy.all import *
import binascii

class PARSER:
    def __init__(self):
        self.packets = rdpcap('./pcap/sq_query.pcap')
        #self.packets = rdpcap('./pcap/WPA2_NO_PMF.pcapng')
        self.Anonce = None
        self.Snonce = None
        self.AP_MAC = None
        self.STA_MAC = None
        self.mics = list()
        self.data = list()
        self.encrypted_pkts = list()
        self.enc_type = None

    def get_info(self):
        for i in range(0, len(self.packets)):
            pkt = self.packets[i]

            # 802.11w, 802.11i를 구분하기 위함
            if pkt.haslayer(Dot11AssoReq):
                if pkt[Dot11AssoReq][Dot11EltRSN][AKMSuite].fields['suite'] == 6:
                    self.enc_type = 3
                elif pkt[Dot11AssoReq][Dot11EltRSN][AKMSuite].fields['suite'] == 2:
                    self.enc_type = 2
            # EAPOL패킷일 경우 필요한 정보들을 추출한다.
            if pkt.haslayer(EAPOL):
                # Check DS Status
                #print(int(binascii.b2a_hex(pkt[EAPOL].load[1:2]),16))
                if pkt[Dot11].FCfield.value & 0x2 == 0x2:
                    # Check Secure bit
                    if int(binascii.b2a_hex(pkt[EAPOL].load[1:2]),16) & 0x02 == 0:
                        # EAPOL1
                        self.AP_MAC = pkt.addr2.replace(':', '')
                        self.STA_MAC = pkt.addr1.replace(':', '')
                        self.Anonce = binascii.b2a_hex(pkt.load[13:45])
                    else:
                        # EAPOL3
                        mic = binascii.b2a_hex(pkt.load[77:93])
                        self.mics.append(mic)
                        data = binascii.hexlify(bytes(pkt[EAPOL]))
                        data = data.replace(mic, b"0"*32)
                        data = binascii.a2b_hex(data)
                        self.data.append(data)
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
                    else:
                        #EAPOL4
                        mic = binascii.b2a_hex(pkt.load[77:93])
                        self.mics.append(mic)
                        data = binascii.hexlify(bytes(pkt[EAPOL]))
                        data = data.replace(mic, b"0"*32)
                        data = binascii.a2b_hex(data)
                        self.data.append(data)
            # 암호화된 패킷들은 한곳에 저장
            elif pkt.haslayer(Dot11CCMP):
                self.encrypted_pkts.append(pkt)
