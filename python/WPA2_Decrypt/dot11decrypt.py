import binascii
from Crypto.Cipher import AES
from scapy.all import *

def dot11i_decrypt(parser, TK):
    for pkt in parser.encrypted_pkts:
        dot11 = pkt[Dot11]
        ccmp = pkt[Dot11CCMP]
        
        PN = "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}".format(ccmp.PN5,ccmp.PN4,ccmp.PN3,ccmp.PN2,ccmp.PN1,ccmp.PN0)
        TA = dot11.addr2.replace(':','',5)
        
        if pkt.haslayer(Dot11QoS):
            tid = '{:01x}'.format(pkt[Dot11QoS].TID)
        else:
            tid = '0'
        priority = '0'+tid
        
        nonce = bytes.fromhex(priority) + bytes.fromhex(TA) + bytes.fromhex(PN)
        
        enc_cipher = AES.new(TK, AES.MODE_CCM, nonce, mac_len=8)
        # MIC는 제거
        decrypted_data = enc_cipher.decrypt(ccmp.data[:-8])
        # 패킷을 저장할때 source, destination의 정보를 함게 넣어줘야 함 + Logical-Link Control 부분은 빼준다.
        wrpcap('./dec_pcap/decrypted.pcap', binascii.a2b_hex(dot11.addr1.replace(':','',5)+dot11.addr2.replace(':','',5))+decrypted_data[6:], append=True)