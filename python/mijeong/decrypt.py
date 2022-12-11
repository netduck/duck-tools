import binascii
from Crypto.Cipher import AES
from scapy.all import *
# only for action frame
# Action프레임에서 nonce생성할때 priority부분이 달라서 디크립트가 안되었었음.
def generate_AAD(dot11):
    FC = dot11.__bytes__()[:2]
    addrs = dot11.__bytes__()[4:22]
    SC = dot11.SC
    x=int(binascii.hexlify(FC),16)
    y=int('8fc7',16)
    z=int('40',16)
    tmp = hex((x&y)|z)[2:].zfill(4)
    
    x=SC
    y=int('f',16)
    tmp2 = hex(x&y)[2:].zfill(4)
    AAD = binascii.unhexlify(tmp)+addrs+binascii.unhexlify(tmp2)
    return AAD

def dot11_decrypt(pkt, TK):
    dot11 = pkt[Dot11]
    ccmp = pkt[Dot11CCMP]
    
    PN = "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}".format(ccmp.PN5,ccmp.PN4,ccmp.PN3,ccmp.PN2,ccmp.PN1,ccmp.PN0)
    TA = dot11.addr2.replace(':','',5)
    if pkt.haslayer(Dot11QoS):
        tid = '{:01x}'.format(pkt[Dot11QoS].TID)
    else:
        tid = '0'
    
    priority = '1'+tid
    nonce = bytes.fromhex(priority) + bytes.fromhex(TA) + bytes.fromhex(PN)
    AAD = generate_AAD(dot11)
    
    enc_cipher = AES.new(TK, AES.MODE_CCM, nonce, mac_len=8)
    enc_cipher.update(AAD)
    # MIC는 제거
    decrypted_data = enc_cipher.decrypt(ccmp.data[:-8])
    return decrypted_data

def dot11_encrypt(pkt, TK, transaction_id):
    dot11 = pkt[Dot11]
    data = binascii.unhexlify('8001')+transaction_id
    PN = "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}".format(0,0,0,0,0,0)
    TA = dot11.addr2.replace(':','',5)
    priority = '10'
    nonce = bytes.fromhex(priority) + bytes.fromhex(TA) + bytes.fromhex(PN)
    enc_cipher = AES.new(TK, AES.MODE_CCM, nonce, mac_len=8)

    # This for PMF
    dot11.FCfield.value=64
    
    encrypted_data, MIC = enc_cipher.encrypt(data), enc_cipher.digest()
    encrypted_data += MIC
    ccmp = Dot11CCMP(PN0=0,PN1=0,key_id=0,ext_iv=1,res1=0,PN2=0,PN3=0,PN4=0,PN5=0,data=encrypted_data)

    pkt = pkt/ccmp
    return pkt


TK = binascii.unhexlify('b765cd4e68c009555a2ed173ee2a653f')
pkt = rdpcap('./test/sa_request.pcap')[0]
transaction_id = dot11_decrypt(pkt, TK)[2:]

ap_mac ='24:4b:fe:ac:1e:f0'
sta_mac = '2c:6d:c1:32:90:ba'
action_frame = RadioTap()/Dot11(type=0,subtype=13,addr1=ap_mac,addr2=sta_mac,addr3=ap_mac)
action_frame = dot11_encrypt(action_frame,TK,transaction_id)

transaction_id = dot11_decrypt(action_frame, TK)[2:]

wrpcap('./test/test.pcap',action_frame)

