# WPA2 Decrypt TEST
from pbkdf2 import PBKDF2
from hashlib import pbkdf2_hmac, sha1, sha256
from Crypto.Cipher import AES
from Crypto.Hash import CMAC
import subprocess
import os
import binascii
import hmac
import parser

class KEY_GENERATOR:
	def __init__(self, parser, ssid, passphrase):
		print(f"[+] SSID: {ssid}")
		print(f"[+] passphrase: {passphrase}\n")
		self.verify_information(parser)
		print(f"[+] AP_MAC: {parser.AP_MAC}")
		print(f"[+] STA_MAC: {parser.STA_MAC}")
		print(f"[+] Anonce: {parser.Anonce.decode()}")
		print(f"[+] Snonce: {parser.Snonce.decode()}")
		if parser.enc_type == 2:
			print("[*] 802.11i encryption\n")
		else:
			print("[*] 802.11w encryption\n")
		self.enc_type = parser.enc_type
		self.SSID = ssid
		self.passphrase = passphrase
		self.AP_MAC = binascii.a2b_hex(parser.AP_MAC)
		self.STA_MAC = binascii.a2b_hex(parser.STA_MAC)
		self.Anonce = binascii.a2b_hex(parser.Anonce.decode())
		self.Snonce = binascii.a2b_hex(parser.Snonce.decode())
	
	# verify information
	def verify_information(self, parser):
		if parser.Anonce == None or parser.Snonce == None or parser.AP_MAC == None or parser.STA_MAC == None:
			print("[!] NOT ENOUGH INFORMATION FOR GENERATING KEYS")
			exit(-1)
	
	# PSK == PMK in WPA2
	def gen_PSK(self):
		PSK = PBKDF2(str.encode(self.passphrase), str.encode(self.SSID), 4096).read(32)
		print(f"[+] PSK: {PSK}")
		return PSK.hex()
	
	def gen_PMK(self):
		if self.enc_type == 2 or self.enc_type == 3:
			PMK = pbkdf2_hmac('sha1', str.encode(self.passphrase), str.encode(self.SSID), 4096, 32) #256 bit
			print(f"[+] PMK: {PMK.hex()}")
			from Crypto.Cipher import ARC4, AES
			return PMK

	def gen_PTK(self, PMK):
		ret = b''
		to_byte = 64 # 512 bit
		B = min(self.AP_MAC, self.STA_MAC) + max(self.AP_MAC, self.STA_MAC) + min(self.Anonce, self.Snonce) + max(self.Anonce, self.Snonce)
		A = b'Pairwise key expansion'
		i = 0
		if self.enc_type == 2:
			while i <= ((to_byte*8 + 159)/160):
				hmacsha1 = hmac.new(PMK, A + chr(0x00).encode() + B + chr(i).encode(), sha1)
				ret = ret + hmacsha1.digest()
				i += 1

		elif self.enc_type == 3:
			ret = ''
			tmp = subprocess.run(['./dot11w/main2', binascii.hexlify(PMK), binascii.hexlify(B)], stdout = subprocess.PIPE)
			tmp = tmp.stdout
			for i in range(0, len(tmp)):
				ret += chr(tmp[i])
			ret = binascii.unhexlify(ret)

		print(f"[+] PTK: {binascii.b2a_hex(ret[:to_byte]).decode()}")
		print(f"    [+] KCK: {binascii.b2a_hex(ret[:16]).decode()}")
		print(f"    [+] KEK: {binascii.b2a_hex(ret[16:32]).decode()}")
		print(f"    [+] TK: {binascii.b2a_hex(ret[32:48]).decode()}")
		print(f"    [+] MIC Tx: {binascii.b2a_hex(ret[48:56]).decode()}")
		print(f"    [+] MIC Rx: {binascii.b2a_hex(ret[56:64]).decode()}\n")
		return ret[:to_byte]


	def gen_mics(self, PTK, data):
		# data는 MIC필드를 0으로 set해놓은 핸드쉐이크 메시지
		# KCK를 이용해서 mic계산
		if self.enc_type == 2:
			mics = [hmac.new(PTK[0:16], i, sha1).digest() for i in data]
			return mics
		elif self.enc_type == 3:
			mics = []
			for i in data:
				cobj = CMAC.new(PTK[0:16], ciphermod=AES)
				cobj.update(i)
				mics.append(cobj.digest())
			return mics
	
	def verify_mics(self, mics, parser):
		for i in range(0, len(mics)):
			mic1Str = parser.mics[i].upper().decode()
			micStr = binascii.b2a_hex(mics[i]).decode().upper()[:len(mic1Str)]
			print(f"[*] original   mic: {mic1Str}")
			print(f"[*] calculated mic: {micStr}")
			if mic1Str != micStr:
				print("[!] MISMATCHED\n")
				return False
			else: print("[+] MATCHED")
		print("[+] ALL MIC MATCHED\n")
		return True
