import binascii
import random
import hashlib
import sys
from Crypto.Cipher import DES

class Cracker:
    def __init__(self, pwfile, username, challenge, response):
        self.pwfile = pwfile
        self.username = username.encode()
        self.challenge = binascii.unhexlify(challenge.replace(':', '').lower())
        self.response = binascii.unhexlify(response.replace(':', '').lower())
    
    def get_nt_password_hash(self, pw):
        return hashlib.new('md4',pw.encode("utf-16le")).digest()
    
    # Copied from https://github.com/SecureAuthCorp/impacket/blob/1c21a460ae1f8d20e7c35c2d4b123800472feeb3/impacket/ntlm.py#L534
    def __expand_DES_key(self, key):
    # Expand the key from a 7-byte password key into a 8-byte DES key
        key  = key[:7]
        key += bytearray(7-len(key))
        s = bytearray()
        s.append(((key[0] >> 1) & 0x7f) << 1)
        s.append(((key[0] & 0x01) << 6 | ((key[1] >> 2) & 0x3f)) << 1)
        s.append(((key[1] & 0x03) << 5 | ((key[2] >> 3) & 0x1f)) << 1)
        s.append(((key[2] & 0x07) << 4 | ((key[3] >> 4) & 0x0f)) << 1)
        s.append(((key[3] & 0x0f) << 3 | ((key[4] >> 5) & 0x07)) << 1)
        s.append(((key[4] & 0x1f) << 2 | ((key[5] >> 6) & 0x03)) << 1)
        s.append(((key[5] & 0x3f) << 1 | ((key[6] >> 7) & 0x01)) << 1)
        s.append((key[6] & 0x7f) << 1)
        return bytes(s)
        
    def crack(self):
        with open(self.pwfile, 'r') as pw_file:
            while True:
                # 개행을 없애는걸 절대 까먹지 말자!!!!!!
                pw = pw_file.readline().replace('\n','')
                
                if pw == '': break
                
                NTHash = self.get_nt_password_hash(pw)

                k0 = NTHash[0:7]
                k1 = NTHash[7:14]
                k2 = NTHash[14:16] + b'\x00'*5
                cipher1 = DES.new(self.__expand_DES_key(k0),DES.MODE_ECB)
                cipher2 = DES.new(self.__expand_DES_key(k1),DES.MODE_ECB)
                cipher3 = DES.new(self.__expand_DES_key(k2),DES.MODE_ECB)

                R = cipher1.encrypt(self.challenge) + cipher2.encrypt(self.challenge) + cipher3.encrypt(self.challenge)
                if R == self.response:
                    print(f"[+] Username: {self.username}")
                    print(f"[+] PW      : {pw}")
                    exit(1)
                

if __name__ == '__main__':
    cracker = Cracker(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
    cracker.crack()
