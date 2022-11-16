import binascii
import random
import hashlib
import sys
import struct
from Crypto.Hash import MD4
from Crypto.Cipher import DES

class Cracker:
    def __init__(self, pwfile, username, challenge, response):
        self.pwfile = pwfile
        self.username = username.encode("utf-16le")
        self.challenge = binascii.unhexlify(challenge.replace(':', '').lower())
        self.response = binascii.unhexlify(response.replace(':', '').lower())
    
    def get_nt_password_hash(self, pw):
        return MD4.new(pw.encode("utf-16le")).digest()
    
    def divide_chunks(self, l, n):
        for i in range(0, len(l), n):
            yield l[i:i + n]
    
    def add_DES_parity(self, key):
        odd_parity = [
            1, 1, 2, 2, 4, 4, 7, 7, 8, 8, 11, 11, 13, 13, 14, 14,
            16, 16, 19, 19, 21, 21, 22, 22, 25, 25, 26, 26, 28, 28, 31, 31,
            32, 32, 35, 35, 37, 37, 38, 38, 41, 41, 42, 42, 44, 44, 47, 47,
            49, 49, 50, 50, 52, 52, 55, 55, 56, 56, 59, 59, 61, 61, 62, 62,
            64, 64, 67, 67, 69, 69, 70, 70, 73, 73, 74, 74, 76, 76, 79, 79,
            81, 81, 82, 82, 84, 84, 87, 87, 88, 88, 91, 91, 93, 93, 94, 94,
            97, 97, 98, 98, 100, 100, 103, 103, 104, 104, 107, 107, 109, 109, 110, 110,
            112, 112, 115, 115, 117, 117, 118, 118, 121, 121, 122, 122, 124, 124, 127, 127,
            128, 128, 131, 131, 133, 133, 134, 134, 137, 137, 138, 138, 140, 140, 143, 143,
            145, 145, 146, 146, 148, 148, 151, 151, 152, 152, 155, 155, 157, 157, 158, 158,
            161, 161, 162, 162, 164, 164, 167, 167, 168, 168, 171, 171, 173, 173, 174, 174,
            176, 176, 179, 179, 181, 181, 182, 182, 185, 185, 186, 186, 188, 188, 191, 191,
            193, 193, 194, 194, 196, 196, 199, 199, 200, 200, 203, 203, 205, 205, 206, 206,
            208, 208, 211, 211, 213, 213, 214, 214, 217, 217, 218, 218, 220, 220, 223, 223,
            224, 224, 227, 227, 229, 229, 230, 230, 233, 233, 234, 234, 236, 236, 239, 239,
            241, 241, 242, 242, 244, 244, 247, 247, 248, 248, 251, 251, 253, 253, 254, 254
        ]

        # Git all bits in the array as bool value
        bits = []
        for i in range(0, len(key)):
            bits.extend(reversed([bool(key[i] & (1 << n)) for n in range(8)]))

        key = b''
        for chunk in self.divide_chunks(bits, 7):
            # Get a chunk of 7 bits and add the least significant bit to 0 (False)
            chunk.append(False)

            # Recreate the value based on the array
            i = sum(v << i for i, v in enumerate(chunk[::-1]))

            # Get the char key value    
            key += struct.pack('B', odd_parity[i])

        return key
    
    def get_challenge_hash(self):
        fake_challenge=bytearray()
        for i in range(0, 16):
            fake_challenge += struct.pack('B', random.randint(0, 255))
        
        sha1_ctx = hashlib.sha1()
        #sha1_ctx.update(fake_challenge)
        sha1_ctx.update(self.challenge) 
        sha1_ctx.update(self.username)
        return sha1_ctx.digest()[:8]
        
    def chall_response(self):
        C = self.get_challenge_hash()
        with open(self.pwfile, 'r') as pw_file:
            while True:
                pw = pw_file.readline()
                if pw == '': break
                
                nt_passwordhash = self.get_nt_password_hash(pw)
                nt_passwordhash += b'\x00' * (21 - len(nt_passwordhash))
                
                k0 = nt_passwordhash[0:7]
                k1 = nt_passwordhash[7:14]
                k2 = nt_passwordhash[14:16] + b'\x00'*5
                cipher1 = DES.new(self.add_DES_parity(k0),DES.MODE_ECB)
                cipher2 = DES.new(self.add_DES_parity(k1),DES.MODE_ECB)
                cipher3 = DES.new(self.add_DES_parity(k2),DES.MODE_ECB)
                
                R = cipher1.encrypt(C) + cipher2.encrypt(C) + cipher3.encrypt(C)
                print(f"My Response  : {binascii.hexlify(R)}")
                print(f"Real REsponse: {binascii.hexlify(self.response)}")
                

if __name__ == '__main__':
    cracker = Cracker(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
    cracker.chall_response()