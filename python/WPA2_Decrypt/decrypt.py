import parser
import keygen
import dot11decrypt
import sys
import os.path
import os

if __name__ == '__main__':
    ssid = sys.argv[1]
    passphrase = sys.argv[2]
    if os.path.isfile('./dec_pcap/decrypted.pcap'):
        os.system('rm ./dec_pcap/decrypted.pcap')

    parser = parser.PARSER()
    parser.get_info()
    keygen = keygen.KEY_GENERATOR(parser, ssid, passphrase)
    pmk = keygen.gen_PMK()
    ptk = keygen.gen_PTK(pmk)
    mics = keygen.gen_mics(ptk, parser.data) 
    if keygen.verify_mics(mics, parser):
        print("[+] DECRYPTED PACKETS SAVED AT ./dec_pcap")
        dot11decrypt.dot11i_decrypt(parser, ptk[32:48])
    else:
        print("[!] THIS PROGRAM CAN'T DECRYPT THIS FILE")
