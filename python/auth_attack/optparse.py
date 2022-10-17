import argparse
import re

def get_args():
    parser = argparse.ArgumentParser(
            prog="auth_attack",
            usage="%(prog)s -i mon0 -c 149 -a AA:AA:AA:AA:AA:AA -s BB:BB:BB:BB:BB:BB -v 41D3N",
            description="WPA1/2 Authentication Attack Tool",
            allow_abbrev=False
            )
    parser.add_argument('-i', '--interface', dest='iface', default="", required=True, type=str)
    parser.add_argument('-c', '--channel', dest='ch', default=0, required=True, type=int)
    parser.add_argument('-a', '--accesspoint', dest='ap', default="", required=True,  type=str)
    parser.add_argument('-s', '--station', dest='sta', default="", required=True, type=str)
    parser.add_argument('-v', '--ssid', dest='ssid', default="", required=True, type=str)
    args = parser.parse_args()

    if not valid_AP(args.ap):
        print("[!] Invalid Access Point MAC : [%s]" % (args.ap))
        exit(-1)
    if not valid_STA(args.sta):
        print("[!] Invalid Station MAC : [%s]" % (args.sta))
        exit(-1)
    if not valid_Iface(args.iface):
        print("[!] Invalid Interface MAC : [%s]" % (args.iface))
        print("[!] You can use : %s" % (get_ifaces()))
        exit(-1)
    if not valid_Ch(args.ch):
        print("[!] Invalid Channel : [%s]" % (args.ch))
        exit(-1)
    if not valid_SSID(args.ssid):
        print("[!] Invalid SSID : [%s]" % (args.ssid))
        exit(-1)

    return args

def valid_SSID(ssid):
    if ssid=="":
        return False
    else:
        return True

def valid_MAC(mac):
    if re.search(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", mac):
        return True
    else:
        return False

def valid_Ch(ch):
    ch_spectrum = list(range(1,164))
    if ch in ch_spectrum:
        return True
    else:
        return False

def valid_Iface(iface):
    ifaces = get_ifaces()
    if iface in ifaces:
        return True
    else:
        return False

def valid_AP(mac):
    return valid_MAC(mac)

def valid_STA(mac):
    return valid_MAC(mac)

# Get Network Interfaces
def get_ifaces():
    ifaces = []
    dev = open('/proc/net/dev', 'r')
    data = dev.read()
    for n in re.findall('[a-zA-Z0-9]+:', data):
        ifaces.append(n.rstrip(":"))
    return ifaces

args = get_args()
