#!/usr/bin/python3
from scapy.all import *
print("SNIFFING PACKETS...")
def print_pkt(pkt):
    pkt.show()
     # In this case, it's filtering packets with a source IP in the range 172.17.0.0/24.
pkt = sniff(iface = "br-****",filter='src net 172.17.0.0/24', prn=print_pkt)

