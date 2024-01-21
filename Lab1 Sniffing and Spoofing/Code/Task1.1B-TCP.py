#!/usr/bin/python3
from scapy.all import *
print ("SNIFFING PACKETS...")
def print_pkt(pkt):
    pkt.show()
    #it's filtering TCP packets with a source IP of 10.9.0.5 and a destination port 23 (Telnet).
pkt = sniff (iface = "br-****",filter='tcp and src host 10.9.0.5 and dst port 23', prn=print_pkt)

