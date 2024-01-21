#!/usr/bin/python3
from scapy.all import *
print("SNIFFING PACKETS...");
def print_pkt(pkt):
    # Display the contents of the packet using Scapy's show() method
    pkt.show()

    # Use the 'sniff' function from Scapy to capture packets
    # Arguments:
    # iface: The network interface to sniff on. Replace "br-****" with the actual interface name.
    # prn: The function to be called for each captured packet. In this case, it's 'print_pkt'.
pkt = sniff(iface = "br-****",prn=print_pkt)

