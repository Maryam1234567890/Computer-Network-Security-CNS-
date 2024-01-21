#!/usr/bin/python3
from scapy.all import *
'''Usage:  ./traceroute.py " hostname or ip address"'''
host=sys.argv[1]
print ("Traceroute "+ host)
ttl=1
while 1:
    # Create an IP layer with the destination IP address and the current TTL value
    IPLayer=IP ()
    IPLayer.dst=host
    IPLayer.ttl=ttl

    # Create an ICMP packet for the traceroute
    ICMPpkt=ICMP()
    pkt=IPLayer/ICMPpkt

    # Send the packet and wait for the response
    replypkt = sr1(pkt,verbose=0)

    # If no response is received, break out of the loop
    if replypkt is None:
        break

    # If the response is an ICMP Echo Reply (type=0), it means we've reached the destination
    elif replypkt [ICMP].type==0:
        print(f"{ttl} hops away: ", replypkt [IP].src)
        print( "Done", replypkt [IP].src)
        break

    # Otherwise, print the hop information and increment the TTL for the next iteration
    else:
        print (f"{ttl} hops away: ", replypkt [IP].src)
        ttl+=1
