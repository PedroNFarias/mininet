#!/usr/bin/env python

from scapy.all import *

def example(pkt):
        #get the source and destination IP addresses
        src = pkt[IP].src
        dst = pkt[IP].dst
        if(dst == "10.2.2.1"):
                print("Packet from source: " + src + " to destination: " + dst) 
                pkt.show()
                return pkt
        elif(dst == "10.1.1.1"):
                print("Packet from source: " + src + " to destination: " + dst)
                pkt.show()
                return None

sniff(iface=['r-eth1','r-eth2'], prn=example)