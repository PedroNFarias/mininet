#!/usr/bin/env python

from scapy.all import *
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.layers import all
from scapy import *

def forwarder(pkt):
        """source_mac_address = pkt[Ether].src
        destination_mac_address = pkt[Ether].dst

        destination_address = pkt[IP].dst
        source_address = pkt[IP].src"""
        print("Package sniffed")
        mac = getmacbyip(pkt[IP].dst)
        #send the packet to the destination by spoofing the source mac address
        sendp(Ether(src=mac)/IP(dst=pkt[IP].dst)/TCP(dport=pkt[TCP].dport, sport=pkt[TCP].sport, flags=pkt[TCP].flags, seq=pkt[TCP].seq, ack=pkt[TCP].ack)/pkt[TCP].payload, iface="eth0")

        


sniff(iface=['r-eth1','r-eth2'], prn=forwarder)