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
        pkt.dst = mac
        sendp(pkt, iface="eth0")

sniff(iface=['r-eth1','r-eth2'], prn=forwarder)