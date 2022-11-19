#!/usr/bin/env python

from scapy.all import *
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.layers import all
from scapy import *

def forwarder(pkt):
        mac = getmacbyip(pkt[IP].dst)
        pkt[Ether].dst = mac
        sendp(pkt)

sniff(iface=['r-eth1','r-eth2','h1-eth0','h2-eth0'], prn=forwarder)
