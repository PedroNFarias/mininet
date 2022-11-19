#!/usr/bin/env python

from scapy.all import *

def forwarder(pkt):
        print(pkt)


sniff(iface=['r-eth1','r-eth2'], prn=forwarder)