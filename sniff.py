#!/usr/bin/env python

from scapy.all import *

def forwading(pkt):
        pkt.show()
        return pkt

sniff(iface=['r-eth1','r-eth2'], prn=forwading)