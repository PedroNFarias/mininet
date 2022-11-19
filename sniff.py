#!/usr/bin/env python

from scapy.all import *

def forwarder(pkt):
        mac = getmacbyip(pkt[IP].dst)
        if mac:
                pkt[Ether].dst = mac
                sendp(pkt)


sniff(iface=['r-eth1','r-eth2'], prn=forwarder)