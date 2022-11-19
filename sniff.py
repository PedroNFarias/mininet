#!/usr/bin/env python

from scapy.all import *

def forwarder(pkt):
        mac = getmacbyip(pkt[IP].dst)
        print("Forwarding packet to %s" % mac)


sniff(iface=['r-eth1','r-eth2'], prn=forwarder)