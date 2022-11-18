#!/usr/bin/env python

from scapy.all import *

def example(pkt):
        print('teste')

sniff(iface=['r-eth1','r-eth2'], prn=example)