#!/usr/bin/env python

from scapy.all import *

def forwarder(pkt):
        #get the mac by ip
        mac = getmacbyip(pkt[IP].dst)
        print('test')
        #send the packet to the mac
        sendp(Ether(dst=mac)/pkt[IP], iface='eth0')


sniff(iface=['r-eth1','r-eth2'], prn=forwarder)