#!/usr/bin/env python

from scapy.all import *

p = srp1(Ether()/IP(dst="10.1.1.1")/ICMP(),iface='r-eth1')

p.show()