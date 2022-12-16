from scapy.all import *
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.layers import all
from scapy import *

def forward(pkt):
    if (IP in pkt):
        if (pkt.sniffed_on == "r-eth1" or pkt.sniffed_on == "r-eth0"):
            pkt[IP].src = "8.8.254.254"
            sendp(pkt)
            

            """if (pkt[IP].dst == "10.2.2.1" and pkt.sniffed_on == "r-eth1"):
                pkt.dst = getmacbyip(pkt[IP].dst)
                sendp(pkt, iface="r-eth2")
            elif (pkt[IP].dst == "10.1.1.1" and pkt.sniffed_on == "r-eth2"):
                pkt.dst = getmacbyip(pkt[IP].dst)
                sendp(pkt, iface="r-eth1")"""

sniff(iface=['r-eth1','r-eth2'], prn=forward)
