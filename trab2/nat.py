#!/usr/bin/env python


from scapy.all import *

# Felipe Machado, Fernando Laydner e Luis Felipe Cavalheiro 

tabelaDeRotas = []

def nat(pkt):
        #if IP not in pkt

        if IP not in pkt:
                return
        if pkt[IP] == None:
                return

        pktInfo = []
        pktInfo.append(pkt[IP].src) 
        pktInfo.append(pkt[IP].dst)  
        pkt.show()

        if TCP in pkt:
                pktInfo.append(pkt[TCP].sport) 
                pktInfo.append(pkt[TCP].dport) 
                pktInfo.append('TCP')

        elif UDP in pkt:
                pktInfo.append(pkt[UDP].sport)
                pktInfo.append(pkt[UDP].dport)
                pktInfo.append('UDP')

        
        if pkt.sniffed_on == 'r-eth0' and (pkt[IP].dst == '8.8.8.8' or pkt[IP].dst == '8.8.4.4') and (pkt[IP].src == '10.1.1.1' or pkt[IP].src == '10.1.1.2'):
                pkt[IP].src = '8.8.254.254'
                pkt[Ether].src = getmacbyip('8.8.254.254')
                pkt.chksum = None
                sendp(pkt, iface='r-eth1')
                tabelaDeRotas.append(pktInfo)

        elif pkt.sniffed_on == 'r-eth1' and (pkt[IP].src == '8.8.8.8' or pkt[IP].src == '8.8.4.4') and pkt[IP].dst == '8.8.254.254':
                for index, info in enumerate(tabelaDeRotas):
                        if TCP in pkt:
                                if (info[1] == pkt[IP].src and info[2] == pkt[TCP].dport and info[3] == pkt[TCP].sport and info[4] == 'TCP'):
                                        pkt[IP].dst = info[0]
                                        pkt[Ether].dst = getmacbyip(pkt[IP].dst)
                                        pkt.chksum = None
                                        sendp(pkt, iface='r-eth0')
                                        tabelaDeRotas.pop(index)
                        elif UDP in pkt:
                                if (info[1] == pkt[IP].src and info[2] == pkt[UDP].dport and info[3] == pkt[UDP].sport and info[4] == 'UDP'):
                                        pkt[IP].dst = info[0]
                                        pkt[Ether].dst = getmacbyip(pkt[IP].dst)
                                        pkt.chksum = None
                                        sendp(pkt, iface='r-eth0')
                                        tabelaDeRotas.pop(index)

sniff(iface=["r-eth0","r-eth1"], prn=nat) 



