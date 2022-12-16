#!/usr/bin/env python


from scapy.all import *

tabelaDeEndrerecos = []

def nat(package):
        #if IP not in package

        if IP not in package:
                return
        if package[IP] == None:
                return

        packageInfo = []
        packageInfo.append(package[IP].src) 
        packageInfo.append(package[IP].dst)  
        #package.show()

        if TCP in package:
                packageInfo.append(package[TCP].sport) 
                packageInfo.append(package[TCP].dport) 
                packageInfo.append('TCP')

        elif UDP in package:
                packageInfo.append(package[UDP].sport)
                packageInfo.append(package[UDP].dport)
                packageInfo.append('UDP')

        
        if package.sniffed_on == 'r-eth0' and (package[IP].dst == '8.8.8.8' or package[IP].dst == '8.8.4.4') and (package[IP].src == '10.1.1.1' or package[IP].src == '10.1.1.2'):
                package[IP].src = '8.8.254.254'
                package[Ether].src = getmacbyip('8.8.254.254')
                package.chksum = None
                sendp(package, iface='r-eth1')
                tabelaDeEndrerecos.append(packageInfo)

        elif package.sniffed_on == 'r-eth1' and (package[IP].src == '8.8.8.8' or package[IP].src == '8.8.4.4') and package[IP].dst == '8.8.254.254':
                for index, info in enumerate(tabelaDeEndrerecos):
                        if TCP in package:
                                if (info[1] == package[IP].src and info[2] == package[TCP].dport and info[3] == package[TCP].sport and info[4] == 'TCP'):
                                        package[IP].dst = info[0]
                                        package[Ether].dst = getmacbyip(package[IP].dst)
                                        package.chksum = None
                                        sendp(package, iface='r-eth0')
                                        tabelaDeEndrerecos.pop(index)
                        elif UDP in package:
                                if (info[1] == package[IP].src and info[2] == package[UDP].dport and info[3] == package[UDP].sport and info[4] == 'UDP'):
                                        package[IP].dst = info[0]
                                        package[Ether].dst = getmacbyip(package[IP].dst)
                                        package.chksum = None
                                        sendp(package, iface='r-eth0')
                                        tabelaDeEndrerecos.pop(index)

sniff(iface=["r-eth0","r-eth1"], prn=nat)