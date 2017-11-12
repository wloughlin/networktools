#!/usr/bin/env python

import subprocess
from scapy.all import *
import sys

cache = []


def setup():
	output = subprocess.check_output(("arp", "-a"))
	out_lines = output.splitlines()
	for line in out_lines:
		words = line.split()
		tup = (words[1].translate(None, ')('), words[3])
		cache.append(tup)
	if len(sys.argv) == 1:
		return "eth0"
	elif sys.argv[1] == "-i":
		return sys.argv[2]
	else:
		print("Invalid Arguments")
		exit()


def check_packet(pkt):
	if pkt[ARP].op == 2:
		for (ip, mac) in cache:
			if pkt[ARP].psrc == ip and pkt[ARP].hwsrc != mac:
				print(str(ip)+" changed from "+str(mac)+" to "+str(pkt[ARP].hwsrc))
				return



def main():
	interface = setup()
	sniff(count=0, store=0, prn=check_packet, filter="arp")

main();