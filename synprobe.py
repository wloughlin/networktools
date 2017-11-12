#!/usr/bin/env python

from scapy.all import *
import sys
import random
import socket

def error(exit_code, msg):
    print(msg)
    sys.exit(exit_code);

def check_args():
    if len(sys.argv) == 2:
        return [sys.argv[1]];
    if len(sys.argv) == 4:
        if sys.argv[1] != '-p':
            error(1, "Error: Unexpected Flag!")
        port_range = sys.argv[2].split('-')
        if (len(port_range) == 1 and not port_range[0].isdigit()) or (len(port_range) == 2 and (not port_range[0].isdigit() or not port_range[1].isdigit())):
            error(1, "Error: Undefined Port Range")
        return port_range + [sys.argv[3]]
    error(1, "Error: Incorrect number of arguments")


def make_range(port_range):
    if port_range == []:
        return [22, 25, 53, 67, 68, 80, 110, 123, 137]
    elif len(port_range) == 1:
        return port_range
    return list(range(int(port_range[0]), int(port_range[1])+1))


def main():
    args = None
    args = check_args()
    ip = args.pop()
    open_ports = []
    port_range = make_range(args)
    for i in port_range:
        response = sr(IP(dst=ip)/TCP(dport = int(i), flags="S"), timeout=5, verbose=0)
        for packet_group in response[0]:
            if packet_group[1][TCP].flags == 18:
                open_ports.append((packet_group[1][IP].src, i))
    for (tuple_ip, port) in open_ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.1)
        s.connect((tuple_ip, port))
        try:
            data = s.recv(1024)
        except socket.error as msg:
            s.send("GET / HTTP/1.1\r\nHost: tuple_ip\r\n\r\n")
            try:
                data = s.recv(1024)
            except socket.error as msg:
                data = "NO DATA RECIEVED"
        s.close()
        print(('-'*70+'\n')+"From " + str(tuple_ip) +':'+str(port)+':\n'+str(data)+'\n'+('-'*70))

main()





























