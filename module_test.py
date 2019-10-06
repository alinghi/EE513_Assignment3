#!/usr/local/bin/python
# PacketInside.com - Scapy Example
import sys
import time
import random
from scapy.all import *

if len(sys.argv) < 2 or "-h" in sys.argv[1]:
    print("Usage: ./module_test.py <ifname> <num>")
    sys.exit(1)


LH = '127.0.0.1'
num = int(sys.argv[2])
if num == 1:
    pkt = Ether() / IP(src=str(LH), dst=str("192.168.1.128")) / TCP(sport=12345, dport=12345) / 'r1'
    sendp(pkt, iface = sys.argv[1])
elif num == 2:
    pkt = Ether() / IP(src=str(LH)) / TCP(dport=25) / 'r2'
    sendp(pkt, iface = sys.argv[1])
elif num == 3:
    pkt = Ether() / IP(src=str(LH), dst=str(LH)) / UDP(dport=12345) / 'r3'
    sendp(pkt, iface = sys.argv[1])
elif num == 4:
    pkt = Ether() / IP(src=str(LH), dst=str(LH), tos=33) / UDP(dport=9999) / 'r4'
    sendp(pkt, iface = sys.argv[1])
elif num == 5:
    pkt = Ether() / IP(src=str(LH), dst=str(LH), ihl=6L, options='\x83\x03\x10') / TCP(dport=8888) / 'r5'
    sendp(pkt, iface = sys.argv[1])
elif num == 6:
    pkt = Ether() / IP(src=str(LH), dst=str(LH), frag=111) / TCP(dport=8888) / 'r6'
    sendp(pkt, iface = sys.argv[1])
elif num == 7:
    pkt = Ether() / IP(src=str(LH)) / TCP(dport=7777, seq=5) / 'r7'
    sendp(pkt, iface = sys.argv[1])
elif num == 8:
    pkt = Ether() / IP(src=str(LH)) / TCP(dport=6666, ack=6) / 'r8'
    sendp(pkt, iface = sys.argv[1])
elif num == 9:
    pkt = Ether() / IP(src=str(LH)) / TCP(dport=6666, flags="SP", ack=111) / 'r9'
    sendp(pkt, iface = sys.argv[1])
elif num == 10:
    pkt = Ether() / IP(src=str(LH)) / TCP(dport=80) / "GET / HTTP/1.0\r\nHOST: 192.168.56.107\r\n\r\n r10"
    sendp(pkt, iface = sys.argv[1])
elif num == 11:
    pkt = Ether() / IP(src=str(LH)) / TCP(dport=22) / "/bin/sh r11"
    sendp(pkt, iface = sys.argv[1])
elif num == 12:
    pkt = Ether() / IP(src=str(LH), tos=123, frag=222) / TCP(dport=30000, seq=15, ack=16) / "r12"
    sendp(pkt, iface = sys.argv[1])
elif num == 13:
    pkt = Ether() / IP(src=str("143.248.57.246"), dst=str("8.8.8.8")) / UDP(dport=53) / "www.naver.com \r\n r13"
    sendp(pkt, iface = sys.argv[1])
elif num == 14:
    pkt = Ether() / IP(src=str(LH), dst=str("143.248.5.153")) / TCP(dport=80) / "GET / HTTP/1.0\r\n\r\n www.kaist.ac.kr r14"
    sendp(pkt, iface = sys.argv[1]) 
else: 
    pkt = Ether() / IP(src=str("143.248.56.125"), dst=str("143.248.12.34")) / TCP(dport=23456) / "r15"
    sendp(pkt, iface = sys.argv[1])
