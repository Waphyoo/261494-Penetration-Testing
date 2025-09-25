#!/usr/bin/env python3
from scapy.all import *
import time

# ข้อมูลพื้นฐาน
ID = 1000
dst_ip = "127.0.0.1"
src_ip = "127.0.0.1"

# Fragment 1: UDP header + first part of payload
ip1 = IP(dst=dst_ip, src=src_ip, id=ID, frag=0, flags=1)
udp1 = UDP(sport=7070, dport=9090, chksum=0, len=100)  # ← เปลี่ยนเป็น 100
payload1 = "A" * 31 + "\n"
pkt1 = ip1/udp1/payload1

# Fragment 2: middle part
ip2 = IP(dst=dst_ip, src=src_ip, id=ID, frag=5, flags=1, proto=17)
payload2 = "B" * 39 + "\n"
pkt2 = ip2/payload2

# Fragment 3: last part  
ip3 = IP(dst=dst_ip, src=src_ip, id=ID, frag=10, flags=0, proto=17)
payload3 = "C" * 19 + "\n"
pkt3 = ip3/payload3

send(pkt1)
send(pkt2)
send(pkt3)
time.sleep(5)