from scapy.all import *

pkt = sniff(iface='lo', filter="icmp")

pkt.summary()
pkt.show()