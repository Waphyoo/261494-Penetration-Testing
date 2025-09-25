from scapy.all import sniff, IP, TCP, UDP, ICMP

def process_packet(pkt): 
    if pkt.haslayer(IP): 
        ip = pkt [IP] 
        print("IP: {} --> {}".format(ip.src, ip.dst))

    if pkt.haslayer(TCP): 
        cp = pkt [TCP] 
        print(" TCP port: {} --> {}".format(tcp.sport, tcp.dport))

    elif pkt.haslayer(UDP): 
        udp = pkt [UDP] 
        print(" UDP port: {} --> {}".format(udp.sport, udp.dport))

    elif pkt.haslayer(ICMP): 
        icmp = pkt [ICMP] 
        print(" ICMP type: {}".format(icmp.type))

    else:print(" Other protocol")

sniff(iface='eth0', filter='ip', prn=process_packet)