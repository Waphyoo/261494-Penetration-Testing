from scapy.all import *
import time

# target_IP = input("ping target IP : ")

# print(f"PING {target_IP}")
for i in range(4):  # ping 4 ครั้ง
    pkt = IP(dst="127.0.0.1")/ICMP(seq=i)
    start_time = time.time()
    
    reply = sr1(pkt, timeout=2, verbose=0)
    end_time = time.time()
    # pkt.show()  # show the packet details
    # reply.show()  # show the reply packet details if any
    
    if reply:
        rtt = (end_time - start_time) * 1000  # convert to ms
        print(f"Reply from {reply.src}: icmp_seq={i} time={rtt}ms TTL={reply.ttl}")
    else:
        print("Request timed out")
    
    time.sleep(1)  # wait for 1 second before the next ping
 # show the packet details    