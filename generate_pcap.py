import time
from scapy.all import wrpcap, Ether, IP, TCP, UDP

base_time = time.time()
packets = []

# 1. Benign Traffic (spaced 10 seconds apart -> should NOT trigger burst alert)
packets.append(Ether() / IP(src="192.168.1.50", dst="93.184.216.34") / TCP(sport=49152, dport=80, flags="S"))
packets[-1].time = base_time

packets.append(Ether() / IP(src="93.184.216.34", dst="192.168.1.50") / TCP(sport=80, dport=49152, flags="SA"))
packets[-1].time = base_time + 10

packets.append(Ether() / IP(src="192.168.1.50", dst="93.184.216.34") / TCP(sport=49152, dport=80, flags="A"))
packets[-1].time = base_time + 20

packets.append(Ether() / IP(src="192.168.1.50", dst="8.8.8.8") / UDP(sport=53535, dport=53))
packets[-1].time = base_time + 30

# 2. Port Scan Simulation (10.0.0.99 spaced out)
for idx, port in enumerate([21, 22, 23, 80, 443, 8080]):
    pkt = Ether() / IP(src="10.0.0.99", dst="192.168.1.1") / TCP(sport=50000 + port, dport=port, flags="S")
    pkt.time = base_time + (idx * 5)
    packets.append(pkt)

# 3. SYN Flood & Rate Limit Burst Simulation (172.16.0.44 blasting 15 packets within 0.5 seconds)
for i in range(15):
    pkt = Ether() / IP(src="172.16.0.44", dst="192.168.1.10") / TCP(sport=40000 + i, dport=80, flags="S")
    pkt.time = base_time + 50 + (i * 0.03)  # Rapid arrival burst
    packets.append(pkt)

wrpcap("pcaps/sample.pcap", packets)
print(f"[+] Successfully generated pcaps/sample.pcap with {len(packets)} packets.")