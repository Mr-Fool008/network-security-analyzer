from scapy.all import wrpcap, Ether, IP, TCP, UDP

packets = [
    # 1. Benign Traffic
    Ether() / IP(src="192.168.1.50", dst="93.184.216.34") / TCP(sport=49152, dport=80, flags="S"),
    Ether() / IP(src="93.184.216.34", dst="192.168.1.50") / TCP(sport=80, dport=49152, flags="SA"),
    Ether() / IP(src="192.168.1.50", dst="93.184.216.34") / TCP(sport=49152, dport=80, flags="A"),
    Ether() / IP(src="192.168.1.50", dst="8.8.8.8") / UDP(sport=53535, dport=53),
]

# 2. Port Scan Simulation (10.0.0.99 hitting 6 unique ports)
for port in [21, 22, 23, 80, 443, 8080]:
    packets.append(
        Ether() / IP(src="10.0.0.99", dst="192.168.1.1") / TCP(sport=50000 + port, dport=port, flags="S")
    )

# 3. SYN Flood Simulation (172.16.0.44 sending 15 unacknowledged SYNs)
for i in range(15):
    packets.append(
        Ether() / IP(src="172.16.0.44", dst="192.168.1.10") / TCP(sport=40000 + i, dport=80, flags="S")
    )

wrpcap("pcaps/sample.pcap", packets)
print(f"[+] Successfully generated pcaps/sample.pcap with {len(packets)} packets.")