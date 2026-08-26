from scapy.all import rdpcap, IP, TCP, UDP

def analyze_pcap(file_path):
    print(f"[*] Reading capture file: {file_path}")
    packets = rdpcap(file_path)
    print(f"[+] Loaded {len(packets)} total packets.\n")

    # DSA Ingestion Structures
    source_ip_counts = {}       # Hash Table (dict): IP -> packet count (O(1) lookups)
    protocol_counts = {}        # Hash Table (dict): Protocol -> packet count
    ip_to_dest_ports = {}       # Hash Table mapping IP -> Hash Set of unique ports (scan detection)

    for pkt in packets:
        if pkt.haslayer(IP):
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst

            # 1. Update Source IP frequency (Hash Map: O(1))
            source_ip_counts[src_ip] = source_ip_counts.get(src_ip, 0) + 1

            # 2. Extract Transport Layer & Unique Destination Ports
            if pkt.haslayer(TCP):
                proto = "TCP"
                dport = pkt[TCP].dport
            elif pkt.haslayer(UDP):
                proto = "UDP"
                dport = pkt[UDP].dport
            else:
                proto = "OTHER"
                dport = None

            # Update protocol frequency
            protocol_counts[proto] = protocol_counts.get(proto, 0) + 1

            # Update unique destination ports per source IP (Set: O(1))
            if dport is not None:
                if src_ip not in ip_to_dest_ports:
                    ip_to_dest_ports[src_ip] = set()
                ip_to_dest_ports[src_ip].add(dport)

    # Output Aggregated Statistics
    print("=== Protocol Distribution ===")
    for proto, count in protocol_counts.items():
        print(f"  {proto:<6}: {count} packets")

    print("\n=== Source IP & Unique Port Tracking ===")
    for ip, count in source_ip_counts.items():
        unique_ports = len(ip_to_dest_ports.get(ip, set()))
        print(f"  {ip:<15} -> {count:<4} packets | {unique_ports} unique target ports")

if __name__ == "__main__":
    analyze_pcap("pcaps/sample.pcap")