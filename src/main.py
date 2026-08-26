import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent))

from scapy.all import rdpcap
from parser import extract_packet_features
from detector import IntrusionDetector

def main():
    pcap_path = "pcaps/sample.pcap"
    print(f"[*] Ingesting: {pcap_path}")
    packets = rdpcap(pcap_path)
    print(f"[+] Loaded {len(packets)} packets.\n")

    detector = IntrusionDetector(port_scan_threshold=5, syn_flood_threshold=10)

    for pkt in packets:
        features = extract_packet_features(pkt)
        detector.process_packet(features)

    # 1. Traffic Breakdown
    print("=== Traffic Summary ===")
    for proto, count in detector.protocol_counts.items():
        print(f"  {proto:<6}: {count} packets")

    # 2. Top-K Talkers
    print("\n=== Top-K Active Talkers (Min-Heap O(N log K)) ===")
    top_talkers = detector.get_top_talkers(k=3)
    for rank, (count, ip) in enumerate(top_talkers, start=1):
        print(f"  #{rank}: {ip:<15} ({count} packets)")

    # 3. Security Alerts
    print("\n=== Security Alerts ===")
    all_alerts = detector.detect_port_scans() + detector.detect_syn_floods()
    if not all_alerts:
        print("  [✓] No anomalies detected.")
    else:
        for alert in all_alerts:
            print(f"  [!] ALERT: {alert['type']}")
            print(f"      Source IP: {alert['source_ip']}")
            print(f"      Details  : {alert['details']}\n")

if __name__ == "__main__":
    main()