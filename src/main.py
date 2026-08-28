import sys
import argparse
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent))

from scapy.all import rdpcap
from parser import extract_packet_features
from detector import IntrusionDetector
from capture import LivePacketCapture
from logger import SecurityLogger

def run_offline_analysis(pcap_path, detector):
    print(f"[*] Ingesting offline capture: {pcap_path}")
    packets = rdpcap(pcap_path)
    print(f"[+] Loaded {len(packets)} total packets.\n")

    for pkt in packets:
        features = extract_packet_features(pkt)
        detector.process_packet(features)

def print_dashboard(detector):
    print("\n" + "=" * 45)
    print("           TRAFFIC & SECURITY REPORT         ")
    print("=" * 45)

    # 1. Protocol Distribution
    print("\n--- Protocol Distribution ---")
    if not detector.protocol_counts:
        print("  No IP traffic recorded.")
    for proto, count in detector.protocol_counts.items():
        print(f"  {proto:<6}: {count} packets")

    # 2. Top-K Talkers (Min-Heap)
    print("\n--- Top-K Active Talkers (Min-Heap) ---")
    top_talkers = detector.get_top_talkers(k=3)
    if not top_talkers:
        print("  No hosts recorded.")
    for rank, (count, ip) in enumerate(top_talkers, start=1):
        print(f"  #{rank}: {ip:<15} ({count} packets)")

    # 3. Security Alerts
    print("\n--- Security Alerts ---")
    all_alerts = (
        detector.detect_port_scans()
        + detector.detect_syn_floods()
        + detector.detect_traffic_bursts()
        + detector.detect_graph_anomalies()
    )

    if not all_alerts:
        print("  [✓] No anomalies detected. Clean traffic.")
    else:
        for alert in all_alerts:
            print(f"  [!] ALERT: {alert['type']}")
            target = alert.get('source_ip') or alert.get('target_ip')
            print(f"      Host   : {target}")
            print(f"      Details: {alert.get('details')}\n")
    print("=" * 45 + "\n")

    # 4. SIEM Log Export
    logger = SecurityLogger()
    logger.log_alerts_json(all_alerts)
    logger.log_traffic_summary_csv(detector.protocol_counts, top_talkers)

def main():
    parser = argparse.ArgumentParser(description="Network Security Analyzer & NIDS")
    parser.add_argument("--mode", choices=["offline", "live"], default="offline", help="Operation mode")
    parser.add_argument("--pcap", default="pcaps/sample.pcap", help="Path to PCAP file")
    parser.add_argument("--count", type=int, default=0, help="Number of packets to sniff (live mode)")

    args = parser.parse_args()

    detector = IntrusionDetector(
        port_scan_threshold=5,
        syn_flood_threshold=10,
        burst_threshold=5,
        burst_window_seconds=2.0
    )

    if args.mode == "offline":
        run_offline_analysis(args.pcap, detector)
    elif args.mode == "live":
        live_cap = LivePacketCapture(detector, packet_count=args.count)
        live_cap.start()

    print_dashboard(detector)

if __name__ == "__main__":
    main()