import sys
from pathlib import Path

# Add src to system path
sys.path.append(str(Path(__file__).resolve().parent))

from scapy.all import sniff
from parser import extract_packet_features
from detector import IntrusionDetector

class LivePacketCapture:
    def __init__(self, detector: IntrusionDetector, interface=None, packet_count=0):
        """
        :param detector: Instance of IntrusionDetector to process live packets.
        :param interface: Specific network interface name (None uses default).
        :param packet_count: Number of packets to capture (0 = infinite / until Ctrl+C).
        """
        self.detector = detector
        self.interface = interface
        self.packet_count = packet_count

    def _packet_callback(self, pkt):
        """Callback invoked by Scapy for every captured packet."""
        features = extract_packet_features(pkt)
        if features:
            self.detector.process_packet(features)

            # Check for real-time alerts on the fly
            port_scan_alerts = self.detector.detect_port_scans()
            syn_flood_alerts = self.detector.detect_syn_floods()
            burst_alerts = self.detector.detect_traffic_bursts()

            all_alerts = port_scan_alerts + syn_flood_alerts + burst_alerts

            # Print inline notice if an alert triggers during capture
            for alert in all_alerts:
                print(f"\n[!] REAL-TIME ALERT: {alert['type']} from {alert['source_ip']}")
                print(f"    Details: {alert['details']}")

    def start(self):
        """Starts live packet sniffing."""
        print(f"[*] Starting live capture on interface: {self.interface or 'Default'}...")
        print("[*] Press Ctrl + C to stop capturing and view aggregate summary.\n")
        try:
            sniff(
                iface=self.interface,
                prn=self._packet_callback,
                store=False,  # Avoid memory bloat by not storing raw packets in RAM
                count=self.packet_count
            )
        except KeyboardInterrupt:
            print("\n[+] Live capture halted by user.")