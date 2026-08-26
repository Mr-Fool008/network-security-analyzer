import unittest
import sys
from pathlib import Path

# Add src/ to the module lookup path
sys.path.append(str(Path(__file__).resolve().parent.parent / "src"))

from detector import IntrusionDetector

class TestIntrusionDetector(unittest.TestCase):

    def setUp(self):
        """Initializes a fresh detector before every test case."""
        self.detector = IntrusionDetector(
            port_scan_threshold=3,
            syn_flood_threshold=5,
            burst_threshold=3,
            burst_window_seconds=2.0
        )

    def test_port_scan_detection(self):
        """Tests if an IP targeting >= 3 distinct ports triggers an alert."""
        scanner_ip = "10.0.0.99"
        
        # Simulate packets hitting 3 different ports
        for port in [21, 22, 80]:
            self.detector.process_packet({
                "src_ip": scanner_ip,
                "dst_ip": "192.168.1.1",
                "proto": "TCP",
                "dport": port,
                "tcp_flags": "S",
                "timestamp": 1000.0
            })

        alerts = self.detector.detect_port_scans()
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["source_ip"], scanner_ip)
        self.assertEqual(alerts[0]["type"], "PORT_SCAN_DETECTED")

    def test_syn_flood_detection(self):
        """Tests if sending >= 5 unacknowledged SYNs triggers a flood alert."""
        flooder_ip = "172.16.0.44"

        # Simulate 6 SYN packets with 0 ACKs
        for _ in range(6):
            self.detector.process_packet({
                "src_ip": flooder_ip,
                "dst_ip": "192.168.1.1",
                "proto": "TCP",
                "dport": 80,
                "tcp_flags": "S",
                "timestamp": 1000.0
            })

        alerts = self.detector.detect_syn_floods()
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["source_ip"], flooder_ip)
        self.assertEqual(alerts[0]["type"], "SYN_FLOOD_SUSPECTED")

    def test_sliding_window_burst_detection(self):
        """Tests if sending >= 3 packets within 2 seconds triggers rate limit."""
        spammer_ip = "192.168.1.200"

        # Simulate 3 packets arriving 0.1s apart
        for i in range(3):
            self.detector.process_packet({
                "src_ip": spammer_ip,
                "dst_ip": "192.168.1.1",
                "proto": "UDP",
                "dport": 53,
                "tcp_flags": None,
                "timestamp": 1000.0 + (i * 0.1)
            })

        alerts = self.detector.detect_traffic_bursts()
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["source_ip"], spammer_ip)
        self.assertEqual(alerts[0]["type"], "RATE_LIMIT_BURST_EXCEEDED")

    def test_top_talkers_min_heap(self):
        """Tests that the Min-Heap accurately sorts top hosts by volume."""
        # Feed 10 packets for Host A, 5 for Host B, 1 for Host C
        for _ in range(10):
            self.detector.process_packet({"src_ip": "1.1.1.1", "dst_ip": "0.0.0.0", "proto": "TCP", "dport": 80})
        for _ in range(5):
            self.detector.process_packet({"src_ip": "2.2.2.2", "dst_ip": "0.0.0.0", "proto": "TCP", "dport": 80})
        for _ in range(1):
            self.detector.process_packet({"src_ip": "3.3.3.3", "dst_ip": "0.0.0.0", "proto": "TCP", "dport": 80})

        top_2 = self.detector.get_top_talkers(k=2)
        self.assertEqual(len(top_2), 2)
        self.assertEqual(top_2[0], (10, "1.1.1.1"))
        self.assertEqual(top_2[1], (5, "2.2.2.2"))

if __name__ == "__main__":
    unittest.main()
    