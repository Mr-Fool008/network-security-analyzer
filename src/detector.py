import heapq

class IntrusionDetector:
    def __init__(self, port_scan_threshold=5, syn_flood_threshold=10):
        self.port_scan_threshold = port_scan_threshold
        self.syn_flood_threshold = syn_flood_threshold

        # DSA State Tables
        self.ip_to_dest_ports = {}     # Hash Map (IP -> Set of unique ports)
        self.source_ip_counts = {}     # Hash Map (IP -> packet count)
        self.protocol_counts = {}      # Hash Map (Proto -> packet count)
        self.ip_tcp_flags = {}         # Hash Map (IP -> {"SYN": int, "ACK": int})

    def process_packet(self, feature_dict):
        """Ingests a packet feature dictionary and updates state tables."""
        if not feature_dict:
            return

        src_ip = feature_dict["src_ip"]
        proto = feature_dict["proto"]
        dport = feature_dict["dport"]
        flags = feature_dict.get("tcp_flags")

        # 1. Frequency Updates (O(1))
        self.source_ip_counts[src_ip] = self.source_ip_counts.get(src_ip, 0) + 1
        self.protocol_counts[proto] = self.protocol_counts.get(proto, 0) + 1

        # 2. Port Scan Tracking (O(1))
        if dport is not None:
            if src_ip not in self.ip_to_dest_ports:
                self.ip_to_dest_ports[src_ip] = set()
            self.ip_to_dest_ports[src_ip].add(dport)

        # 3. TCP Flag Tracking (O(1))
        if proto == "TCP" and flags:
            if src_ip not in self.ip_tcp_flags:
                self.ip_tcp_flags[src_ip] = {"SYN": 0, "ACK": 0}
            
            # Isolated SYN without ACK flag
            if "S" in flags and "A" not in flags:
                self.ip_tcp_flags[src_ip]["SYN"] += 1
            if "A" in flags:
                self.ip_tcp_flags[src_ip]["ACK"] += 1

    def detect_port_scans(self):
        """Flags IPs exceeding unique port cardinality threshold."""
        alerts = []
        for ip, ports in self.ip_to_dest_ports.items():
            if len(ports) >= self.port_scan_threshold:
                alerts.append({
                    "type": "PORT_SCAN_DETECTED",
                    "source_ip": ip,
                    "details": f"Hit {len(ports)} unique ports: {sorted(list(ports))}"
                })
        return alerts

    def detect_syn_floods(self):
        """
        Flags IPs with a high volume of unacknowledged SYN packets.
        Triggered when SYN count >= threshold and SYN-to-ACK ratio is disproportionate.
        """
        alerts = []
        for ip, counts in self.ip_tcp_flags.items():
            syn_count = counts["SYN"]
            ack_count = counts["ACK"]

            if syn_count >= self.syn_flood_threshold and syn_count > (ack_count * 3):
                alerts.append({
                    "type": "SYN_FLOOD_SUSPECTED",
                    "source_ip": ip,
                    "details": f"Sent {syn_count} SYNs with only {ack_count} ACKs"
                })
        return alerts

    def get_top_talkers(self, k=3):
        """Min-Heap Top-K implementation in O(N log K) time."""
        min_heap = []
        for ip, count in self.source_ip_counts.items():
            if len(min_heap) < k:
                heapq.heappush(min_heap, (count, ip))
            else:
                if count > min_heap[0][0]:
                    heapq.heappushpop(min_heap, (count, ip))
        return sorted(min_heap, key=lambda x: x[0], reverse=True)