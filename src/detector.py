import heapq

class IntrusionDetector:
    def __init__(self, port_scan_threshold=5):
        self.port_scan_threshold = port_scan_threshold
        # DSA Structures
        self.ip_to_dest_ports = {}  # Hash Map (IP -> Set of unique ports)
        self.source_ip_counts = {}  # Hash Map (IP -> packet count)
        self.protocol_counts = {}   # Hash Map (Proto -> packet count)

    def process_packet(self, feature_dict):
        """Ingests a packet feature dictionary and updates state tables."""
        if not feature_dict:
            return

        src_ip = feature_dict["src_ip"]
        proto = feature_dict["proto"]
        dport = feature_dict["dport"]

        # O(1) Frequency Updates
        self.source_ip_counts[src_ip] = self.source_ip_counts.get(src_ip, 0) + 1
        self.protocol_counts[proto] = self.protocol_counts.get(proto, 0) + 1

        # O(1) Unique Port Tracking
        if dport is not None:
            if src_ip not in self.ip_to_dest_ports:
                self.ip_to_dest_ports[src_ip] = set()
            self.ip_to_dest_ports[src_ip].add(dport)

    def detect_port_scans(self):
        """Flags IPs whose unique destination port set cardinality exceeds threshold."""
        alerts = []
        for ip, ports in self.ip_to_dest_ports.items():
            if len(ports) >= self.port_scan_threshold:
                alerts.append({
                    "type": "PORT_SCAN_DETECTED",
                    "source_ip": ip,
                    "unique_port_count": len(ports),
                    "targeted_ports": sorted(list(ports))
                })
        return alerts

    def get_top_talkers(self, k=3):
        """
        Uses a Min-Heap of size K to find the top K most active IPs.
        Time Complexity: O(N log K) where N is unique IPs.
        Space Complexity: O(K) auxiliary space.
        """
        min_heap = []  # Elements stored as: (packet_count, ip)

        for ip, count in self.source_ip_counts.items():
            if len(min_heap) < k:
                heapq.heappush(min_heap, (count, ip))
            else:
                # If current IP has more packets than the smallest in the heap, replace it
                if count > min_heap[0][0]:
                    heapq.heappushpop(min_heap, (count, ip))

        # Return sorted descending (highest talker first)
        return sorted(min_heap, key=lambda x: x[0], reverse=True)