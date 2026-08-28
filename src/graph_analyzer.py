class NetworkGraph:
    def __init__(self):
        # Graph representation: Adjacency List
        # { source_ip: set(destination_ips) }
        self.adj_list = {}
        # In-degree tracking: { destination_ip: set(source_ips) }
        self.in_degree_map = {}

    def add_edge(self, src_ip: str, dst_ip: str):
        """Adds a directed communication edge (src -> dst) in O(1) time."""
        if not src_ip or not dst_ip:
            return

        # Update outgoing adjacency list
        if src_ip not in self.adj_list:
            self.adj_list[src_ip] = set()
        self.adj_list[src_ip].add(dst_ip)

        # Update incoming adjacency list (for in-degree analysis)
        if dst_ip not in self.in_degree_map:
            self.in_degree_map[dst_ip] = set()
        self.in_degree_map[dst_ip].add(src_ip)

    def get_out_degree(self, ip: str) -> int:
        """Returns the number of unique target IPs contacted by this host."""
        return len(self.adj_list.get(ip, set()))

    def get_in_degree(self, ip: str) -> int:
        """Returns the number of unique source IPs communicating with this host."""
        return len(self.in_degree_map.get(ip, set()))

    def detect_lateral_movement(self, fan_out_threshold=3):
        """
        Flags source hosts communicating with an abnormally large number of distinct endpoints.
        """
        anomalies = []
        for src_ip, destinations in self.adj_list.items():
            if len(destinations) >= fan_out_threshold:
                anomalies.append({
                    "type": "HIGH_FAN_OUT_LATERAL_MOVEMENT",
                    "source_ip": src_ip,
                    "target_count": len(destinations),
                    "destinations": sorted(list(destinations))
                })
        return anomalies

    def detect_c2_star_topology(self, fan_in_threshold=3):
        """
        Flags destination endpoints receiving traffic from many distinct internal hosts (Star Topology).
        """
        anomalies = []
        for dst_ip, sources in self.in_degree_map.items():
            if len(sources) >= fan_in_threshold:
                anomalies.append({
                    "type": "SUSPECTED_C2_STAR_TOPOLOGY",
                    "target_ip": dst_ip,
                    "source_count": len(sources),
                    "sources": sorted(list(sources))
                })
        return anomalies