from scapy.all import IP, TCP, UDP
import time

def extract_packet_features(pkt):
    """
    Extracts Layer 3 and Layer 4 metadata, TCP flags, and timestamp.
    """
    if not pkt.haslayer(IP):
        return None

    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    tcp_flags = None

    if pkt.haslayer(TCP):
        proto = "TCP"
        dport = pkt[TCP].dport
        tcp_flags = str(pkt[TCP].flags)
    elif pkt.haslayer(UDP):
        proto = "UDP"
        dport = pkt[UDP].dport
    else:
        proto = "OTHER"
        dport = None

    # Extract Scapy packet timestamp or fall back to current epoch time
    timestamp = float(pkt.time) if hasattr(pkt, "time") and pkt.time is not None else time.time()

    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "proto": proto,
        "dport": dport,
        "tcp_flags": tcp_flags,
        "timestamp": timestamp
    }