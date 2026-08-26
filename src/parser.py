from scapy.all import IP, TCP, UDP

def extract_packet_features(pkt):
    """
    Extracts Layer 3 and Layer 4 metadata from a Scapy packet.
    Returns a dict with src_ip, dst_ip, proto, and dport, or None if non-IP.
    """
    if not pkt.haslayer(IP):
        return None

    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst

    if pkt.haslayer(TCP):
        proto = "TCP"
        dport = pkt[TCP].dport
    elif pkt.haslayer(UDP):
        proto = "UDP"
        dport = pkt[UDP].dport
    else:
        proto = "OTHER"
        dport = None

    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "proto": proto,
        "dport": dport
    }