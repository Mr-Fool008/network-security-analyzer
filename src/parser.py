from scapy.all import IP, TCP, UDP

def extract_packet_features(pkt):
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

    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "proto": proto,
        "dport": dport,
        "tcp_flags": tcp_flags
    }