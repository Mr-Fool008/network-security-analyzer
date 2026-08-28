# Network Security Analyzer & Algorithmic NIDS

A modular Network Intrusion Detection System (NIDS) and packet analyzer built from scratch in Python. Designed to combine low-level network packet analysis with core Data Structures & Algorithms (DSA) for efficient, real-time threat detection.

---

## 🛠️ Architecture & DSA Implementations

| Component | Applied Data Structure | Algorithmic Complexity | Security Purpose |
| :--- | :--- | :--- | :--- |
| **Packet Volume Tracking** | Hash Map (`dict`) | $O(1)$ lookup / update | Ingestion frequency per IP and protocol |
| **Port Scan Detection** | Hash Set (`set`) | $O(1)$ amortized insert | Tracks unique target port cardinality |
| **SYN Flood Detection** | Stateful State Table | $O(1)$ lookup / update | Measures isolated `SYN` to `ACK` flag ratios |
| **Rate Limit Limiter** | Double-Ended Queue (`deque`)| $O(1)$ push / popleft | Sliding time-window inter-arrival analysis |
| **Top-K Active Talkers** | Bounded Min-Heap (`heapq`) | $O(N \log K)$ time, $O(K)$ space | Ranks highest-volume endpoints efficiently |
| **Lateral Movement / C2** | Directed Graph (Adjacency List) | $O(1)$ edge insertion | Identifies fan-out pivots and star topologies |

---

## 🚀 Key Features
- **Dual-Mode Processing:** Supports both offline `.pcap` analysis and real-time live sniffing from network interface cards (NICs).
- **Automated Unit Testing:** Full `unittest` test suite covering detection rules, rate limiters, and heap ranking logic.
- **SIEM-Ready Logging:** Exports structured incident logs to `reports/alerts.json` (JSON-Lines) and traffic metrics to `reports/traffic_summary.csv`.

---

## 📂 Project Structure

```text
network-security-analyzer/
├── src/
│   ├── parser.py          # Layer 3/4 feature, flag, and timestamp extraction
│   ├── detector.py        # Core DSA state engine and anomaly rules
│   ├── capture.py         # Live NIC packet streaming using Scapy
│   ├── graph_analyzer.py  # Network adjacency graph & flow centrality
│   ├── logger.py          # SIEM JSON/CSV disk serialization
│   └── main.py            # CLI entry point and dashboard renderer
├── tests/
│   ├── __init__.py
│   └── test_detector.py   # Unit test suite
├── pcaps/
│   └── sample.pcap        # Synthetic attack & benign traffic captures
├── reports/
│   ├── dev_log.md         # Detailed milestone engineering logs
│   ├── alerts.json        # SIEM JSON-Lines alert output
│   └── traffic_summary.csv# Tabular metrics summary
├── generate_pcap.py       # Reproducible synthetic packet generator
└── requirements.txt       # Dependencies

---

## ⚡ Quickstart

### 1. Installation
```powershell
git clone [https://github.com/Mr-Fool008/network-security-analyzer.git](https://github.com/Mr-Fool008/network-security-analyzer.git)
cd network-security-analyzer
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
