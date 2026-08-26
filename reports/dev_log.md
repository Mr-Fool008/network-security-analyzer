# Network Security Analyzer - Engineering Log

## Project Overview
A lightweight Network Intrusion Detection System (NIDS) and packet analyzer built in Python, designed to apply core Data Structures & Algorithms (DSA) concepts to network security problems.

### Core References
- [Y6THAY/Network_Traffic_Analyzer](https://github.com/Y6THAY/Network_Traffic_Analyzer): Reference for architecture, traffic statistics, top-IP tracking, and dashboard reporting.
- [Tinshea/WireOwl](https://github.com/Tinshea/WireOwl): Reference for low-level packet breakdown, byte offsets, and protocol parsing.
- [pthevenet/Simple-NIDS](https://github.com/pthevenet/Simple-NIDS): Reference for rule-based signature detection logic.
- [ghouddan/SOC-PCAP-Analyzer](https://github.com/ghouddan/SOC-PCAP-Analyzer): Reference for offline PCAP hunting and scan detection.

---

## Milestone 1: Environment, Isolation & Version Control
- **Status:** Complete

### Implementation Details
- Established project directory structure: `src/`, `tests/`, `pcaps/`, `reports/`.
- Configured PowerShell execution policy to `RemoteSigned` for local virtual environment activation.
- Initialized virtual environment (`.venv`) and installed Scapy.
- Locked dependencies in `requirements.txt` and configured `.gitignore` to exclude `.venv/`, `__pycache__/`, and `.pcap` capture files.
- Initialized local Git repository, configured identity, and linked to remote GitHub origin.

---

## Milestone 2: Offline Packet Ingestion & Algorithmic Parsing
- **Status:** Complete

### Implementation Details
- Generated synthetic PCAP capture (`pcaps/sample.pcap`) simulating normal HTTP/DNS traffic alongside a multi-port horizontal scan.
- Parsed IP, TCP, and UDP layer headers via Scapy's `rdpcap`.
- Integrated core DSA structures for high-volume packet indexing:
  - **Hash Maps (`dict`):** Used for $O(1)$ average-time insertion and lookup to track IP and protocol packet frequencies.
  - **Hash Sets (`set`):** Used for $O(1)$ automatic de-duplication to track unique destination ports contacted by each source IP.
- Benchmarked complexity advantages of Hash Tables ($O(N)$ overall) versus linear list scanning ($O(N^2)$).

---

## Milestone 3: Modular Architecture & Threshold Detection
- **Status:** Complete

### Implementation Details
- Refactored monolithic prototype into modular components following the Single Responsibility Principle:
  - `src/parser.py` (`extract_packet_features`): Handles Layer 3/4 header extraction into standardized feature dictionaries.
  - `src/detector.py` (`IntrusionDetector`): Encapsulates detection state tables (Hash Maps/Sets) and threshold evaluation logic.
  - `src/main.py` (`main`): Pipeline orchestrator that coordinates PCAP loading, parsing loops, and alert rendering.
- Implemented **Port Scan Detection Rule**: Flags source IPs exceeding a configurable unique destination port threshold (`port_scan_threshold=5`).
- Verified rule execution against `pcaps/sample.pcap`: Successfully isolated scanner host `10.0.0.99` targeting 6 unique ports (`[21, 22, 23, 80, 443, 8080]`).