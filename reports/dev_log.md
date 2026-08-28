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

## Milestone 4: Priority Ranking via Min-Heap ($O(N \log K)$)
- **Status:** Complete

### Implementation Details
- Integrated Python's standard `heapq` module within `IntrusionDetector.get_top_talkers()`.
- Implemented a Min-Heap of bounded size $K=3$ to track the highest-volume active hosts.
- Algorithmic Advantage:
  - **Min-Heap Approach:** $O(N \log K)$ time complexity and $O(K)$ auxiliary space (where $N$ is unique hosts).
  - **Full Sort Approach:** $O(N \log N)$ time and $O(N)$ space.
  - Optimizes memory and CPU runtime when analyzing high-cardinality captures.

### Output Verification
- Identified Top 3 active hosts:
  1. `10.0.0.99` (6 packets)
  2. `192.168.1.50` (2 packets)
  3. `93.184.216.34` (1 packet)
- Port scan detection alert successfully triggered for `10.0.0.99` targeting 6 unique ports.

## Milestone 5: TCP Flag Analysis & SYN Flood Detection
- **Status:** Complete

### Implementation Details
- Extended `src/parser.py` to extract TCP control flags (`flags`) from transport headers.
- Enhanced `IntrusionDetector` with an IP-to-flag state table (`self.ip_tcp_flags`) tracking raw `SYN` requests vs completed `ACK` responses in $O(1)$ time.
- Implemented **SYN Flood Detection Rule**:
  - Triggers when `SYN >= syn_flood_threshold` (10) and `SYN > ACK * 3`.
  - Simulates detection of half-open denial-of-service attempts.

### Output Verification
- Ingested 25 synthetic packets across 4 hosts.
- Successfully flagged `172.16.0.44` sending 15 unacknowledged SYNs (`SYN_FLOOD_SUSPECTED`).
- Maintained Min-Heap top talker ranking with `172.16.0.44` at #1 (15 pkts) and `10.0.0.99` at #2 (6 pkts).

## Milestone 6: Sliding Window Rate Limiting via Queues (`deque`)
- **Status:** Complete

### Implementation Details
- Extended `src/parser.py` to extract packet timestamps (`pkt.time`).
- Integrated double-ended queues (`collections.deque`) in `IntrusionDetector.ip_timestamps` to implement a moving time-window rate limiter.
- Algorithmic Mechanics:
  - Appends arrival timestamps to the right ($O(1)$).
  - Evicts stale timestamps exceeding the window duration (`burst_window_seconds = 2.0`) from the left ($O(1)$ amortized).
  - Triggers `RATE_LIMIT_BURST_EXCEEDED` if window cardinality $\ge$ `burst_threshold` (5 packets).

### Output Verification
- Simulated spaced traffic for benign host `192.168.1.50` and scanner `10.0.0.99` (no rate limit alerts).
- Triggered three distinct detection vectors for malicious traffic:
  - `PORT_SCAN_DETECTED` on `10.0.0.99` (6 target ports).
  - `SYN_FLOOD_SUSPECTED` on `172.16.0.44` (15 unacknowledged SYNs).
  - `RATE_LIMIT_BURST_EXCEEDED` on `172.16.0.44` (15 packets within 2.0s window).


## Milestone 7: Automated Unit Testing (`unittest`)
- **Status:** Complete

### Implementation Details
- Built automated test suite in `tests/test_detector.py` using Python's standard `unittest` framework.
- Decoupled testing logic from real PCAP capture files by feeding mock packet dictionaries directly into `IntrusionDetector`.
- Test Coverage:
  1. `test_port_scan_detection`: Validates Set cardinality thresholding on unique target ports.
  2. `test_syn_flood_detection`: Validates flag imbalance tracking (isolated `SYN` ratio vs `ACK`).
  3. `test_sliding_window_burst_detection`: Validates inter-arrival time eviction in `collections.deque`.
  4. `test_top_talkers_min_heap`: Validates bounded Min-Heap ordering and frequency ranking.

### Test Execution
- Executed via `python -m unittest discover tests`.
- Result: 4 tests passed (`OK`) in 0.001s.

## Milestone 8: Live Packet Capture & Real-Time Ingestion
- **Status:** Complete

### Implementation Details
- Built `src/capture.py` (`LivePacketCapture`) using Scapy's `sniff()` with non-buffering execution (`store=False`) to stream live NIC traffic without RAM bloat.
- Integrated `argparse` in `src/main.py` allowing dual-mode execution (`--mode offline` vs `--mode live`).
- Connected live packet callback directly to the DSA pipeline (Layer feature extraction $\rightarrow$ Hash Map/Set/Deque state updates $\rightarrow$ real-time anomaly detection).

### Live Verification
- Captured 82 live network packets (50 TCP, 32 UDP) across real network interfaces.
- Successfully ranked active endpoints using the Min-Heap engine:
  1. `10.128.254.222` (40 pkts - Local Interface)
  2. `142.251.156.4` (13 pkts - Google Cloud/Web)
  3. `13.89.179.12` (5 pkts - Microsoft Azure)
- Real-time sliding window deque correctly flagged active web-traffic bursts.