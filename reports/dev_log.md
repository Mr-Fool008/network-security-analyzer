Open reports/dev_log.md in VS Code and update it with these comprehensive notes detailing both setup and technical decisions:

Markdown
# Network Security Analyzer - Engineering Log & Architecture Notes

## Project Overview
A lightweight Network Intrusion Detection System (NIDS) and packet analyzer built in Python, prioritizing core Data Structures & Algorithms (DSA) efficiency over simple black-box library calls.

### Core References
- [Y6THAY/Network_Traffic_Analyzer](https://github.com/Y6THAY/Network_Traffic_Analyzer): Reference for overall architecture, flow tracking, multi-threading, and stats dashboards.
- [Tinshea/WireOwl](https://github.com/Tinshea/WireOwl): Reference for low-level packet structure and byte-level protocol parsing.

---

## Milestone 1: Environment, Isolation & Version Control

### 1. Project Directory Structure
```text
network-security-analyzer/
├── .venv/               # Isolated Python virtual environment
├── src/                 # Core engine and detection logic
├── tests/               # Unit tests for parsers and detection rules
├── pcaps/               # Packet capture test files
├── reports/             # Developer logs, benchmarks, and project documentation
├── .gitignore           # Git ignore configuration
├── README.md            # Public documentation & architecture overview
└── requirements.txt     # Locked project dependencies
2. Environment Setup & Tooling
Virtual Environment (.venv): Isolates Scapy and supporting dependencies from global system packages.

PowerShell Execution Policy: Set via Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned to enable script execution for virtual environments.

Git & GitHub: Initialized locally and linked to remote GitHub repository for incremental commit tracking and portfolio proof.

.gitignore Configuration: Excluded .venv/, __pycache__/, and .pcap capture files to prevent repo bloat and protect sensitive network payload data.

Milestone 2: Offline Packet Ingestion & Algorithmic Parsing
1. Packet Processing Concepts
A network packet contains nested encapsulation layers:

Layer 2 (Ethernet): Hardware MAC routing.

Layer 3 (IP): Source and destination host addresses (src, dst).

Layer 4 (TCP/UDP): Transport protocols and target service ports (sport, dport).

2. DSA Architecture Decisions
Real-world network monitoring processes high packet volumes where naive linear searches fail:

Hash Map / Dictionary (source_ip_counts):

Purpose: Tracks packet volume per source IP.

Complexity: O(1) average-time insertion and lookup.

Why it matters: Maintains constant speed regardless of total packets captured.

Hash Set (ip_to_dest_ports):

Purpose: Maps each source IP to a set of unique destination ports.

Complexity: O(1) insertion and automatic de-duplication.

Why it matters: Differentiates normal high-volume traffic (e.g., 500 packets to port 443 → set size = 1) from horizontal port scans (e.g., 6 packets to 6 unique ports → set size = 6).

Approach	1,000 Packets	1,000,000 Packets
Naive Lists (O(N 
2
 ))	~1,000,000 ops (~0.05s)	~1,000,000,000,000 ops (High latency / Crash)
Hash Map + Set (O(N) total)	~1,000 ops (< 0.001s)	~1,000,000 ops (< 0.5s)
3. Verification & Results
Synthetic capture (pcaps/sample.pcap) verified:

Normal client traffic: 192.168.1.50 (2 packets across 2 distinct ports).

Scanner detection: 10.0.0.99 targeting 6 unique ports ([21, 22, 23, 80, 443, 8080]).

