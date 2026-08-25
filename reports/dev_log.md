# Network Security Analyzer - Engineering Log

## Project Scope & Architecture
- **Objective:** Build a lightweight Network Intrusion Detection System (NIDS) and packet analyzer in Python, emphasizing Data Structures & Algorithms (DSA).
- **Core References:**
  - Architecture & flow design: Y6THAY/Network_Traffic_Analyzer
  - Low-level packet parsing concepts: Tinshea/WireOwl

---

## Milestone 1: Environment & Workspace Setup
- **Date:** August 25, 2026
- **Status:** Complete

### Actions Taken
- Created project directory structure: `src/`, `tests/`, `pcaps/`, `reports/`.
- Configured PowerShell execution policy to `RemoteSigned` for local script execution.
- Initialized isolated Python virtual environment (`.venv`) and installed `scapy`.
- Generated `requirements.txt` and created `.gitignore` to exclude `.venv/`, caches, and PCAP captures.
- Verified base environment execution with `src/main.py`.

### Technical Decisions & Challenges
- **Virtual Environment Isolation:** Chose `.venv` to prevent dependency contamination with global packages.
- **Git Hygiene:** Excluded `pcaps/` from version control to prevent uploading sensitive traffic captures.
- **PowerShell Script Policy:** Resolved `PSSecurityException` using `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned`.

---

## Milestone 2: Offline Packet Ingestion & Parsing
- **Date:** In Progress
- **Status:** Active

### Planned Implementation
- Download safe, baseline HTTP PCAP sample for testing.
- Implement packet loader using Scapy's `rdpcap`.
- Extract network layer (IP) and transport layer (TCP/UDP) headers.
- Build frequency maps using hash tables (`dict`) for IP traffic tracking ($O(1)$ lookups).
- Build unique port sets (`set`) per source IP to detect scanning behavior.