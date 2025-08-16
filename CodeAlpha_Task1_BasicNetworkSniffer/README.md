# CodeAlpha — Task 1: Basic Network Sniffer

Build a Python program to capture and analyze network packets.

## Features
 Live capture using `scapy` (or fallback to raw sockets if scapy unavailable).
 Shows source/destination IPs, protocol, ports, and payload length.
 Optional write-out to PCAP and JSON Lines.
 Simple traffic analytics: top talkers, protocol counts.

## Setup
bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
sudo -E python sniffer.py --iface eth0 --count 100 --pcap out/sniff.pcap --json out/packets.jsonl
python analyzer.py --pcap out/sniff.pcap --json out/packets.jsonl
```

Note: Packet capture usually requires elevated privileges (e.g., `sudo`).

## Deliverables (for submission)
 Source code (this folder).
 Short demo video (screen capture) running the sniffer.
 GitHub repo name suggestion: `CodeAlpha_BasicNetworkSniffer`.
 Report: `report/Report.md` with screenshots and findings.

## LinkedIn Post Template
Just completed **Task 1 — Basic Network Sniffer** with live packet capture and analysis 
Key learnings: protocols, packet anatomy, traffic analytics.  
Repo: <your GitHub link>  
#CyberSecurity #Python #Scapy #CodeAlpha #Internship

