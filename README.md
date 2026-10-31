# CodeAlpha_NetworkSniffer

A basic network packet sniffer built with Python and scapy, created for the CodeAlpha Cyber Security internship (Task 1).

## Features
- Captures live network packets
- Shows source/destination IPs and ports, protocol (TCP, UDP, ICMP), and packet size
- Displays TCP flags, DNS queries, and payload previews
- BPF filtering (e.g. only HTTP or DNS traffic)
- Optional logging to a file

## Requirements
- Python 3
- scapy: `pip install scapy`
- Windows: Npcap (npcap.com)
- Run with administrator/root privileges

## Usage
```
python sniffer.py -c 20
python sniffer.py -f "udp port 53"
python sniffer.py -c 50 -o capture.log
```

## Sample Output
Most modern traffic (HTTPS, QUIC on port 443) is encrypted, so payloads appear as scrambled bytes while the packet metadata (IPs, ports, protocol, size) stays visible. Unencrypted traffic such as DNS shows readable content.

## What I Learned
How packets are structured in layers (IP, TCP/UDP, payload), how common protocols work, and how data flows through a network. I also saw first-hand why HTTPS protects the content of communications.

## Disclaimer
For educational use only. Capture traffic only on networks you own or have permission to monitor.
