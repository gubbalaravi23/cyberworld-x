# CYBERWORLD-X Network Telemetry Datasets

## Overview
This directory stores network traffic datasets for time-series attack progression forecasting.

### Included Datasets:
1. `sample_network_traffic.csv`:
   - **Type**: Controlled Synthetic Network Flow Telemetry (DEMO DATA).
   - **Purpose**: Demonstrates the temporal transition pipeline $S(t) \to S(t+1) \dots \to S(t+K)$ without requiring live PCAP capture or sensitive infrastructure logs.
   - **Progression Simulated**: Normal Baseline $\to$ Port Scanning (Reconnaissance) $\to$ Web Exploit (Initial Access) $\to$ SMB/RDP Pivoting (Lateral Movement) $\to$ Beaconing (Command & Control) $\to$ High-Volume Egress (Exfiltration).
   - **Label**: Explicitly tagged with `is_demo=True`.

### Supported Formats for User Uploads:
- **CSV Flow Records**: Supporting flow metadata (Source/Destination IP, Ports, Protocol, Bytes, Packets, TCP Flags, Duration, IAT).
- **PCAP / PCAPNG**: Raw packet captures parsed securely locally using Scapy / PyShark. Payloads are stripped, retaining only flow metadata and timing statistics.
