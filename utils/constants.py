"""
CYBERWORLD-X: Constants and Configuration Definitions
NTRO SIH 2026 | Problem Statement ID: 26153
"""

from typing import Dict, List, Tuple

# Project Metadata
PROJECT_NAME = "CYBERWORLD-X"
PROJECT_TITLE = "CYBERWORLD-X — AI-Based Network Attack Forecasting"
PROJECT_SUBTITLE = "Predict the next stage before the attack progresses."
ORGANIZATION = "National Technical Research Organisation (NTRO)"
PROBLEM_STATEMENT_ID = "26153"
THEME = "Blockchain & Cybersecurity"

# Attack Stages in Temporal Progression Order
ATTACK_STAGES: List[str] = [
    "Normal Activity",
    "Reconnaissance",
    "Initial Access",
    "Lateral Movement",
    "Command and Control",
    "Exfiltration",
]

STAGE_KEYS = {
    "NORMAL": "Normal Activity",
    "RECON": "Reconnaissance",
    "INITIAL_ACCESS": "Initial Access",
    "LATERAL_MOVEMENT": "Lateral Movement",
    "C2": "Command and Control",
    "EXFILTRATION": "Exfiltration",
}

STAGE_COLORS: Dict[str, str] = {
    "Normal Activity": "#10b981",       # Emerald Green
    "Reconnaissance": "#38bdf8",        # Cyan Blue
    "Initial Access": "#f59e0b",        # Amber
    "Lateral Movement": "#f97316",      # Vivid Orange
    "Command and Control": "#ec4899",   # Fuchsia
    "Exfiltration": "#ef4444",          # Crimson Red
}

STAGE_ICONS: Dict[str, str] = {
    "Normal Activity": "🛡️",
    "Reconnaissance": "🔍",
    "Initial Access": "🚪",
    "Lateral Movement": "🔀",
    "Command and Control": "📡",
    "Exfiltration": "📤",
}

STAGE_DESCRIPTIONS: Dict[str, str] = {
    "Normal Activity": "Routine operational traffic with baseline protocol distributions and low entropy.",
    "Reconnaissance": "Active scanning, host/service discovery, port probing, and asset identification.",
    "Initial Access": "Exploitation of public services, credential brute forcing, or unauthorized ingress attempts.",
    "Lateral Movement": "Internal pivoting via SMB, RDP, SSH, or administrative token reuse.",
    "Command and Control": "Periodic beaconing, outbound tunneling, domain generation algorithms, or encrypted channels.",
    "Exfiltration": "High-volume compressed data egress, unauthorized transfers over alternative ports/protocols.",
}

# Time Windows (in seconds)
TIME_WINDOWS: List[int] = [5, 10, 30, 60]
DEFAULT_TIME_WINDOW: int = 30

# Forecast Horizons (number of future time windows K)
FORECAST_HORIZONS: List[int] = [1, 3, 5, 8, 10]
DEFAULT_FORECAST_HORIZON: int = 5

# Sequence Lengths for Temporal AI Models
SEQUENCE_LENGTHS: List[int] = [5, 10, 15, 20]
DEFAULT_SEQUENCE_LENGTH: int = 10

# Risk Thresholds
RISK_THRESHOLD_NORMAL: float = 0.30
RISK_THRESHOLD_ELEVATED: float = 0.55
RISK_THRESHOLD_HIGH: float = 0.75

# Standard Feature Set for Network States S(t)
NETWORK_STATE_FEATURES: List[str] = [
    "packet_count",           # Total packets in time window
    "byte_count",             # Total volume in bytes
    "packet_rate",            # Packets per second
    "byte_rate",              # Bytes per second
    "syn_ratio",              # Ratio of SYN packets to total TCP
    "rst_ratio",              # Ratio of RST packets
    "unique_dst_ips",         # Number of unique destination IPs (spread/fan-out)
    "unique_dst_ports",       # Number of unique destination ports (port scanning)
    "avg_packet_size",        # Average payload/packet size
    "iat_mean",               # Inter-arrival time mean (seconds)
    "iat_std",                # Inter-arrival time variance/jitter
    "dns_query_count",        # DNS activity indicator
    "outbound_ratio",         # Ratio of egress to ingress volume
    "failed_conn_ratio",      # Ratio of unanswered or reset connections
]

# Standard CSV Mapping Dictionary for common field aliases
DEFAULT_COLUMN_ALIASES: Dict[str, List[str]] = {
    "src_ip": ["src_ip", "srcip", "source_ip", "ip_src", "src", "source"],
    "dst_ip": ["dst_ip", "dstip", "dest_ip", "ip_dst", "dst", "destination"],
    "src_port": ["src_port", "sport", "source_port", "srcport", "s_port"],
    "dst_port": ["dst_port", "dsport", "dest_port", "dstport", "d_port"],
    "protocol": ["protocol", "proto", "ip_proto", "trans_protocol"],
    "timestamp": ["timestamp", "time", "epoch", "datetime", "stime", "ltime"],
    "packets": ["packets", "packet_count", "spkts", "dpkts", "tot_pkts", "pkts"],
    "bytes": ["bytes", "byte_count", "sbytes", "dbytes", "tot_bytes", "size"],
    "duration": ["duration", "dur", "flow_duration", "elapsed_time"],
    "tcp_flags": ["tcp_flags", "flags", "state", "tcp_flag"],
    "ttl": ["ttl", "sttl", "dttl", "time_to_live"],
}

# Footer Notice
SYSTEM_FOOTER = (
    "Local-first prototype • Network metadata focused • "
    "Zero external cloud AI API dependencies • NTRO SIH 2026 Problem Statement 26153"
)
