"""
CYBERWORLD-X: Sample & Demo Network Telemetry Generator
NTRO SIH 2026 | Problem Statement ID: 26153

Generates realistic sequential network traffic flows demonstrating temporal attack progression:
Normal Routine Activity -> Port & Service Scanning (Reconnaissance) ->
Exploitation / Brute Force (Initial Access) -> Internal Pivoting / SMB (Lateral Movement) ->
Beaconing (C2) -> Outbound Data Transfer (Exfiltration).

ALL synthetic records are explicitly tagged as DEMO DATA.
"""

import os
from datetime import datetime, timedelta
from typing import Optional
import numpy as np
import pandas as pd


def generate_synthetic_network_traffic(
    num_flows: int = 1200,
    start_time: Optional[datetime] = None,
    save_path: Optional[str] = None
) -> pd.DataFrame:
    """
    Generates a controlled synthetic time-series dataset of network flows simulating
    an enterprise network under multi-stage cyber assault.
    
    Returns:
        pd.DataFrame with realistic network flow attributes.
    """
    if start_time is None:
        start_time = datetime.now() - timedelta(minutes=40)

    np.random.seed(42)  # For deterministic reproducibility in demo mode

    records = []
    current_time = start_time

    # Enterprise subnet IPs
    internal_workstations = [f"192.168.10.{i}" for i in range(10, 60)]
    internal_servers = ["192.168.1.10", "192.168.1.15", "192.168.1.20", "192.168.1.50"]
    gateway_ip = "192.168.1.1"
    external_adversary_ip = "198.51.100.44"
    c2_server_ip = "203.0.113.89"
    external_normal_ips = ["142.250.190.46", "157.240.22.35", "104.16.132.229"]

    # Partition the flows across temporal phases:
    # Phase 1 (0 to 300): Normal baseline operations
    # Phase 2 (300 to 550): Reconnaissance (External scanning, SYN sweep)
    # Phase 3 (550 to 750): Initial Access (Brute force & exploit attempts on DMZ server)
    # Phase 4 (750 to 950): Lateral Movement (Internal probing, SMB 445 / RDP 3389)
    # Phase 5 (950 to 1100): Command and Control (Periodic beaconing on 443/8443)
    # Phase 6 (1100 to 1200): Exfiltration (Large outbound payloads)

    for i in range(num_flows):
        # Time increment (avg 1-3 seconds between flows)
        current_time += timedelta(milliseconds=float(np.random.exponential(scale=1800)))

        if i < 300:
            # PHASE 1: Normal Baseline
            stage = "Normal Activity"
            src_ip = np.random.choice(internal_workstations)
            dst_ip = np.random.choice(external_normal_ips + internal_servers)
            proto = np.random.choice(["TCP", "UDP"], p=[0.85, 0.15])
            if proto == "TCP":
                dst_port = np.random.choice([80, 443, 8080, 53])
                tcp_flags = np.random.choice(["SYN,ACK,PSH", "ACK", "SYN,ACK"], p=[0.7, 0.2, 0.1])
            else:
                dst_port = 53
                tcp_flags = "-"
            src_port = int(np.random.randint(49152, 65535))
            duration = float(np.random.uniform(0.1, 4.5))
            packets = int(np.random.randint(4, 45))
            bytes_count = packets * int(np.random.randint(64, 850))
            ttl = int(np.random.choice([64, 128]))
            packet_size = int(bytes_count / max(1, packets))
            iat = float(np.random.uniform(0.01, 0.25))

        elif i < 550:
            # PHASE 2: Reconnaissance
            stage = "Reconnaissance"
            src_ip = external_adversary_ip
            dst_ip = np.random.choice(internal_servers)
            proto = "TCP"
            # Rapid scanning across common attack ports
            scan_ports = [21, 22, 23, 25, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 8080]
            dst_port = int(np.random.choice(scan_ports)) if np.random.rand() > 0.2 else int(np.random.randint(1, 1024))
            src_port = int(np.random.randint(30000, 65000))
            # SYN scans or RST responses
            tcp_flags = np.random.choice(["SYN", "RST", "SYN,RST"], p=[0.75, 0.2, 0.05])
            duration = float(np.random.uniform(0.01, 0.3))
            packets = int(np.random.randint(1, 4))
            bytes_count = packets * int(np.random.randint(40, 64))
            ttl = int(np.random.choice([52, 54, 110]))
            packet_size = int(bytes_count / max(1, packets))
            iat = float(np.random.uniform(0.001, 0.04))  # Low IAT (rapid succession)

        elif i < 750:
            # PHASE 3: Initial Access
            stage = "Initial Access"
            src_ip = external_adversary_ip
            dst_ip = "192.168.1.10"  # Target DMZ Web/App Server
            proto = "TCP"
            dst_port = int(np.random.choice([443, 80, 22, 8080]))
            src_port = int(np.random.randint(40000, 60000))
            tcp_flags = np.random.choice(["SYN,ACK,PSH", "ACK,PSH", "RST"], p=[0.7, 0.25, 0.05])
            duration = float(np.random.uniform(0.5, 8.0))
            # High packet bursts indicating exploit payloads / auth attempts
            packets = int(np.random.randint(25, 120))
            bytes_count = packets * int(np.random.randint(300, 1200))
            ttl = int(np.random.choice([50, 52]))
            packet_size = int(bytes_count / max(1, packets))
            iat = float(np.random.uniform(0.005, 0.08))

        elif i < 950:
            # PHASE 4: Lateral Movement
            stage = "Lateral Movement"
            # Compromised DMZ server pivoting to internal workstations
            src_ip = "192.168.1.10"
            dst_ip = np.random.choice(internal_workstations[:15])
            proto = "TCP"
            # Internal lateral protocols: SMB (445), RDP (3389), WMI (135), SSH (22)
            dst_port = int(np.random.choice([445, 3389, 135, 22], p=[0.45, 0.35, 0.15, 0.05]))
            src_port = int(np.random.randint(49152, 65535))
            tcp_flags = np.random.choice(["SYN,ACK,PSH", "ACK", "PSH"], p=[0.6, 0.3, 0.1])
            duration = float(np.random.uniform(1.0, 15.0))
            packets = int(np.random.randint(30, 200))
            bytes_count = packets * int(np.random.randint(200, 1000))
            ttl = 128  # Internal Windows default
            packet_size = int(bytes_count / max(1, packets))
            iat = float(np.random.uniform(0.01, 0.15))

        elif i < 1100:
            # PHASE 5: Command and Control
            stage = "Command and Control"
            # Workstations beaconing back to external C2
            src_ip = np.random.choice(internal_workstations[:5])
            dst_ip = c2_server_ip
            proto = "TCP"
            dst_port = int(np.random.choice([443, 8443, 80]))
            src_port = int(np.random.randint(50000, 65000))
            tcp_flags = np.random.choice(["ACK,PSH", "ACK"], p=[0.8, 0.2])
            duration = float(np.random.uniform(0.2, 2.0))
            packets = int(np.random.randint(6, 18))  # Periodic small heartbeats
            bytes_count = packets * int(np.random.randint(120, 350))
            ttl = 64
            packet_size = int(bytes_count / max(1, packets))
            # Highly regular periodic IAT with low jitter
            iat = float(np.random.normal(loc=0.5, scale=0.02))

        else:
            # PHASE 6: Exfiltration
            stage = "Exfiltration"
            src_ip = np.random.choice(internal_workstations[:3])
            dst_ip = c2_server_ip
            proto = "TCP"
            dst_port = int(np.random.choice([443, 8443, 9001]))
            src_port = int(np.random.randint(52000, 64000))
            tcp_flags = np.random.choice(["ACK,PSH", "PSH"], p=[0.9, 0.1])
            duration = float(np.random.uniform(5.0, 30.0))
            # High volume data dumps
            packets = int(np.random.randint(150, 800))
            bytes_count = packets * int(np.random.randint(1100, 1460))
            ttl = 64
            packet_size = int(bytes_count / max(1, packets))
            iat = float(np.random.uniform(0.002, 0.02))

        records.append({
            "timestamp": current_time.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": proto,
            "packets": packets,
            "bytes": bytes_count,
            "duration": round(duration, 3),
            "tcp_flags": tcp_flags,
            "ttl": ttl,
            "packet_size": packet_size,
            "iat": round(max(0.0001, iat), 4),
            "attack_stage": stage,
            "is_demo": True
        })

    df = pd.DataFrame(records)

    if save_path:
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        df.to_csv(save_path, index=False)

    return df


def get_or_create_sample_dataset() -> pd.DataFrame:
    """
    Retrieves the cached sample dataset or generates one immediately if absent.
    Ensures zero delay out-of-the-box demo availability.
    """
    default_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "sample_network_traffic.csv")
    if os.path.exists(default_path):
        try:
            df = pd.read_csv(default_path)
            return df
        except Exception:
            pass

    return generate_synthetic_network_traffic(num_flows=1200, save_path=default_path)
