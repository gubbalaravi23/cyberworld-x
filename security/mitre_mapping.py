"""
CYBERWORLD-X: MITRE ATT&CK Security Framework Mapping
NTRO SIH 2026 | Problem Statement ID: 26153

Maps predicted attack stages and temporal behavioral anomalies
to authoritative MITRE ATT&CK Enterprise tactics and techniques.
"""

from typing import Any, Dict, List, Optional


MITRE_TACTIC_MAPPINGS: Dict[str, List[Dict[str, str]]] = {
    "Reconnaissance": [
        {
            "tactic": "Reconnaissance (TA0043)",
            "technique_id": "T1595.001",
            "technique_name": "Active Scanning: Scanning IP Blocks",
            "description": "Adversary scans target enterprise CIDR blocks to gather network routing and host existence info.",
            "detection_indicators": "Bursts of ICMP Echo, sequential SYN probes, uniform short packet sizes."
        },
        {
            "tactic": "Discovery (TA0007)",
            "technique_id": "T1046",
            "technique_name": "Network Service Discovery",
            "description": "Adversary probes a range of target ports (21, 22, 80, 443, 445, 3389) across live hosts to inventory listening services.",
            "detection_indicators": "Multiple TCP SYN packets across diverse destination ports from a single external IP with low inter-arrival jitter."
        }
    ],
    "Initial Access": [
        {
            "tactic": "Initial Access (TA0001)",
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "description": "Adversary attempts exploitation of internet-accessible web servers, SSL VPN gateways, or exposed SSH services.",
            "detection_indicators": "Spike in inbound byte volume to DMZ ports 80/443 followed by anomalous application error responses."
        },
        {
            "tactic": "Credential Access (TA0006)",
            "technique_id": "T1110.001",
            "technique_name": "Brute Force: Password Guessing",
            "description": "Adversary systematically attempts multiple authentication credentials against exposed services.",
            "detection_indicators": "High frequency of short-duration TCP sessions with frequent RST or FIN terminations on ports 22, 3389, or 445."
        }
    ],
    "Lateral Movement": [
        {
            "tactic": "Lateral Movement (TA0008)",
            "technique_id": "T1021.002",
            "technique_name": "Remote Services: SMB/Windows Admin Shares",
            "description": "Adversary leverages compromised credentials to pivot across internal subnets via SMB port 445.",
            "detection_indicators": "East-west internal traffic bursts between workstations and domain controllers on TCP 445."
        },
        {
            "tactic": "Lateral Movement (TA0008)",
            "technique_id": "T1021.001",
            "technique_name": "Remote Desktop Protocol (RDP)",
            "description": "Adversary connects to internal remote desktop interfaces on port 3389 for interactive control.",
            "detection_indicators": "Sustained high-throughput bidirectional flows between internal endpoints on TCP 3389."
        }
    ],
    "Command and Control": [
        {
            "tactic": "Command and Control (TA0011)",
            "technique_id": "T1071.001",
            "technique_name": "Application Layer Protocol: Web Protocols",
            "description": "Adversary communicates using HTTP/HTTPS to blend malicious C2 traffic with legitimate business browsing.",
            "detection_indicators": "Periodic small packet exchanges (beaconing) with near-constant inter-arrival intervals to external IPs."
        },
        {
            "tactic": "Command and Control (TA0011)",
            "technique_id": "T1573.002",
            "technique_name": "Encrypted Channel: Asymmetric Cryptography",
            "description": "Adversary employs custom SSL/TLS certificates or non-standard ports to encapsulate control commands.",
            "detection_indicators": "Outbound TLS sessions to uncommon destinations, low packet length variance."
        }
    ],
    "Exfiltration": [
        {
            "tactic": "Exfiltration (TA0010)",
            "technique_id": "T1048.003",
            "technique_name": "Exfiltration Over Alternative Protocol: Unencrypted/Encrypted Non-C2",
            "description": "Adversary steals sensitive enterprise data by uploading directly to cloud services or remote FTP/HTTPS endpoints.",
            "detection_indicators": "Extreme outbound-to-inbound byte ratio (>90% egress), sustained high MTU packet bursts."
        },
        {
            "tactic": "Exfiltration (TA0010)",
            "technique_id": "T1041",
            "technique_name": "Exfiltration Over C2 Channel",
            "description": "Adversary transmits sensitive records back through the established command and control socket.",
            "detection_indicators": "Shift from low-volume beaconing to massive outbound byte rate on existing persistent sessions."
        }
    ],
    "Normal Activity": [
        {
            "tactic": "Operational Baseline",
            "technique_id": "BENIGN",
            "technique_name": "Routine Network Telemetry",
            "description": "Expected enterprise communications matching established statistical baselines.",
            "detection_indicators": "Balanced client-server ratios, expected protocol entropy, healthy TCP handshakes."
        }
    ]
}


def get_mitre_mapping_for_stage(stage_name: str) -> List[Dict[str, str]]:
    """
    Returns verified MITRE ATT&CK techniques associated with an attack progression stage.
    """
    for key, mappings in MITRE_TACTIC_MAPPINGS.items():
        if key.lower() in stage_name.lower() or stage_name.lower() in key.lower():
            return mappings

    return MITRE_TACTIC_MAPPINGS["Normal Activity"]
