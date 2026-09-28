"""
CYBERWORLD-X: Vulnerability & CVE Reference Intelligence
NTRO SIH 2026 | Problem Statement ID: 26153
"""

from typing import Dict, List


CVE_STAGE_REFERENCES: Dict[str, List[Dict[str, str]]] = {
    "Reconnaissance": [
        {
            "cve_id": "NVD-REF-SCAN",
            "service": "Network Scanning & Banner Grabbing",
            "cvss": "N/A (Reconnaissance)",
            "impact": "Exposes software versions, open ports, and patch levels."
        }
    ],
    "Initial Access": [
        {
            "cve_id": "CVE-2021-44228",
            "service": "Apache Log4j2 (Log4Shell)",
            "cvss": "10.0 (Critical)",
            "impact": "Remote code execution via LDAP/JNDI lookup injection on public HTTP endpoints."
        },
        {
            "cve_id": "CVE-2024-6387",
            "service": "OpenSSH (regreSSHion)",
            "cvss": "8.1 (High)",
            "impact": "Signal handler race condition leading to unauthenticated root code execution."
        }
    ],
    "Lateral Movement": [
        {
            "cve_id": "CVE-2017-0144",
            "service": "Microsoft SMBv1 (EternalBlue)",
            "cvss": "8.1 (High)",
            "impact": "Allows remote attackers to execute arbitrary code via specially crafted SMB packets."
        },
        {
            "cve_id": "CVE-2020-1472",
            "service": "Netlogon (Zerologon)",
            "cvss": "10.0 (Critical)",
            "impact": "Elevation of privilege when establishing vulnerable Netlogon cryptographic connections."
        }
    ],
    "Command and Control": [
        {
            "cve_id": "C2-BEACON-PATTERN",
            "service": "Cobalt Strike / Sliver / Mythic Beaconing",
            "cvss": "Adversary TTP",
            "impact": "Maintains persistent interactive shell control over encrypted outbound channels."
        }
    ],
    "Exfiltration": [
        {
            "cve_id": "DATA-EGRESS-EVENT",
            "service": "Unauthorized Data Egress",
            "cvss": "Confidentiality Breach",
            "impact": "Direct intellectual property loss and regulatory non-compliance."
        }
    ],
    "Normal Activity": [
        {
            "cve_id": "NONE",
            "service": "Legitimate Traffic",
            "cvss": "0.0",
            "impact": "No active vulnerabilities exploited."
        }
    ]
}


def get_cve_mapping_for_stage(stage_name: str) -> List[Dict[str, str]]:
    for key, mappings in CVE_STAGE_REFERENCES.items():
        if key.lower() in stage_name.lower() or stage_name.lower() in key.lower():
            return mappings
    return CVE_STAGE_REFERENCES["Normal Activity"]
