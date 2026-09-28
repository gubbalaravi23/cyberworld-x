"""
CYBERWORLD-X: CAPEC (Common Attack Pattern Enumeration and Classification) Mapping
NTRO SIH 2026 | Problem Statement ID: 26153
"""

from typing import Dict, List


CAPEC_STAGE_MAPPINGS: Dict[str, List[Dict[str, str]]] = {
    "Reconnaissance": [
        {
            "capec_id": "CAPEC-300",
            "name": "Port Scanning",
            "likelihood": "High",
            "severity": "Low",
            "summary": "An adversary probes open ports across target machines to identify services and version profiles."
        },
        {
            "capec_id": "CAPEC-292",
            "name": "Host Discovery",
            "likelihood": "High",
            "severity": "Low",
            "summary": "Mapping active IP allocations within a designated CIDR network block."
        }
    ],
    "Initial Access": [
        {
            "capec_id": "CAPEC-112",
            "name": "Brute Force Authentication",
            "likelihood": "High",
            "severity": "Medium",
            "summary": "Exhaustive trial-and-error attempts against remote authentication services."
        },
        {
            "capec_id": "CAPEC-233",
            "name": "Privilege Escalation via Parameter Manipulation",
            "likelihood": "Medium",
            "severity": "High",
            "summary": "Exploiting input parameters on public web services to obtain unauthorized session access."
        }
    ],
    "Lateral Movement": [
        {
            "capec_id": "CAPEC-555",
            "name": "Remote Services Abuse",
            "likelihood": "Medium",
            "severity": "High",
            "summary": "Leveraging administrative remote execution protocols (SMB, RPC, RDP, WMI) across internal hosts."
        },
        {
            "capec_id": "CAPEC-645",
            "name": "Pass the Hash / Kerberos Ticket Reuse",
            "likelihood": "Medium",
            "severity": "High",
            "summary": "Authenticating to network resources without knowledge of the cleartext password."
        }
    ],
    "Command and Control": [
        {
            "capec_id": "CAPEC-584",
            "name": "Bypassing Protocol Whitelisting via Tunneling",
            "likelihood": "Medium",
            "severity": "High",
            "summary": "Encapsulating non-standard command sessions inside allowable outbound protocols like HTTP/HTTPS/DNS."
        }
    ],
    "Exfiltration": [
        {
            "capec_id": "CAPEC-560",
            "name": "Data Transmission via External Channel",
            "likelihood": "High",
            "severity": "Very High",
            "summary": "Transferring collected files, credentials, or proprietary databases outside the enterprise boundary."
        }
    ],
    "Normal Activity": [
        {
            "capec_id": "N/A",
            "name": "Standard Operational Communications",
            "likelihood": "N/A",
            "severity": "None",
            "summary": "Traffic patterns conform to normal network service interactions."
        }
    ]
}


def get_capec_mapping_for_stage(stage_name: str) -> List[Dict[str, str]]:
    for key, mappings in CAPEC_STAGE_MAPPINGS.items():
        if key.lower() in stage_name.lower() or stage_name.lower() in key.lower():
            return mappings
    return CAPEC_STAGE_MAPPINGS["Normal Activity"]
