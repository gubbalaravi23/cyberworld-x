"""
CYBERWORLD-X: Time Windowing & Network State S(t) Aggregator
NTRO SIH 2026 | Problem Statement ID: 26153

Aggregates raw flow/packet streams into sequential discrete temporal network states:
S(t-2) -> S(t-1) -> S(t) -> S(t+1) ...
And generates sliding sequence windows for PyTorch LSTM / Transformer training and inference.
"""

from typing import Dict, List, Optional, Tuple
import numpy as np
import pandas as pd
from utils.constants import NETWORK_STATE_FEATURES, DEFAULT_TIME_WINDOW


def aggregate_into_network_states(
    df: pd.DataFrame,
    window_seconds: int = DEFAULT_TIME_WINDOW
) -> pd.DataFrame:
    """
    Transforms event/flow level network records into sequential macro network states S(t).
    
    Each time window aggregates:
    - Volumetric metrics (packets, bytes, packet_rate, byte_rate)
    - Protocol & connection behavioral flags (syn_ratio, rst_ratio, failed_conn_ratio)
    - Structural dispersion (unique dst IPs, unique dst ports)
    - Payload/timing dynamics (avg_packet_size, iat_mean, iat_std)
    - Ground truth / dominant attack stage (if present)
    """
    if df.empty:
        return pd.DataFrame()

    df_work = df.copy()

    # Ensure timestamp is parsed datetime
    if "parsed_timestamp" not in df_work.columns:
        if "timestamp" in df_work.columns:
            df_work["parsed_timestamp"] = pd.to_datetime(df_work["timestamp"], errors="coerce")
        else:
            df_work["parsed_timestamp"] = pd.date_range(end=pd.Timestamp.now(), periods=len(df_work), freq="2s")

    # Drop any null timestamps and sort
    df_work = df_work.dropna(subset=["parsed_timestamp"]).sort_values("parsed_timestamp")
    df_work = df_work.set_index("parsed_timestamp")

    rule = f"{window_seconds}s"
    states = []

    # Group by resample window
    grouped = df_work.resample(rule)

    for window_start, group in grouped:
        if group.empty:
            continue

        pkt_count = group["packets"].sum() if "packets" in group.columns else len(group)
        byte_count = group["bytes"].sum() if "bytes" in group.columns else (pkt_count * 64)
        duration_total = float(window_seconds)

        packet_rate = float(pkt_count) / max(0.1, duration_total)
        byte_rate = float(byte_count) / max(0.1, duration_total)

        # Flag analysis
        syn_count = 0
        rst_count = 0
        if "tcp_flags" in group.columns:
            flags_str = group["tcp_flags"].astype(str).str.upper()
            syn_count = flags_str.str.contains("SYN").sum()
            rst_count = flags_str.str.contains("RST").sum()
        elif "is_syn" in group.columns:
            syn_count = group["is_syn"].sum()
            rst_count = group["is_rst"].sum()

        syn_ratio = float(syn_count) / max(1, len(group))
        rst_ratio = float(rst_count) / max(1, len(group))

        unique_dst_ips = int(group["dst_ip"].nunique()) if "dst_ip" in group.columns else 1
        unique_dst_ports = int(group["dst_port"].nunique()) if "dst_port" in group.columns else 1

        avg_packet_size = float(group["packet_size"].mean()) if "packet_size" in group.columns else (float(byte_count) / max(1, pkt_count))
        
        iat_mean = float(group["iat"].mean()) if "iat" in group.columns else 0.05
        iat_std = float(group["iat"].std()) if "iat" in group.columns else 0.01
        if pd.isna(iat_std):
            iat_std = 0.0

        # DNS / Port 53 queries
        dns_query_count = 0
        if "dst_port" in group.columns:
            dns_query_count = int((group["dst_port"] == 53).sum())

        # Outbound / Ingress ratio approximation
        outbound_ratio = 0.5
        if "dst_ip" in group.columns:
            # Check if dst is external (rough private IP regex)
            external_count = group["dst_ip"].astype(str).apply(
                lambda ip: not (ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.16."))
            ).sum()
            outbound_ratio = float(external_count) / max(1, len(group))

        failed_conn_ratio = float(rst_count) / max(1, len(group))

        # Dominant stage
        dominant_stage = "Normal Activity"
        if "attack_stage" in group.columns:
            mode_series = group["attack_stage"].mode()
            if not mode_series.empty:
                dominant_stage = mode_series.iloc[0]

        states.append({
            "window_timestamp": window_start,
            "packet_count": pkt_count,
            "byte_count": byte_count,
            "packet_rate": packet_rate,
            "byte_rate": byte_rate,
            "syn_ratio": syn_ratio,
            "rst_ratio": rst_ratio,
            "unique_dst_ips": unique_dst_ips,
            "unique_dst_ports": unique_dst_ports,
            "avg_packet_size": avg_packet_size,
            "iat_mean": iat_mean,
            "iat_std": iat_std,
            "dns_query_count": dns_query_count,
            "outbound_ratio": outbound_ratio,
            "failed_conn_ratio": failed_conn_ratio,
            "attack_stage": dominant_stage
        })

    df_states = pd.DataFrame(states)
    return df_states


def create_sliding_sequences(
    state_matrix: np.ndarray,
    sequence_length: int = 10,
    forecast_horizon: int = 5
) -> Tuple[np.ndarray, np.ndarray]:
    """
    Constructs rolling temporal tensor batches for the World Model:
    X: [batch_size, sequence_length, feature_dim] representing S(t-W+1)...S(t)
    Y: [batch_size, forecast_horizon, feature_dim] representing S(t+1)...S(t+K)
    
    If state_matrix has fewer steps than (sequence_length + forecast_horizon),
    it generates mirrored/augmented temporal sequences for demonstration.
    """
    total_steps = len(state_matrix)
    min_required = sequence_length + forecast_horizon

    if total_steps < min_required:
        # Augment by replicating with subtle noise for small demo datasets
        repeat_factor = int(np.ceil(min_required / max(1, total_steps))) + 1
        augmented = []
        for r in range(repeat_factor):
            noise = np.random.normal(0, 0.05, state_matrix.shape)
            augmented.append(state_matrix + noise)
        state_matrix = np.vstack(augmented)
        total_steps = len(state_matrix)

    X_list = []
    Y_list = []

    for i in range(total_steps - sequence_length - forecast_horizon + 1):
        X_seq = state_matrix[i : i + sequence_length]
        Y_seq = state_matrix[i + sequence_length : i + sequence_length + forecast_horizon]
        X_list.append(X_seq)
        Y_list.append(Y_seq)

    return np.array(X_list, dtype=np.float32), np.array(Y_list, dtype=np.float32)
