"""
CYBERWORLD-X: Data Cleaning & Sanitization Module
NTRO SIH 2026 | Problem Statement ID: 26153
"""

import logging
from typing import Dict, List, Tuple
import numpy as np
import pandas as pd

logger = logging.getLogger("cyberworld_x.cleaning")


def clean_network_dataframe(df: pd.DataFrame) -> Tuple[pd.DataFrame, Dict[str, any]]:
    """
    Cleans and standardizes raw network traffic dataframes.
    
    Handles:
    - Stripping column whitespace and normalizing case
    - Datetime parsing (ISO, epoch seconds, epoch millis)
    - Handling infinite values, NaN, and negative durations
    - Numeric type enforcement for ports, packets, bytes
    - Sorting by timestamp
    
    Returns:
        Tuple[pd.DataFrame, Dict[str, any]]: Cleaned dataframe and audit metadata.
    """
    if df.empty:
        return df, {"rows_in": 0, "rows_out": 0, "status": "empty"}

    df_clean = df.copy()
    initial_rows = len(df_clean)

    # 1. Normalize column names (strip whitespace, lowercase)
    df_clean.columns = [str(c).strip().lower().replace(" ", "_") for c in df_clean.columns]

    # 2. Parse Timestamp column
    timestamp_col = None
    for cand in ["timestamp", "time", "datetime", "stime", "epoch"]:
        if cand in df_clean.columns:
            timestamp_col = cand
            break

    if timestamp_col:
        try:
            # Check if numeric (epoch)
            if pd.api.types.is_numeric_dtype(df_clean[timestamp_col]):
                max_val = df_clean[timestamp_col].max()
                unit = "ms" if max_val > 1e11 else "s"
                df_clean["parsed_timestamp"] = pd.to_datetime(df_clean[timestamp_col], unit=unit, errors="coerce")
            else:
                df_clean["parsed_timestamp"] = pd.to_datetime(df_clean[timestamp_col], errors="coerce")

            # Fallback for unparseable dates: generate synthetic increments
            if df_clean["parsed_timestamp"].isna().all():
                start_dt = pd.Timestamp.now() - pd.Timedelta(minutes=30)
                df_clean["parsed_timestamp"] = [start_dt + pd.Timedelta(seconds=i) for i in range(len(df_clean))]
            else:
                # Forward-fill and backward-fill any rare missing timestamps
                df_clean["parsed_timestamp"] = df_clean["parsed_timestamp"].ffill().bfill()
        except Exception as e:
            logger.warning(f"Timestamp parsing failed: {e}. Generating sequential timestamps.")
            start_dt = pd.Timestamp.now() - pd.Timedelta(minutes=30)
            df_clean["parsed_timestamp"] = [start_dt + pd.Timedelta(seconds=i) for i in range(len(df_clean))]
    else:
        # Synthesize time index if none was provided in CSV
        start_dt = pd.Timestamp.now() - pd.Timedelta(minutes=30)
        df_clean["parsed_timestamp"] = [start_dt + pd.Timedelta(seconds=i * 2) for i in range(len(df_clean))]

    # Sort deterministically by timestamp
    df_clean = df_clean.sort_values(by="parsed_timestamp").reset_index(drop=True)

    # 3. Numeric sanitation (replace inf, -inf with NaN, then impute)
    numeric_cols = df_clean.select_dtypes(include=[np.number]).columns
    df_clean[numeric_cols] = df_clean[numeric_cols].replace([np.inf, -np.inf], np.nan)

    for col in numeric_cols:
        if df_clean[col].isna().any():
            median_val = df_clean[col].median()
            df_clean[col] = df_clean[col].fillna(0 if pd.isna(median_val) else median_val)

    # Enforce non-negativity on counts and duration
    for col in ["packets", "bytes", "duration", "packet_size", "iat"]:
        if col in df_clean.columns:
            df_clean[col] = df_clean[col].clip(lower=0)

    # 4. String column sanitation
    str_cols = df_clean.select_dtypes(include=["object"]).columns
    for col in str_cols:
        df_clean[col] = df_clean[col].fillna("UNKNOWN")

    audit = {
        "rows_in": initial_rows,
        "rows_out": len(df_clean),
        "columns": list(df_clean.columns),
        "start_time": str(df_clean["parsed_timestamp"].min()),
        "end_time": str(df_clean["parsed_timestamp"].max()),
        "duration_seconds": (df_clean["parsed_timestamp"].max() - df_clean["parsed_timestamp"].min()).total_seconds(),
        "status": "success"
    }

    return df_clean, audit
