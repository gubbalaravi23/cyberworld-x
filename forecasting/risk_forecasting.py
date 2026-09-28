"""
CYBERWORLD-X: Network Attack Risk Forecasting & Chart Generator
NTRO SIH 2026 | Problem Statement ID: 26153

Computes time-series risk scores over historical, current, and forecasted future windows.
Generates interactive Plotly visualizations with clear demarcation of historical vs forecast horizons,
uncertainty bands, and threshold alert zones.
"""

from typing import Any, Dict, List, Optional, Tuple
import numpy as np
import pandas as pd
import plotly.graph_objects as go
from utils.constants import (
    RISK_THRESHOLD_NORMAL,
    RISK_THRESHOLD_ELEVATED,
    RISK_THRESHOLD_HIGH
)
from utils.helpers import apply_glass_theme


def calculate_historical_risk(df_states: pd.DataFrame) -> List[float]:
    """
    Computes empirical risk trajectory across past time windows based on behavioral metrics.
    """
    if df_states.empty:
        return []

    risk_scores = []
    for _, row in df_states.iterrows():
        syn_ratio = float(row.get("syn_ratio", 0.0))
        rst_ratio = float(row.get("rst_ratio", 0.0))
        pkt_rate = float(row.get("packet_rate", 5.0))
        dst_ports = int(row.get("unique_dst_ports", 1))
        failed_ratio = float(row.get("failed_conn_ratio", 0.0))

        # Multi-factor behavioral risk index
        score = (
            (syn_ratio * 0.25) +
            (min(pkt_rate, 400.0) / 400.0 * 0.25) +
            (min(dst_ports, 30) / 30.0 * 0.25) +
            (failed_ratio * 0.15) +
            (rst_ratio * 0.10)
        )
        risk_scores.append(float(np.clip(score, 0.05, 0.95)))

    return risk_scores


def create_risk_forecast_plot(
    historical_risks: List[float],
    forecast_risks: List[float],
    timestamps: Optional[List[str]] = None,
    current_stage: str = "Reconnaissance",
    predicted_stage: str = "Initial Access"
) -> go.Figure:
    """
    Builds the main Plotly chart: NETWORK ATTACK RISK FORECAST.
    Shows Historical (solid cyan line) -> Current State (highlighted marker) -> Forecast (dashed amber/red line).
    Includes high-risk threshold zone and prediction uncertainty cone.
    """
    num_hist = len(historical_risks)
    num_fore = len(forecast_risks)

    # Time labels
    x_hist = [f"t-{num_hist - 1 - i}" if i < num_hist - 1 else "Current S(t)" for i in range(num_hist)]
    x_fore = [f"t+{i + 1} (Forecast)" for i in range(num_fore)]

    fig = go.Figure()

    # High-Risk Region Shading
    fig.add_hrect(
        y0=RISK_THRESHOLD_HIGH * 100,
        y1=100,
        fillcolor="rgba(239, 68, 68, 0.08)",
        line_width=0,
        annotation_text="PREDICTED HIGH-RISK REGION (>75%)",
        annotation_position="top left",
        annotation_font_size=10,
        annotation_font_color="#ef4444"
    )

    # Elevated Risk Region Shading
    fig.add_hrect(
        y0=RISK_THRESHOLD_ELEVATED * 100,
        y1=RISK_THRESHOLD_HIGH * 100,
        fillcolor="rgba(245, 158, 11, 0.05)",
        line_width=0,
    )

    # Historical Line Trace
    hist_percentages = [r * 100 for r in historical_risks]
    fig.add_trace(go.Scatter(
        x=x_hist,
        y=hist_percentages,
        mode="lines+markers",
        name="Historical Risk",
        line=dict(color="#00f0ff", width=3),
        marker=dict(size=7, color="#00f0ff", symbol="circle"),
        hovertemplate="<b>%{x}</b><br>Observed Risk: %{y:.1f}%<extra></extra>"
    ))

    # Forecast Uncertainty Cone (upper and lower bounds)
    if num_fore > 0 and num_hist > 0:
        fore_x_full = [x_hist[-1]] + x_fore
        fore_y_full = [hist_percentages[-1]] + [r * 100 for r in forecast_risks]

        # Widening uncertainty bounds as horizon increases
        upper_bound = []
        lower_bound = []
        for i, y in enumerate(fore_y_full):
            uncertainty = i * 2.8  # Expanding uncertainty
            upper_bound.append(min(100.0, y + uncertainty))
            lower_bound.append(max(0.0, y - uncertainty))

        # Upper bound line (invisible, for fill)
        fig.add_trace(go.Scatter(
            x=fore_x_full,
            y=upper_bound,
            mode="lines",
            line=dict(width=0),
            showlegend=False,
            hoverinfo="skip"
        ))

        # Lower bound line with confidence fill
        fig.add_trace(go.Scatter(
            x=fore_x_full,
            y=lower_bound,
            mode="lines",
            line=dict(width=0),
            fill="tonexty",
            fillcolor="rgba(245, 158, 11, 0.15)",
            name="Forecast Uncertainty",
            hoverinfo="skip"
        ))

        # Main Forecast Line (Dashed)
        fig.add_trace(go.Scatter(
            x=fore_x_full,
            y=fore_y_full,
            mode="lines+markers",
            name="Forecasted Risk Trajectory",
            line=dict(color="#f59e0b", width=3, dash="dash"),
            marker=dict(size=8, color="#f59e0b", symbol="diamond"),
            hovertemplate="<b>%{x}</b><br>Forecasted Risk: %{y:.1f}%<extra></extra>"
        ))

    # Mark Current State S(t) with a prominent vertical marker
    if num_hist > 0:
        cur_x = x_hist[-1]
        cur_y = hist_percentages[-1]
        fig.add_trace(go.Scatter(
            x=[cur_x],
            y=[cur_y],
            mode="markers+text",
            name="Current State S(t)",
            marker=dict(size=14, color="#00f0ff", line=dict(color="#ffffff", width=2)),
            text=["CURRENT STATE S(t)"],
            textposition="top center",
            textfont=dict(color="#00f0ff", size=11, family="Plus Jakarta Sans"),
            hovertemplate="<b>Current State S(t)</b><br>Risk: %{y:.1f}%<extra></extra>"
        ))

        # Vertical line demarcating Forecast Start
        fig.add_vline(
            x=cur_x,
            line_width=1.5,
            line_dash="dot",
            line_color="rgba(255, 255, 255, 0.4)"
        )

    fig.update_yaxes(
        title_text="Attack Risk Score (%)",
        range=[0, 105],
        ticksuffix="%"
    )
    fig.update_xaxes(
        title_text="Sequential Time Windows"
    )

    return apply_glass_theme(fig, height=440, title="NETWORK ATTACK RISK FORECAST (Historical → Current → Forecast)")
