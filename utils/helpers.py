"""
CYBERWORLD-X: Helper Functions & Liquid Glass UI Components
NTRO SIH 2026 | Problem Statement ID: 26153
"""

import html
from typing import Any, Dict, Optional
import plotly.graph_objects as go
from utils.constants import STAGE_COLORS, STAGE_ICONS


def get_liquid_glass_css() -> str:
    """
    Returns the custom Liquid Glass styling CSS for Streamlit.
    Implements glassmorphism cards, luminous borders, futuristic dark theme,
    and responsive layout styles.
    """
    return """
    <style>
    /* Google Fonts import */
    @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap');

    /* Global Streamlit Dark Resets */
    :root {
        --glass-bg: rgba(13, 21, 39, 0.65);
        --glass-bg-subtle: rgba(13, 21, 39, 0.40);
        --glass-border: rgba(0, 240, 255, 0.18);
        --glass-border-hover: rgba(0, 240, 255, 0.45);
        --glass-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.45);
        --glass-glow: 0 0 20px rgba(0, 240, 255, 0.15);
        --cyan-glow: #00f0ff;
        --purple-glow: #8b5cf6;
        --crimson-glow: #ef4444;
        --font-main: 'Plus Jakarta Sans', system-ui, -apple-system, sans-serif;
        --font-mono: 'JetBrains Mono', monospace;
    }

    html, body, [class*="css"] {
        font-family: var(--font-main) !important;
        color: #e2e8f0;
    }

    /* Main Container Padding and Futuristic Background */
    .stApp {
        background: radial-gradient(circle at 15% 20%, rgba(16, 27, 54, 0.8) 0%, rgba(7, 11, 20, 1) 70%),
                    radial-gradient(circle at 85% 80%, rgba(35, 18, 55, 0.5) 0%, rgba(7, 11, 20, 1) 70%),
                    #070b14;
        background-attachment: fixed;
    }

    /* Streamlit Header & Toolbar minimal */
    header[data-testid="stHeader"] {
        background: rgba(7, 11, 20, 0.75) !important;
        backdrop-filter: blur(12px) !important;
        -webkit-backdrop-filter: blur(12px) !important;
        border-bottom: 1px solid rgba(255, 255, 255, 0.05);
    }

    /* Sidebar Glassmorphism */
    section[data-testid="stSidebar"] {
        background: rgba(9, 14, 26, 0.82) !important;
        backdrop-filter: blur(20px) !important;
        -webkit-backdrop-filter: blur(20px) !important;
        border-right: 1px solid rgba(0, 240, 255, 0.15) !important;
        box-shadow: 4px 0 24px rgba(0, 0, 0, 0.5);
    }

    /* Glass Cards */
    .glass-card {
        background: var(--glass-bg);
        backdrop-filter: blur(16px);
        -webkit-backdrop-filter: blur(16px);
        border: 1px solid var(--glass-border);
        border-radius: 16px;
        padding: 24px;
        box-shadow: var(--glass-shadow);
        transition: all 0.3s cubic-bezier(0.16, 1, 0.3, 1);
        position: relative;
        overflow: hidden;
    }

    .glass-card:hover {
        border-color: var(--glass-border-hover);
        box-shadow: var(--glass-shadow), var(--glass-glow);
        transform: translateY(-2px);
    }

    .glass-card::before {
        content: "";
        position: absolute;
        top: 0;
        left: -100%;
        width: 100%;
        height: 2px;
        background: linear-gradient(90deg, transparent, var(--cyan-glow), transparent);
        transition: 0.5s;
    }

    .glass-card:hover::before {
        left: 100%;
    }

    /* Glass Metric Card */
    .glass-metric {
        background: rgba(13, 22, 42, 0.7);
        backdrop-filter: blur(14px);
        -webkit-backdrop-filter: blur(14px);
        border: 1px solid rgba(0, 240, 255, 0.18);
        border-radius: 14px;
        padding: 20px;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.35);
        display: flex;
        flex-direction: column;
        justify-content: space-between;
        min-height: 140px;
    }

    .glass-metric-label {
        font-size: 0.78rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 1.5px;
        color: #94a3b8;
        display: flex;
        align-items: center;
        gap: 6px;
    }

    .glass-metric-value {
        font-size: 2.2rem;
        font-weight: 800;
        font-family: var(--font-mono);
        color: #ffffff;
        margin: 8px 0;
        letter-spacing: -0.5px;
    }

    .glass-metric-sub {
        font-size: 0.8rem;
        font-weight: 600;
        display: flex;
        align-items: center;
        gap: 6px;
    }

    /* State Transition Glass Badge */
    .state-node-card {
        background: rgba(15, 23, 42, 0.75);
        backdrop-filter: blur(12px);
        border: 1px solid rgba(0, 240, 255, 0.2);
        border-radius: 14px;
        padding: 16px;
        text-align: center;
        min-width: 130px;
        box-shadow: 0 4px 16px rgba(0, 0, 0, 0.3);
        transition: transform 0.2s ease, border-color 0.2s ease;
    }

    .state-node-card:hover {
        border-color: #00f0ff;
        transform: scale(1.03);
    }

    /* Alert Banner */
    .glass-alert {
        background: rgba(30, 20, 35, 0.7);
        backdrop-filter: blur(16px);
        border-left: 4px solid #f59e0b;
        border-top: 1px solid rgba(245, 158, 11, 0.2);
        border-right: 1px solid rgba(245, 158, 11, 0.15);
        border-bottom: 1px solid rgba(245, 158, 11, 0.2);
        border-radius: 12px;
        padding: 16px 20px;
        box-shadow: 0 4px 24px rgba(245, 158, 11, 0.12);
        margin: 16px 0;
    }

    .glass-alert.critical {
        background: rgba(35, 15, 25, 0.75);
        border-left-color: #ef4444;
        box-shadow: 0 4px 24px rgba(239, 68, 68, 0.15);
    }

    .glass-alert.info {
        background: rgba(12, 28, 48, 0.75);
        border-left-color: #00f0ff;
        box-shadow: 0 4px 24px rgba(0, 240, 255, 0.15);
    }

    /* Demo Data Badge */
    .demo-badge {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        background: rgba(245, 158, 11, 0.15);
        border: 1px solid rgba(245, 158, 11, 0.4);
        color: #fbbf24;
        padding: 4px 12px;
        border-radius: 9999px;
        font-size: 0.72rem;
        font-weight: 700;
        letter-spacing: 1px;
        text-transform: uppercase;
    }

    /* Live Status Pill */
    .status-pill {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        padding: 4px 10px;
        border-radius: 9999px;
        font-size: 0.72rem;
        font-weight: 700;
        letter-spacing: 0.5px;
    }

    .status-pill.online {
        background: rgba(16, 185, 129, 0.15);
        border: 1px solid rgba(16, 185, 129, 0.4);
        color: #34d399;
    }

    .status-pill.active {
        background: rgba(0, 240, 255, 0.15);
        border: 1px solid rgba(0, 240, 255, 0.4);
        color: #38bdf8;
    }

    .status-pill.warning {
        background: rgba(245, 158, 11, 0.15);
        border: 1px solid rgba(245, 158, 11, 0.4);
        color: #fbbf24;
    }

    /* Pulsing dot */
    .pulse-dot {
        width: 8px;
        height: 8px;
        border-radius: 50%;
        display: inline-block;
        background-color: currentColor;
        box-shadow: 0 0 8px currentColor;
        animation: pulseAnimation 2s infinite;
    }

    @keyframes pulseAnimation {
        0% { opacity: 0.4; transform: scale(0.9); }
        50% { opacity: 1; transform: scale(1.1); }
        100% { opacity: 0.4; transform: scale(0.9); }
    }

    /* Attack Stage Progression Horizontal Bar */
    .progression-container {
        display: flex;
        align-items: center;
        justify-content: space-between;
        background: rgba(13, 21, 39, 0.6);
        border: 1px solid rgba(0, 240, 255, 0.15);
        border-radius: 16px;
        padding: 20px;
        margin: 18px 0;
        overflow-x: auto;
        gap: 12px;
    }

    .stage-item {
        flex: 1;
        min-width: 140px;
        padding: 12px 14px;
        border-radius: 10px;
        text-align: center;
        border: 1px solid rgba(255, 255, 255, 0.08);
        background: rgba(255, 255, 255, 0.03);
        transition: all 0.3s ease;
    }

    .stage-item.current {
        border: 1.5px solid #00f0ff;
        background: rgba(0, 240, 255, 0.12);
        box-shadow: 0 0 16px rgba(0, 240, 255, 0.25);
    }

    .stage-item.predicted {
        border: 1.5px dashed #f59e0b;
        background: rgba(245, 158, 11, 0.12);
        box-shadow: 0 0 16px rgba(245, 158, 11, 0.2);
    }

    .stage-item.completed {
        border: 1px solid rgba(16, 185, 129, 0.3);
        background: rgba(16, 185, 129, 0.08);
        opacity: 0.8;
    }

    /* Buttons override */
    .stButton > button {
        background: linear-gradient(135deg, rgba(0, 240, 255, 0.15), rgba(112, 0, 255, 0.18)) !important;
        border: 1px solid rgba(0, 240, 255, 0.35) !important;
        color: #ffffff !important;
        border-radius: 10px !important;
        font-weight: 600 !important;
        padding: 0.6rem 1.4rem !important;
        transition: all 0.25s ease !important;
        box-shadow: 0 4px 14px rgba(0, 0, 0, 0.25) !important;
    }

    .stButton > button:hover {
        border-color: #00f0ff !important;
        box-shadow: 0 0 18px rgba(0, 240, 255, 0.35) !important;
        transform: translateY(-1px) !important;
        color: #00f0ff !important;
    }

    /* Streamlit Selectbox, Slider, Input */
    div[data-baseweb="select"] > div,
    div[data-baseweb="input"] > div {
        background-color: rgba(13, 21, 39, 0.8) !important;
        border: 1px solid rgba(0, 240, 255, 0.2) !important;
        border-radius: 10px !important;
        color: #e2e8f0 !important;
    }

    /* Dataframe glass styling */
    .stDataFrame {
        border: 1px solid rgba(0, 240, 255, 0.15) !important;
        border-radius: 12px !important;
        overflow: hidden !important;
    }
    </style>
    """


def render_header() -> str:
    """
    Renders top dashboard header with status indicators.
    """
    return """
    <div style="margin-bottom: 24px; padding-bottom: 16px; border-bottom: 1px solid rgba(0, 240, 255, 0.15);">
        <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 12px;">
            <div>
                <div style="display: flex; align-items: center; gap: 12px;">
                    <span style="font-size: 2.2rem; font-weight: 900; letter-spacing: 2px; color: #ffffff;">
                        CYBER<span style="color: #00f0ff;">WORLD</span><span style="color: #ff007f;">-X</span>
                    </span>
                    <span class="status-pill online">
                        <span class="pulse-dot"></span> SYSTEM: ONLINE
                    </span>
                    <span class="demo-badge">
                        DEMO MODE ACTIVE
                    </span>
                </div>
                <div style="color: #94a3b8; font-size: 0.95rem; margin-top: 4px; font-weight: 500;">
                    AI-Based Network Attack Forecasting &bull; <span style="color: #38bdf8; font-style: italic;">"Predict the next stage before the attack progresses."</span>
                </div>
            </div>
            <div style="display: flex; gap: 8px; align-items: center;">
                <span class="status-pill active">DATA: READY</span>
                <span class="status-pill active">MODEL: LSTM ONLINE</span>
                <span class="status-pill active" style="border-color: rgba(139, 92, 246, 0.4); color: #c084fc;">PS: 26153</span>
            </div>
        </div>
    </div>
    """


def render_metric_card(
    label: str,
    value: str,
    sub_label: str = "",
    status_color: str = "#00f0ff",
    is_demo: bool = True,
    icon: str = "⚡"
) -> str:
    """
    Generates a Liquid Glass Metric Card HTML string.
    """
    escaped_label = html.escape(label)
    escaped_val = html.escape(value)
    escaped_sub = html.escape(sub_label)
    demo_tag = '<span style="font-size: 0.65rem; color: #f59e0b; margin-left: 4px;">[DEMO]</span>' if is_demo else ""

    return f"""
    <div class="glass-metric" style="border-top: 2px solid {status_color};">
        <div class="glass-metric-label">
            <span>{icon}</span> {escaped_label} {demo_tag}
        </div>
        <div class="glass-metric-value" style="color: {status_color};">
            {escaped_val}
        </div>
        <div class="glass-metric-sub" style="color: #94a3b8;">
            {escaped_sub}
        </div>
    </div>
    """


def render_alert_box(
    title: str,
    message: str,
    risk_level: str = "warning",
    metrics_info: Optional[Dict[str, Any]] = None
) -> str:
    """
    Generates an Early Warning Alert Glass Card HTML string.
    """
    css_class = "glass-alert"
    border_color = "#f59e0b"
    title_icon = "⚠️"

    if risk_level.lower() == "critical" or risk_level.lower() == "high":
        css_class = "glass-alert critical"
        border_color = "#ef4444"
        title_icon = "🚨"
    elif risk_level.lower() == "info" or risk_level.lower() == "normal":
        css_class = "glass-alert info"
        border_color = "#00f0ff"
        title_icon = "🛡️"

    metrics_html = ""
    if metrics_info:
        pill_elements = []
        for k, v in metrics_info.items():
            pill_elements.append(
                f'<span style="background: rgba(255,255,255,0.06); padding: 3px 8px; border-radius: 6px; font-size: 0.75rem; border: 1px solid rgba(255,255,255,0.1);">'
                f'<strong style="color: #94a3b8;">{html.escape(k)}:</strong> <span style="color: #f1f5f9;">{html.escape(str(v))}</span></span>'
            )
        metrics_html = f'<div style="display: flex; gap: 8px; flex-wrap: wrap; margin-top: 10px;">{"".join(pill_elements)}</div>'

    return f"""
    <div class="{css_class}">
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <div style="font-weight: 700; font-size: 0.95rem; color: #ffffff; letter-spacing: 0.5px;">
                {title_icon} {html.escape(title)}
            </div>
            <span class="demo-badge">PROBABILISTIC FORECAST</span>
        </div>
        <div style="color: #cbd5e1; font-size: 0.88rem; margin-top: 6px; line-height: 1.5;">
            {html.escape(message)}
        </div>
        {metrics_html}
    </div>
    """


def render_attack_progression(current_stage: str, predicted_stage: str) -> str:
    """
    Renders horizontal attack progression visualization:
    Reconnaissance -> Initial Access -> Lateral Movement -> Command & Control -> Exfiltration
    """
    stages = [
        "Reconnaissance",
        "Initial Access",
        "Lateral Movement",
        "Command and Control",
        "Exfiltration"
    ]

    # Find indices
    cur_idx = -1
    pred_idx = -1
    for i, s in enumerate(stages):
        if s.lower() in current_stage.lower() or current_stage.lower() in s.lower():
            cur_idx = i
        if s.lower() in predicted_stage.lower() or predicted_stage.lower() in s.lower():
            pred_idx = i

    html_parts = ['<div class="progression-container">']

    for i, stage in enumerate(stages):
        icon = STAGE_ICONS.get(stage, "⚡")
        badge_style = "stage-item"
        tag_html = ""

        if i == cur_idx:
            badge_style += " current"
            tag_html = '<div style="font-size: 0.65rem; color: #00f0ff; font-weight: 800; margin-top: 4px;">● CURRENT STAGE</div>'
        elif i == pred_idx:
            badge_style += " predicted"
            tag_html = '<div style="font-size: 0.65rem; color: #f59e0b; font-weight: 800; margin-top: 4px;">⏱ PREDICTED NEXT</div>'
        elif cur_idx != -1 and i < cur_idx:
            badge_style += " completed"
            tag_html = '<div style="font-size: 0.65rem; color: #10b981; font-weight: 600; margin-top: 4px;">✓ OBSERVED</div>'
        else:
            tag_html = '<div style="font-size: 0.65rem; color: #64748b; font-weight: 500; margin-top: 4px;">UNAFFECTED</div>'

        html_parts.append(f"""
        <div class="{badge_style}">
            <div style="font-size: 1.2rem; margin-bottom: 2px;">{icon}</div>
            <div style="font-size: 0.82rem; font-weight: 700; color: #f8fafc;">{stage}</div>
            {tag_html}
        </div>
        """)

        if i < len(stages) - 1:
            arrow_color = "#38bdf8" if (i < cur_idx or i < pred_idx) else "rgba(255,255,255,0.15)"
            html_parts.append(f'<div style="color: {arrow_color}; font-size: 1.1rem; font-weight: 800;">→</div>')

    html_parts.append('</div>')
    return "".join(html_parts)


def apply_glass_theme(fig: go.Figure, height: int = 420, title: str = "") -> go.Figure:
    """
    Applies unified Liquid Glass cyber styling to any Plotly chart.
    """
    fig.update_layout(
        title={
            "text": title,
            "font": {"size": 15, "color": "#f8fafc", "family": "'Plus Jakarta Sans', sans-serif"},
            "x": 0.02,
            "y": 0.95
        } if title else None,
        paper_bgcolor="rgba(13, 21, 39, 0.4)",
        plot_bgcolor="rgba(8, 14, 27, 0.5)",
        font={"color": "#94a3b8", "family": "'Plus Jakarta Sans', sans-serif"},
        hoverlabel={
            "bgcolor": "rgba(15, 23, 42, 0.95)",
            "bordercolor": "#00f0ff",
            "font": {"color": "#ffffff", "family": "'JetBrains Mono', monospace"}
        },
        margin={"l": 40, "r": 30, "t": 50 if title else 25, "b": 40},
        height=height,
        xaxis={
            "gridcolor": "rgba(255, 255, 255, 0.05)",
            "zerolinecolor": "rgba(255, 255, 255, 0.1)",
            "color": "#94a3b8",
        },
        yaxis={
            "gridcolor": "rgba(255, 255, 255, 0.05)",
            "zerolinecolor": "rgba(255, 255, 255, 0.1)",
            "color": "#94a3b8",
        },
        legend={
            "bgcolor": "rgba(13, 21, 39, 0.7)",
            "bordercolor": "rgba(0, 240, 255, 0.2)",
            "borderwidth": 1,
            "font": {"color": "#e2e8f0"}
        }
    )
    return fig
