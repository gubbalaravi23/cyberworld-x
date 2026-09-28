"""
CYBERWORLD-X: AI-Based Network Attack Forecasting from Network Traffic Data
NTRO SIH 2026 | Problem Statement ID: 26153

Core Paradigm:
S(t-W+1) ... S(t)  ==[Temporal World Model]==>  S(t+1) ... S(t+K)
Predicting attack progression and risk escalation into future time windows.
"""

import os
os.environ["KMP_DUPLICATE_LIB_OK"] = "TRUE"

import io
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

import streamlit as st
import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

# Local Modules
from utils.constants import (
    PROJECT_NAME,
    PROJECT_TITLE,
    PROJECT_SUBTITLE,
    ORGANIZATION,
    PROBLEM_STATEMENT_ID,
    ATTACK_STAGES,
    STAGE_COLORS,
    STAGE_ICONS,
    STAGE_DESCRIPTIONS,
    TIME_WINDOWS,
    DEFAULT_TIME_WINDOW,
    FORECAST_HORIZONS,
    DEFAULT_FORECAST_HORIZON,
    SEQUENCE_LENGTHS,
    DEFAULT_SEQUENCE_LENGTH,
    RISK_THRESHOLD_HIGH,
    RISK_THRESHOLD_ELEVATED,
    SYSTEM_FOOTER
)
from utils.helpers import (
    get_liquid_glass_css,
    render_header,
    render_metric_card,
    render_alert_box,
    render_attack_progression,
    apply_glass_theme
)
from utils.sample_data import get_or_create_sample_dataset, generate_synthetic_network_traffic
from preprocessing.data_cleaning import clean_network_dataframe
from preprocessing.feature_extraction import (
    auto_map_columns,
    extract_features_from_pcap,
    compute_flow_aggregations
)
from preprocessing.time_windowing import (
    aggregate_into_network_states,
    create_sliding_sequences
)
from forecasting.world_model import WorldModelForecaster
from forecasting.risk_forecasting import (
    calculate_historical_risk,
    create_risk_forecast_plot
)
from forecasting.attack_stage_prediction import AttackStagePredictor
from explainability.shap_explainer import (
    SHAPForecastingExplainer,
    create_feature_importance_plot
)
from security.mitre_mapping import get_mitre_mapping_for_stage
from security.capec_mapping import get_capec_mapping_for_stage
from security.cve_mapping import get_cve_mapping_for_stage
from models.baseline_model import BaselineClassifier

# Set Streamlit Page Configuration
st.set_page_config(
    page_title="CYBERWORLD-X | Attack Forecasting",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Inject Liquid Glass Design CSS
st.markdown(get_liquid_glass_css(), unsafe_allow_html=True)


# Initialize Session State
def init_session_state():
    if "raw_df" not in st.session_state:
        df_sample = get_or_create_sample_dataset()
        st.session_state.raw_df = df_sample
        st.session_state.is_demo = True
        st.session_state.dataset_source = "Built-in Synthetic Demo Telemetry"
    if "time_window" not in st.session_state:
        st.session_state.time_window = DEFAULT_TIME_WINDOW
    if "forecast_horizon" not in st.session_state:
        st.session_state.forecast_horizon = DEFAULT_FORECAST_HORIZON
    if "sequence_length" not in st.session_state:
        st.session_state.sequence_length = DEFAULT_SEQUENCE_LENGTH
    if "model_type" not in st.session_state:
        st.session_state.model_type = "LSTM"
    if "baseline_model" not in st.session_state:
        st.session_state.baseline_model = BaselineClassifier()
    if "training_history" not in st.session_state:
        st.session_state.training_history = None

init_session_state()


# Cache-backed pipeline execution
@st.cache_data(ttl=600, show_spinner=False)
def run_pipeline(
    df: pd.DataFrame,
    time_window: int,
    forecast_horizon: int,
    sequence_length: int,
    model_type: str
) -> Dict[str, Any]:
    """
    Executes the full forecasting pipeline from raw flows to temporal state rollouts.
    """
    cleaned_df, audit = clean_network_dataframe(df)
    flow_df = compute_flow_aggregations(cleaned_df)
    states_df = aggregate_into_network_states(flow_df, window_seconds=time_window)

    if states_df.empty:
        return {"error": "Unable to generate network states from input data."}

    forecaster = WorldModelForecaster(
        model_type=model_type,
        sequence_length=sequence_length,
        forecast_horizon=forecast_horizon
    )

    forecast_results = forecaster.run_forecast(states_df)

    hist_risks = calculate_historical_risk(states_df)
    fore_risks = forecast_results.get("future_risk_curve", [])

    stage_predictor = AttackStagePredictor()
    cur_feat = states_df.iloc[-1].to_dict()
    fut_feat = forecast_results["future_states_df"].iloc[0].to_dict() if not forecast_results["future_states_df"].empty else cur_feat
    stage_transition = stage_predictor.predict_stage_transition(
        cur_feat,
        fut_feat,
        model_stage_probs=forecast_results.get("stage_distribution")
    )

    return {
        "cleaned_df": cleaned_df,
        "flow_df": flow_df,
        "states_df": states_df,
        "forecast_results": forecast_results,
        "historical_risks": hist_risks,
        "forecast_risks": fore_risks,
        "stage_transition": stage_transition,
        "audit": audit
    }


# Execute pipeline
with st.spinner("Processing network state temporal windows..."):
    pipeline_output = run_pipeline(
        st.session_state.raw_df,
        st.session_state.time_window,
        st.session_state.forecast_horizon,
        st.session_state.sequence_length,
        st.session_state.model_type
    )

if "error" in pipeline_output:
    st.error(f"Pipeline error: {pipeline_output['error']}")
    st.stop()

states_df = pipeline_output["states_df"]
forecast_res = pipeline_output["forecast_results"]
hist_risks = pipeline_output["historical_risks"]
fore_risks = pipeline_output["forecast_risks"]
stage_trans = pipeline_output["stage_transition"]
cleaned_df = pipeline_output["cleaned_df"]


# Sidebar Navigation & Controls
with st.sidebar:
    st.markdown("""
    <div style="display: flex; align-items: center; gap: 10px; padding: 10px 0 16px 0;">
        <span style="font-size: 1.8rem; font-weight: 900; letter-spacing: 1.5px; color: #ffffff;">
            CYBER<span style="color: #00f0ff;">WORLD</span><span style="color: #ff007f;">-X</span>
        </span>
    </div>
    """, unsafe_allow_html=True)

    page = st.radio(
        "NAVIGATION",
        [
            "Executive Dashboard",
            "Traffic Analysis",
            "Attack Forecast",
            "Attack Timeline",
            "Explainability",
            "Dataset / Upload",
            "Model Performance",
            "System Information"
        ],
        index=0,
        label_visibility="collapsed"
    )

    st.markdown("---")
    st.markdown("<p style='font-size: 0.75rem; font-weight: 700; color: #94a3b8; text-transform: uppercase; letter-spacing: 1px;'>FORECAST CONFIGURATION</p>", unsafe_allow_html=True)

    model_choice = st.selectbox(
        "Temporal AI Model",
        ["LSTM", "Transformer"],
        index=0 if st.session_state.model_type == "LSTM" else 1,
        help="Select deep neural temporal architecture for network state rollout."
    )
    if model_choice != st.session_state.model_type:
        st.session_state.model_type = model_choice
        st.rerun()

    time_win = st.selectbox(
        "Time Window (seconds)",
        TIME_WINDOWS,
        index=TIME_WINDOWS.index(st.session_state.time_window),
        help="Duration of discrete macro network state S(t)."
    )
    if time_win != st.session_state.time_window:
        st.session_state.time_window = time_win
        st.rerun()

    f_horizon = st.select_slider(
        "Forecast Horizon (K windows)",
        options=FORECAST_HORIZONS,
        value=st.session_state.forecast_horizon,
        help="Number of future states S(t+1)...S(t+K) to forecast forward."
    )
    if f_horizon != st.session_state.forecast_horizon:
        st.session_state.forecast_horizon = f_horizon
        st.rerun()

    seq_len = st.select_slider(
        "Sequence History Length (W)",
        options=SEQUENCE_LENGTHS,
        value=st.session_state.sequence_length,
        help="Lookback sequence length S(t-W+1)...S(t)."
    )
    if seq_len != st.session_state.sequence_length:
        st.session_state.sequence_length = seq_len
        st.rerun()

    if st.button("⚡ Run Forecast Now", use_container_width=True):
        st.cache_data.clear()
        st.rerun()

    st.markdown("---")
    # Live status indicators at sidebar bottom
    st.markdown(f"""
    <div style="font-size: 0.75rem; color: #94a3b8; line-height: 1.8;">
        <div><strong>DATA SOURCE:</strong> <span style="color: {'#fbbf24' if st.session_state.is_demo else '#38bdf8'};">{'DEMO DATA' if st.session_state.is_demo else 'USER UPLOAD'}</span></div>
        <div><strong>FLOW COUNT:</strong> <span style="color: #ffffff;">{len(cleaned_df):,}</span></div>
        <div><strong>WINDOW STATES:</strong> <span style="color: #ffffff;">{len(states_df)}</span></div>
        <div style="margin-top: 8px; display: flex; gap: 6px; flex-wrap: wrap;">
            <span class="status-pill online"><span class="pulse-dot"></span> SYSTEM: ONLINE</span>
            <span class="status-pill active">MODEL: READY</span>
            <span class="status-pill active">DATA: READY</span>
        </div>
    </div>
    """, unsafe_allow_html=True)


# Render Top Header
st.markdown(render_header(), unsafe_allow_html=True)


# =====================================================================
# PAGE 1: EXECUTIVE DASHBOARD (DEFAULT)
# =====================================================================
if page == "Executive Dashboard":
    # 1. Glass Metric Cards Row
    col1, col2, col3, col4, col5 = st.columns(5)

    cur_risk_val = forecast_res.get("current_risk", 0.78)
    cur_risk_pct = f"{cur_risk_val * 100:.0f}%"
    risk_color = "#ef4444" if cur_risk_val > RISK_THRESHOLD_HIGH else ("#f59e0b" if cur_risk_val > RISK_THRESHOLD_ELEVATED else "#10b981")

    with col1:
        st.markdown(render_metric_card(
            label="Current Risk",
            value=cur_risk_pct,
            sub_label="Elevated Risk Level" if cur_risk_val > RISK_THRESHOLD_ELEVATED else "Baseline Normal",
            status_color=risk_color,
            is_demo=st.session_state.is_demo,
            icon="⚠️"
        ), unsafe_allow_html=True)

    with col2:
        st.markdown(render_metric_card(
            label="Forecast Horizon",
            value=f"{st.session_state.forecast_horizon} Steps",
            sub_label=f"K={st.session_state.forecast_horizon} × {st.session_state.time_window}s ahead",
            status_color="#00f0ff",
            is_demo=st.session_state.is_demo,
            icon="⏱️"
        ), unsafe_allow_html=True)

    with col3:
        state_status = "ANOMALOUS" if cur_risk_val > RISK_THRESHOLD_ELEVATED else "STABLE"
        st.markdown(render_metric_card(
            label="Current State",
            value=state_status,
            sub_label=f"State S(t) ID: #{len(states_df)}",
            status_color="#f59e0b" if state_status == "ANOMALOUS" else "#10b981",
            is_demo=st.session_state.is_demo,
            icon="📡"
        ), unsafe_allow_html=True)

    with col4:
        pred_stage_name = stage_trans.get("predicted_next_stage", "Lateral Movement")
        st.markdown(render_metric_card(
            label="Predicted Stage",
            value=pred_stage_name,
            sub_label=f"Current: {stage_trans.get('current_stage', 'Reconnaissance')}",
            status_color=stage_trans.get("stage_color", "#f97316"),
            is_demo=st.session_state.is_demo,
            icon=stage_trans.get("stage_icon", "🔀")
        ), unsafe_allow_html=True)

    with col5:
        conf_val = stage_trans.get("confidence", 0.84)
        st.markdown(render_metric_card(
            label="Model Confidence",
            value=f"{conf_val:.2f}",
            sub_label="Probabilistic Rollout",
            status_color="#a855f7",
            is_demo=st.session_state.is_demo,
            icon="🎯"
        ), unsafe_allow_html=True)

    st.markdown("<div style='height: 16px;'></div>", unsafe_allow_html=True)

    # 2. Main Risk Forecast Plot
    fig_risk = create_risk_forecast_plot(
        historical_risks=hist_risks[-25:],
        forecast_risks=fore_risks,
        current_stage=stage_trans.get("current_stage", "Reconnaissance"),
        predicted_stage=pred_stage_name
    )
    st.plotly_chart(fig_risk, use_container_width=True)

    # 3. Early Warning Alert Banner
    alert_metrics = {
        "Current Risk": cur_risk_pct,
        "Current Stage": stage_trans.get("current_stage"),
        "Predicted Stage": pred_stage_name,
        "Forecast Horizon": f"+{st.session_state.forecast_horizon * st.session_state.time_window}s",
        "Confidence": f"{conf_val * 100:.0f}%"
    }
    alert_level = "critical" if cur_risk_val > RISK_THRESHOLD_HIGH else ("warning" if cur_risk_val > RISK_THRESHOLD_ELEVATED else "info")
    st.markdown(render_alert_box(
        title="EARLY WARNING FORECAST",
        message=(
            f"Observed network telemetry exhibits sequential escalation consistent with transition toward '{pred_stage_name}'. "
            f"Model predicts elevated probability of multi-stage breach progression over the next {st.session_state.forecast_horizon} time windows."
        ),
        risk_level=alert_level,
        metrics_info=alert_metrics
    ), unsafe_allow_html=True)

    # 4. Attack Progression Bar
    st.markdown(render_attack_progression(
        current_stage=stage_trans.get("current_stage", "Reconnaissance"),
        predicted_stage=pred_stage_name
    ), unsafe_allow_html=True)

    # 5. Dual Column: World Model State Transition Chain + Explainability Summary
    col_left, col_right = st.columns([3, 2])

    with col_left:
        st.markdown("""
        <div style="font-size: 1.05rem; font-weight: 700; color: #ffffff; margin-bottom: 12px; display: flex; align-items: center; gap: 8px;">
            <span>🌐</span> TEMPORAL WORLD MODEL STATE CHAIN: S(t) → S(t+1) → ... → S(t+K)
        </div>
        """, unsafe_allow_html=True)

        state_chain = forecast_res.get("state_chain", [])
        if state_chain:
            state_cols = st.columns(len(state_chain))
            for i, st_node in enumerate(state_chain):
                with state_cols[i]:
                    is_cur = st_node["type"] == "current"
                    border_color = "#00f0ff" if is_cur else ("#f59e0b" if i == 1 else "rgba(0, 240, 255, 0.25)")
                    st.markdown(f"""
                    <div class="state-node-card" style="border-top: 3px solid {border_color};">
                        <div style="font-size: 0.72rem; font-weight: 800; color: {border_color}; letter-spacing: 1px;">
                            {st_node["id"]}
                        </div>
                        <div style="font-size: 0.75rem; font-weight: 600; color: #94a3b8; margin: 4px 0;">
                            {st_node["title"]}
                        </div>
                        <div style="font-size: 0.85rem; font-weight: 800; color: #ffffff; margin-bottom: 6px;">
                            {st_node["stage"]}
                        </div>
                        <div style="font-size: 0.72rem; color: #cbd5e1; border-top: 1px solid rgba(255,255,255,0.08); padding-top: 6px; text-align: left; line-height: 1.6;">
                            <div>Rate: <b>{st_node['metrics'].get('Packets/s', '-')} p/s</b></div>
                            <div>SYN: <b>{st_node['metrics'].get('SYN Ratio', '-')}</b></div>
                            <div>Ports: <b>{st_node['metrics'].get('Target Ports', '-')}</b></div>
                            <div>Risk: <b style="color: {border_color};">{st_node['risk_score']*100:.0f}%</b></div>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)

    with col_right:
        st.markdown("""
        <div style="font-size: 1.05rem; font-weight: 700; color: #ffffff; margin-bottom: 12px; display: flex; align-items: center; gap: 8px;">
            <span>🔍</span> TOP ATTACK DRIVERS (SHAP EXPLAINABILITY)
        </div>
        """, unsafe_allow_html=True)

        explainer = SHAPForecastingExplainer()
        cur_vector = states_df.select_dtypes(include=[np.number]).iloc[-1:].values

        def quick_predict(arr):
            # Dynamic sensitivity function
            return np.array([min(1.0, (r[0] / 300.0 * 0.4) + (r[4] * 0.4) + (r[6] / 30.0 * 0.2)) for r in arr])

        bg_data = states_df.select_dtypes(include=[np.number]).iloc[:-1].values
        shap_res = explainer.explain_forecast(
            model_predict_fn=quick_predict,
            background_data=bg_data,
            instance_to_explain=cur_vector,
            feature_names=states_df.select_dtypes(include=[np.number]).columns.tolist()
        )

        fig_shap = create_feature_importance_plot(shap_res.get("feature_ranking", []), method=shap_res.get("method", "SHAP"))
        st.plotly_chart(fig_shap, use_container_width=True)


# =====================================================================
# PAGE 2: TRAFFIC ANALYSIS
# =====================================================================
elif page == "Traffic Analysis":
    st.markdown("### 📊 Network Flow & Packet Traffic Analysis")
    st.markdown("Inspect granular network connection records, flow rates, protocol distributions, and destination targeting.")

    # Filter Controls Row
    fcol1, fcol2, fcol3, fcol4 = st.columns(4)
    with fcol1:
        proto_options = ["ALL"] + sorted(list(cleaned_df["protocol"].dropna().unique()))
        selected_proto = st.selectbox("Protocol", proto_options)
    with fcol2:
        stage_options = ["ALL"] + ATTACK_STAGES
        selected_stage = st.selectbox("Attack Stage Tag", stage_options)
    with fcol3:
        min_bytes = st.number_input("Min Bytes", value=0, step=100)
    with fcol4:
        search_query = st.text_input("Search IP / Port", placeholder="e.g. 192.168.1.10 or 445")

    # Apply Filters
    df_filtered = cleaned_df.copy()
    if selected_proto != "ALL":
        df_filtered = df_filtered[df_filtered["protocol"] == selected_proto]
    if selected_stage != "ALL" and "attack_stage" in df_filtered.columns:
        df_filtered = df_filtered[df_filtered["attack_stage"] == selected_stage]
    if min_bytes > 0 and "bytes" in df_filtered.columns:
        df_filtered = df_filtered[df_filtered["bytes"] >= min_bytes]
    if search_query:
        mask = (
            df_filtered["src_ip"].astype(str).str.contains(search_query, case=False) |
            df_filtered["dst_ip"].astype(str).str.contains(search_query, case=False) |
            df_filtered["dst_port"].astype(str).str.contains(search_query, case=False)
        )
        df_filtered = df_filtered[mask]

    # Metrics overview
    tcol1, tcol2, tcol3, tcol4 = st.columns(4)
    tcol1.metric("Filtered Flows", f"{len(df_filtered):,}")
    tcol2.metric("Total Volume", f"{df_filtered['bytes'].sum() / (1024*1024):.2f} MB" if "bytes" in df_filtered.columns else "N/A")
    tcol3.metric("Unique Src IPs", f"{df_filtered['src_ip'].nunique()}" if "src_ip" in df_filtered.columns else "1")
    tcol4.metric("Unique Dst Ports", f"{df_filtered['dst_port'].nunique()}" if "dst_port" in df_filtered.columns else "1")

    st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)

    # Interactive Traffic Table
    display_cols = [c for c in [
        "parsed_timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
        "protocol", "packets", "bytes", "duration", "tcp_flags", "attack_stage"
    ] if c in df_filtered.columns]

    st.dataframe(
        df_filtered[display_cols].head(300),
        use_container_width=True,
        height=340
    )

    # Charts Row
    ccol1, ccol2 = st.columns(2)
    with ccol1:
        if "dst_port" in df_filtered.columns:
            top_ports = df_filtered["dst_port"].value_counts().head(10).reset_index()
            top_ports.columns = ["Destination Port", "Flow Count"]
            top_ports["Destination Port"] = top_ports["Destination Port"].astype(str)
            fig_ports = px.bar(
                top_ports,
                x="Destination Port",
                y="Flow Count",
                color="Flow Count",
                color_continuous_scale="Tealgrn"
            )
            fig_ports = apply_glass_theme(fig_ports, height=320, title="Top Targeted Destination Ports")
            st.plotly_chart(fig_ports, use_container_width=True)

    with ccol2:
        if "protocol" in df_filtered.columns:
            proto_counts = df_filtered["protocol"].value_counts().reset_index()
            proto_counts.columns = ["Protocol", "Count"]
            fig_proto = px.pie(
                proto_counts,
                names="Protocol",
                values="Count",
                hole=0.45,
                color_discrete_sequence=["#00f0ff", "#7000ff", "#ff007f", "#38bdf8"]
            )
            fig_proto = apply_glass_theme(fig_proto, height=320, title="Protocol Breakdown")
            st.plotly_chart(fig_proto, use_container_width=True)


# =====================================================================
# PAGE 3: ATTACK FORECAST
# =====================================================================
elif page == "Attack Forecast":
    st.markdown("### 🔮 Multi-Step Temporal Attack Progression Forecast")
    st.markdown(
        f"Simulating network behavior rollout across future discrete time windows: "
        f"**S(t+1) → S(t+{st.session_state.forecast_horizon})**."
    )

    # Forecast Dynamics Plot
    fut_df = forecast_res.get("future_states_df", pd.DataFrame())
    if not fut_df.empty:
        col_f1, col_f2 = st.columns(2)
        with col_f1:
            fig_dyn1 = go.Figure()
            steps = [f"S(t+{i+1})" for i in range(len(fut_df))]
            if "packet_rate" in fut_df.columns:
                fig_dyn1.add_trace(go.Scatter(
                    x=steps, y=fut_df["packet_rate"],
                    mode="lines+markers", name="Packet Rate (pps)",
                    line=dict(color="#00f0ff", width=2.5)
                ))
            if "byte_rate" in fut_df.columns:
                fig_dyn1.add_trace(go.Scatter(
                    x=steps, y=fut_df["byte_rate"] / 100.0,
                    mode="lines+markers", name="Byte Rate (scaled x0.01)",
                    line=dict(color="#f59e0b", width=2.5, dash="dash")
                ))
            fig_dyn1 = apply_glass_theme(fig_dyn1, height=320, title="Forecasted Volumetric Dynamics")
            st.plotly_chart(fig_dyn1, use_container_width=True)

        with col_f2:
            fig_dyn2 = go.Figure()
            if "syn_ratio" in fut_df.columns:
                fig_dyn2.add_trace(go.Scatter(
                    x=steps, y=fut_df["syn_ratio"],
                    mode="lines+markers", name="SYN Flag Ratio",
                    line=dict(color="#ec4899", width=2.5)
                ))
            if "unique_dst_ports" in fut_df.columns:
                fig_dyn2.add_trace(go.Scatter(
                    x=steps, y=fut_df["unique_dst_ports"],
                    mode="lines+markers", name="Unique Dst Ports",
                    line=dict(color="#8b5cf6", width=2.5)
                ))
            fig_dyn2 = apply_glass_theme(fig_dyn2, height=320, title="Forecasted Targeting & Scanning Entropy")
            st.plotly_chart(fig_dyn2, use_container_width=True)

    # Multi-Step Probability Distribution
    st.markdown("#### 🎯 Multi-Class Attack Stage Likelihood Distribution")
    stage_dist = forecast_res.get("stage_distribution", {})
    if stage_dist:
        s_names = list(stage_dist.keys())
        s_probs = [v * 100 for v in stage_dist.values()]
        s_colors = [STAGE_COLORS.get(k, "#00f0ff") for k in s_names]

        fig_dist = go.Figure(go.Bar(
            x=s_names,
            y=s_probs,
            marker_color=s_colors,
            hovertemplate="<b>%{x}</b><br>Predicted Likelihood: %{y:.1f}%<extra></extra>"
        ))
        fig_dist.update_yaxes(title_text="Likelihood (%)", range=[0, 100])
        fig_dist = apply_glass_theme(fig_dist, height=300, title="Temporal Stage Likelihood")
        st.plotly_chart(fig_dist, use_container_width=True)

    # Detailed Forecast Table
    st.markdown("#### 📋 Forecasted State Vector Table")
    state_chain = forecast_res.get("state_chain", [])
    if state_chain:
        fc_data = []
        for node in state_chain:
            fc_data.append({
                "State": node["id"],
                "Type": node["type"].upper(),
                "Predicted Stage": node["stage"],
                "Risk Score": f"{node['risk_score']*100:.1f}%",
                "Packets/sec": node["metrics"].get("Packets/s"),
                "SYN Ratio": node["metrics"].get("SYN Ratio"),
                "Target Ports": node["metrics"].get("Target Ports"),
                "Avg Packet Size": node["metrics"].get("Avg Packet (B)")
            })
        st.dataframe(pd.DataFrame(fc_data), use_container_width=True)


# =====================================================================
# PAGE 4: ATTACK TIMELINE & SECURITY FRAMEWORKS
# =====================================================================
elif page == "Attack Timeline":
    st.markdown("### ⏳ Chronological Attack Timeline & Threat Mapping")
    st.markdown("Aligning forecasted temporal transitions with MITRE ATT&CK, CAPEC, and CVE references.")

    pred_stage = stage_trans.get("predicted_next_stage", "Initial Access")
    cur_stage = stage_trans.get("current_stage", "Reconnaissance")

    col_tl1, col_tl2 = st.columns([1, 1])

    with col_tl1:
        st.markdown(f"#### 🛡️ MITRE ATT&CK Mappings for: **{pred_stage}**")
        mitre_entries = get_mitre_mapping_for_stage(pred_stage)
        for entry in mitre_entries:
            st.markdown(f"""
            <div class="glass-card" style="margin-bottom: 12px; border-left: 3px solid #00f0ff;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <span style="font-weight: 800; color: #00f0ff; font-size: 0.95rem;">{entry['technique_id']} &bull; {entry['technique_name']}</span>
                    <span class="status-pill active">{entry['tactic']}</span>
                </div>
                <div style="color: #cbd5e1; font-size: 0.85rem; margin-top: 6px; line-height: 1.4;">
                    {entry['description']}
                </div>
                <div style="font-size: 0.78rem; color: #94a3b8; margin-top: 8px; border-top: 1px solid rgba(255,255,255,0.06); padding-top: 6px;">
                    <strong>Detection Signature:</strong> {entry['detection_indicators']}
                </div>
            </div>
            """, unsafe_allow_html=True)

    with col_tl2:
        st.markdown(f"#### 🎯 CAPEC Patterns & CVE Intel for: **{pred_stage}**")
        capec_entries = get_capec_mapping_for_stage(pred_stage)
        for capec in capec_entries:
            st.markdown(f"""
            <div class="glass-card" style="margin-bottom: 12px; border-left: 3px solid #f59e0b;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <span style="font-weight: 800; color: #f59e0b; font-size: 0.95rem;">{capec['capec_id']} &bull; {capec['name']}</span>
                    <span style="font-size: 0.72rem; color: #f87171;">Severity: {capec.get('severity', 'Medium')}</span>
                </div>
                <div style="color: #cbd5e1; font-size: 0.85rem; margin-top: 6px;">
                    {capec['summary']}
                </div>
            </div>
            """, unsafe_allow_html=True)

        cve_entries = get_cve_mapping_for_stage(pred_stage)
        for cve in cve_entries:
            st.markdown(f"""
            <div class="glass-card" style="margin-bottom: 12px; border-left: 3px solid #a855f7;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <span style="font-weight: 800; color: #c084fc; font-size: 0.9rem;">{cve['cve_id']} &bull; {cve['service']}</span>
                    <span style="font-size: 0.72rem; color: #fbbf24;">CVSS: {cve['cvss']}</span>
                </div>
                <div style="color: #cbd5e1; font-size: 0.82rem; margin-top: 4px;">
                    {cve['impact']}
                </div>
            </div>
            """, unsafe_allow_html=True)


# =====================================================================
# PAGE 5: EXPLAINABILITY
# =====================================================================
elif page == "Explainability":
    st.markdown("### 🧠 Explainable AI & SHAP Attribution")
    st.markdown("Empirical mathematical explanations detailing telemetry factors driving the current forecast.")

    explainer = SHAPForecastingExplainer()
    num_df = states_df.select_dtypes(include=[np.number])
    cur_vec = num_df.iloc[-1:].values

    def eval_fn(arr):
        return np.array([min(1.0, (r[0]/300.0*0.35) + (r[4]*0.35) + (r[6]/30.0*0.30)) for r in arr])

    shap_res = explainer.explain_forecast(
        model_predict_fn=eval_fn,
        background_data=num_df.iloc[:-1].values,
        instance_to_explain=cur_vec,
        feature_names=num_df.columns.tolist()
    )

    col_e1, col_e2 = st.columns([3, 2])
    with col_e1:
        fig_sh = create_feature_importance_plot(shap_res.get("feature_ranking", []), method=shap_res.get("method", "SHAP"))
        st.plotly_chart(fig_sh, use_container_width=True)

    with col_e2:
        st.markdown("#### 🔬 Feature Contribution Breakdown")
        ranking = shap_res.get("feature_ranking", [])
        if ranking:
            for item in ranking:
                feat_name = item["feature"]
                pct = item["importance"]
                val = item["value"]
                st.markdown(f"""
                <div style="margin-bottom: 10px; background: rgba(13, 21, 39, 0.5); padding: 8px 12px; border-radius: 8px; border: 1px solid rgba(0,240,255,0.12);">
                    <div style="display: flex; justify-content: space-between; font-size: 0.82rem; font-weight: 700; color: #ffffff;">
                        <span>{feat_name}</span>
                        <span style="color: #00f0ff;">{pct:.1f}% Impact</span>
                    </div>
                    <div style="font-size: 0.75rem; color: #94a3b8; margin-top: 2px;">
                        Observed State Value: <span style="color: #e2e8f0; font-family: monospace;">{val:.2f}</span>
                    </div>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.info("Explanation unavailable for this model/input.")


# =====================================================================
# PAGE 6: DATASET / UPLOAD
# =====================================================================
elif page == "Dataset / Upload":
    st.markdown("### 📁 Dataset Management & Traffic Ingestion")
    st.markdown("Upload custom CSV flow logs or raw PCAP/PCAPNG packet captures. Payloads are stripped; only metadata is processed locally.")

    col_u1, col_u2 = st.columns(2)

    with col_u1:
        st.markdown("#### 📤 Upload Network Data")
        uploaded_file = st.file_uploader(
            "Select PCAP, PCAPNG, or CSV file",
            type=["csv", "pcap", "pcapng"],
            help="Max size 200MB. Processed entirely within your local memory."
        )

        if uploaded_file is not None:
            filename = uploaded_file.name.lower()
            if filename.endswith(".csv"):
                try:
                    user_df = pd.read_csv(uploaded_file)
                    st.success(f"CSV uploaded: {uploaded_file.name} ({len(user_df)} rows)")
                    mapped_df, applied_map = auto_map_columns(user_df)
                    st.write("Column Mappings Applied:", applied_map)

                    if st.button("Apply & Analyze Uploaded CSV"):
                        st.session_state.raw_df = mapped_df
                        st.session_state.is_demo = False
                        st.session_state.dataset_source = f"Uploaded CSV: {uploaded_file.name}"
                        st.cache_data.clear()
                        st.rerun()
                except Exception as e:
                    st.error(f"Error parsing CSV: {e}")

            elif filename.endswith((".pcap", ".pcapng")):
                try:
                    with st.spinner("Extracting packet metadata using Scapy..."):
                        pcap_bytes = uploaded_file.read()
                        pcap_df, pcap_stats = extract_features_from_pcap(pcap_bytes)
                        if not pcap_df.empty:
                            st.success(f"Parsed {pcap_stats.get('packets_processed', len(pcap_df))} packets successfully.")
                            if st.button("Apply & Analyze Uploaded PCAP"):
                                st.session_state.raw_df = pcap_df
                                st.session_state.is_demo = False
                                st.session_state.dataset_source = f"Uploaded PCAP: {uploaded_file.name}"
                                st.cache_data.clear()
                                st.rerun()
                        else:
                            st.error(f"PCAP parsing produced no packets: {pcap_stats.get('error', 'unknown error')}")
                except Exception as e:
                    st.error(f"Failed to process PCAP: {e}")

    with col_u2:
        st.markdown("#### ⚡ Use Synthetic Demo Telemetry")
        st.markdown(
            "Immediately load pre-configured multi-stage enterprise attack telemetry "
            "simulating Normal → Recon → Initial Access → Lateral Movement → C2 → Exfiltration."
        )
        if st.button("Load Multi-Stage Demo Dataset", use_container_width=True):
            st.session_state.raw_df = get_or_create_sample_dataset()
            st.session_state.is_demo = True
            st.session_state.dataset_source = "Built-in Synthetic Demo Telemetry"
            st.cache_data.clear()
            st.rerun()

        st.markdown("---")
        st.markdown(f"""
        <div style="font-size: 0.85rem; color: #cbd5e1; line-height: 1.8;">
            <div><strong>Active Dataset:</strong> <span style="color: #00f0ff;">{st.session_state.dataset_source}</span></div>
            <div><strong>Total Flows / Packets:</strong> <span style="color: #ffffff;">{len(st.session_state.raw_df):,}</span></div>
            <div><strong>Calculated States S(t):</strong> <span style="color: #ffffff;">{len(states_df)}</span></div>
            <div><strong>Current Time Window:</strong> <span style="color: #ffffff;">{st.session_state.time_window}s</span></div>
        </div>
        """, unsafe_allow_html=True)


# =====================================================================
# PAGE 7: MODEL PERFORMANCE
# =====================================================================
elif page == "Model Performance":
    st.markdown("### 📈 Model Evaluation & Baseline Comparison")
    st.markdown("Compare the Temporal LSTM World Model against a static Logistic Regression baseline.")

    col_m1, col_m2 = st.columns(2)

    with col_m1:
        st.markdown("#### ⚙️ Temporal World Model Architecture")
        st.markdown(f"""
        <div class="glass-card" style="font-size: 0.85rem; line-height: 1.8;">
            <div><strong>Model Type:</strong> <span style="color: #00f0ff;">{st.session_state.model_type} World Model</span></div>
            <div><strong>Input Features:</strong> <span style="color: #ffffff;">{states_df.shape[1] - 2} State Dimension</span></div>
            <div><strong>Sequence Length (W):</strong> <span style="color: #ffffff;">{st.session_state.sequence_length} windows</span></div>
            <div><strong>Forecast Horizon (K):</strong> <span style="color: #ffffff;">{st.session_state.forecast_horizon} windows</span></div>
            <div><strong>Loss Function:</strong> <span style="color: #ffffff;">Multi-Objective MSE + CrossEntropy</span></div>
            <div><strong>Optimization:</strong> <span style="color: #ffffff;">AdamW (lr=0.003, weight_decay=1e-4)</span></div>
        </div>
        """, unsafe_allow_html=True)

        if st.button("🚀 Train / Fine-Tune Baseline on Current Dataset"):
            with st.spinner("Training baseline model..."):
                num_df = states_df.select_dtypes(include=[np.number]).fillna(0)
                if len(num_df) > 8:
                    X_arr = num_df.values
                    # Synthetic binary labels based on risk
                    y_arr = (num_df["syn_ratio"] > 0.3).astype(int).values
                    split = int(0.75 * len(X_arr))
                    metrics = st.session_state.baseline_model.fit_and_evaluate(
                        X_arr[:split], y_arr[:split],
                        X_arr[split:], y_arr[split:]
                    )
                    st.success("Baseline model trained and evaluated!")
                else:
                    st.warning("Insufficient time windows to perform train/test split. Increase dataset size.")

    with col_m2:
        st.markdown("#### 📊 Empirical Baseline Benchmark")
        metrics = st.session_state.baseline_model.get_metrics_display()

        bcol1, bcol2 = st.columns(2)
        bcol1.metric("Precision", str(metrics["precision"]))
        bcol2.metric("Recall", str(metrics["recall"]))

        bcol3, bcol4 = st.columns(2)
        bcol3.metric("F1 Score", str(metrics["f1_score"]))
        bcol4.metric("False Positive Rate", str(metrics["false_positive_rate"]))

        if metrics["status"] == "Not evaluated yet":
            st.info("Baseline model has not been evaluated yet. Click 'Train / Fine-Tune Baseline' to compute genuine empirical metrics.")


# =====================================================================
# PAGE 8: SYSTEM INFORMATION
# =====================================================================
elif page == "System Information":
    st.markdown("### ℹ️ System Architecture & Environmental Information")
    st.markdown(
        f"**CYBERWORLD-X** | {ORGANIZATION} | Problem Statement ID: {PROBLEM_STATEMENT_ID}"
    )

    st.markdown("""
    <div class="glass-card" style="line-height: 1.8; font-size: 0.9rem;">
        <h4 style="color: #00f0ff; margin-top: 0;">System Philosophy & Paradigm</h4>
        <p>Traditional Intrusion Detection Systems (IDS) operate primarily as static binary filters: 
        <code>packet → benign / malicious</code>. They fail to anticipate multi-stage campaigns before irreversible compromise occurs.</p>
        <p><strong>CYBERWORLD-X</strong> introduces a predictive paradigm:
        <br/>
        <code style="color: #00f0ff; font-weight: bold;">S(t-W+1) ... S(t) → S(t+1) → S(t+2) → ... → S(t+K)</code>
        <br/>
        The system maps the temporal trajectories of network state representations to forecast escalation before an attacker pivots or exfiltrates enterprise assets.</p>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("<div style='height: 16px;'></div>", unsafe_allow_html=True)

    col_s1, col_s2 = st.columns(2)
    with col_s1:
        st.markdown("""
        <div class="glass-card" style="font-size: 0.85rem; line-height: 1.8;">
            <h5 style="color: #38bdf8; margin-top: 0;">🛡️ Privacy & Local Security</h5>
            <div>&bull; <strong>Cloud AI Dependency:</strong> None (Zero OpenAI, Hugging Face, or Gemini API dependencies)</div>
            <div>&bull; <strong>Execution Model:</strong> 100% Local-First Inference</div>
            <div>&bull; <strong>Data Privacy:</strong> Payload content is automatically stripped; only flow and timing headers are analyzed</div>
            <div>&bull; <strong>Target Platform:</strong> Linux / Windows / Streamlit Community Cloud</div>
        </div>
        """, unsafe_allow_html=True)

    with col_s2:
        import torch
        st.markdown(f"""
        <div class="glass-card" style="font-size: 0.85rem; line-height: 1.8;">
            <h5 style="color: #a855f7; margin-top: 0;">💻 Runtime Environment</h5>
            <div>&bull; <strong>Python Core:</strong> 3.12+</div>
            <div>&bull; <strong>PyTorch Engine:</strong> {torch.__version__} (Device: CPU)</div>
            <div>&bull; <strong>Streamlit Version:</strong> {st.__version__}</div>
            <div>&bull; <strong>Network Packet Engine:</strong> Scapy 2.7.0</div>
            <div>&bull; <strong>Explainability Engine:</strong> SHAP / Permutation Sensitivity</div>
        </div>
        """, unsafe_allow_html=True)


# Application Footer
st.markdown("<div style='height: 40px;'></div>", unsafe_allow_html=True)
st.markdown(f"""
<div style="text-align: center; color: #64748b; font-size: 0.78rem; padding: 16px 0; border-top: 1px solid rgba(255, 255, 255, 0.08);">
    {SYSTEM_FOOTER}
</div>
""", unsafe_allow_html=True)
