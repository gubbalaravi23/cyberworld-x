"""
CYBERWORLD-X: World Model Orchestrator & State Transition Engine
NTRO SIH 2026 | Problem Statement ID: 26153

Coordinates the core concept:
S(t) -> S(t+1) -> S(t+2) -> ... -> S(t+K)

Transforms past network states into multi-step forward rollouts,
mapping feature trajectory evolution into future risk scores and stage transitions.
"""

from typing import Any, Dict, List, Optional, Tuple
import numpy as np
import pandas as pd

from models.model_loader import get_world_model
from preprocessing.normalization import NetworkFeatureScaler
from utils.constants import ATTACK_STAGES, NETWORK_STATE_FEATURES


class WorldModelForecaster:
    """
    Simulates and forecasts future network behavioral states using temporal neural world models.
    """

    def __init__(
        self,
        model_type: str = "LSTM",
        sequence_length: int = 10,
        forecast_horizon: int = 5
    ):
        self.model_type = model_type
        self.sequence_length = sequence_length
        self.forecast_horizon = forecast_horizon
        self.scaler = NetworkFeatureScaler(method="robust")
        self.world_model = get_world_model(
            model_type=model_type,
            input_size=len(NETWORK_STATE_FEATURES),
            sequence_length=sequence_length,
            forecast_horizon=forecast_horizon
        )

    def run_forecast(
        self,
        df_states: pd.DataFrame
    ) -> Dict[str, Any]:
        """
        Executes future state forecasting from historical state observations S(t).
        
        Returns:
            Dict containing:
                - state_chain: List of dicts representing S(t), S(t+1) ... S(t+K)
                - future_states_df: DataFrame of forecasted feature values
                - stage_distribution: Probability distribution across ATTACK_STAGES
                - current_risk: Risk of S(t)
                - future_risk_curve: Array of risk scores across forecast horizon
                - forecast_horizon: K
        """
        if df_states.empty:
            return {"error": "Empty state sequence provided"}

        feature_cols = [c for c in NETWORK_STATE_FEATURES if c in df_states.columns]
        if len(feature_cols) < 5:
            # Fallback to whatever numerical columns exist
            feature_cols = df_states.select_dtypes(include=[np.number]).columns.tolist()[:14]

        # 1. Scale state features
        X_scaled = self.scaler.fit_transform(df_states, feature_cols)

        # 2. Extract recent sequence window S(t-W+1) ... S(t)
        if len(X_scaled) < self.sequence_length:
            pad_len = self.sequence_length - len(X_scaled)
            first_row = X_scaled[0:1]
            padded_prefix = np.repeat(first_row, pad_len, axis=0)
            seq_window = np.vstack([padded_prefix, X_scaled])
        else:
            seq_window = X_scaled[-self.sequence_length:]

        # 3. Model inference: Future states, stage logits, risk curve
        pred_scaled_states, stage_probs, risk_curve = self.world_model.predict_future(seq_window)

        # Inverse transform predicted states back to physical metrics
        pred_raw_states = self.scaler.inverse_transform(pred_scaled_states)
        pred_df = pd.DataFrame(pred_raw_states, columns=feature_cols)

        # Ensure non-negative counts
        for col in ["packet_count", "byte_count", "packet_rate", "byte_rate", "unique_dst_ips", "unique_dst_ports"]:
            if col in pred_df.columns:
                pred_df[col] = pred_df[col].clip(lower=0)

        # 4. Construct S(t) -> S(t+1) -> ... -> S(t+K) State Chain
        state_chain = []

        # Current State S(t)
        current_state_row = df_states.iloc[-1]
        cur_syn_ratio = float(current_state_row.get("syn_ratio", 0.0))
        cur_packet_rate = float(current_state_row.get("packet_rate", 10.0))
        cur_dst_ports = int(current_state_row.get("unique_dst_ports", 1))

        # Dynamic risk calculation for current state
        cur_risk = min(0.95, max(0.05, float(
            (cur_syn_ratio * 0.35) +
            (min(cur_packet_rate, 500) / 500.0 * 0.35) +
            (min(cur_dst_ports, 50) / 50.0 * 0.30)
        )))

        current_stage = str(current_state_row.get("attack_stage", "Normal Activity"))

        state_chain.append({
            "id": "S(t)",
            "title": "CURRENT STATE",
            "type": "current",
            "stage": current_stage,
            "risk_score": cur_risk,
            "metrics": {
                "Packets/s": f"{cur_packet_rate:.1f}",
                "SYN Ratio": f"{cur_syn_ratio:.2f}",
                "Target Ports": f"{cur_dst_ports}",
                "Avg Packet (B)": f"{float(current_state_row.get('avg_packet_size', 64)):.0f}"
            }
        })

        # Forecasted States S(t+1) ... S(t+K)
        # Stage progression mapping
        stages = [
            "Normal Activity",
            "Reconnaissance",
            "Initial Access",
            "Lateral Movement",
            "Command and Control",
            "Exfiltration"
        ]

        top_stage_idx = int(np.argmax(stage_probs))
        pred_top_stage = stages[top_stage_idx % len(stages)]

        for k in range(self.forecast_horizon):
            step_num = k + 1
            step_row = pred_df.iloc[k]
            step_risk = float(risk_curve[k]) if k < len(risk_curve) else (cur_risk + (k * 0.05))
            step_risk = float(np.clip(step_risk, 0.02, 0.98))

            # Progression stage forecast for future steps
            if step_risk < 0.30:
                step_stage = "Normal Activity"
            elif step_risk < 0.50:
                step_stage = "Reconnaissance"
            elif step_risk < 0.68:
                step_stage = "Initial Access"
            elif step_risk < 0.82:
                step_stage = "Lateral Movement"
            elif step_risk < 0.90:
                step_stage = "Command and Control"
            else:
                step_stage = "Exfiltration"

            # If model strongly predicts a specific stage, bias near-term forecast towards it
            if k == 0 and stage_probs[top_stage_idx] > 0.4:
                step_stage = pred_top_stage

            state_chain.append({
                "id": f"S(t+{step_num})",
                "title": f"FORECAST {step_num}",
                "type": "forecast",
                "stage": step_stage,
                "risk_score": step_risk,
                "metrics": {
                    "Packets/s": f"{float(step_row.get('packet_rate', 15.0)):.1f}",
                    "SYN Ratio": f"{float(step_row.get('syn_ratio', 0.1)):.2f}",
                    "Target Ports": f"{int(step_row.get('unique_dst_ports', 2))}",
                    "Avg Packet (B)": f"{float(step_row.get('avg_packet_size', 128)):.0f}"
                }
            })

        stage_dist_dict = {stages[i % len(stages)]: float(stage_probs[i]) for i in range(len(stages))}

        return {
            "state_chain": state_chain,
            "future_states_df": pred_df,
            "stage_distribution": stage_dist_dict,
            "current_risk": cur_risk,
            "future_risk_curve": [s["risk_score"] for s in state_chain[1:]],
            "forecast_horizon": self.forecast_horizon,
            "predicted_next_stage": state_chain[1]["stage"] if len(state_chain) > 1 else pred_top_stage,
            "confidence": float(np.max(stage_probs))
        }
