"""
CYBERWORLD-X: PyTorch Transformer Temporal World Model
NTRO SIH 2026 | Problem Statement ID: 26153

Multi-Head Self-Attention model capturing long-range temporal dependencies
across network state transitions S(t-W) ... S(t) -> S(t+K).
"""

import os
os.environ["KMP_DUPLICATE_LIB_OK"] = "TRUE"

import math
import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np
from typing import Dict, Tuple


class PositionalEncoding(nn.Module):
    def __init__(self, d_model: int, max_len: int = 100):
        super().__init__()
        pe = torch.zeros(max_len, d_model)
        position = torch.arange(0, max_len, dtype=torch.float).unsqueeze(1)
        div_term = torch.exp(torch.arange(0, d_model, 2).float() * (-math.log(10000.0) / d_model))
        pe[:, 0::2] = torch.sin(position * div_term)
        pe[:, 1::2] = torch.cos(position * div_term)
        pe = pe.unsqueeze(0)
        self.register_buffer("pe", pe)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return x + self.pe[:, :x.size(1)]


class PyTorchTransformerWorldModel(nn.Module):
    """
    Transformer Encoder architecture for temporal state forecasting.
    """

    def __init__(
        self,
        input_size: int = 14,
        d_model: int = 64,
        nhead: int = 4,
        num_layers: int = 2,
        dim_feedforward: int = 128,
        dropout: float = 0.1,
        sequence_length: int = 10,
        forecast_horizon: int = 5,
        num_classes: int = 6
    ):
        super(PyTorchTransformerWorldModel, self).__init__()
        self.input_size = input_size
        self.d_model = d_model
        self.forecast_horizon = forecast_horizon
        self.sequence_length = sequence_length

        # Input Embedding Projection
        self.input_proj = nn.Linear(input_size, d_model)
        self.pos_encoder = PositionalEncoding(d_model)

        encoder_layer = nn.TransformerEncoderLayer(
            d_model=d_model,
            nhead=nhead,
            dim_feedforward=dim_feedforward,
            dropout=dropout,
            batch_first=True
        )
        self.transformer_encoder = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)

        # Multi-step state forecasting head
        self.state_projector = nn.Sequential(
            nn.Linear(d_model, d_model),
            nn.GELU(),
            nn.Linear(d_model, forecast_horizon * input_size)
        )

        # Stage classification head
        self.stage_head = nn.Linear(d_model, num_classes)

        # Risk curve head
        self.risk_head = nn.Sequential(
            nn.Linear(d_model, 32),
            nn.ReLU(),
            nn.Linear(32, forecast_horizon),
            nn.Sigmoid()
        )

    def forward(
        self, x: torch.Tensor
    ) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        batch_size = x.size(0)
        # Linear projection to d_model
        emb = self.input_proj(x)
        emb = self.pos_encoder(emb)

        # Pass through Transformer encoder
        encoded = self.transformer_encoder(emb)
        pooled = encoded.mean(dim=1)  # Mean pooling over sequence

        # Heads
        states_flat = self.state_projector(pooled)
        future_states = states_flat.view(batch_size, self.forecast_horizon, self.input_size)
        stage_logits = self.stage_head(pooled)
        risk_forecast = self.risk_head(pooled)

        return future_states, stage_logits, risk_forecast


class TransformerWorldModelWrapper:
    """
    Wrapper for Transformer World Model inference and training.
    """

    def __init__(
        self,
        input_size: int = 14,
        d_model: int = 64,
        sequence_length: int = 10,
        forecast_horizon: int = 5
    ):
        self.input_size = input_size
        self.sequence_length = sequence_length
        self.forecast_horizon = forecast_horizon
        self.device = torch.device("cpu")

        self.model = PyTorchTransformerWorldModel(
            input_size=input_size,
            d_model=d_model,
            sequence_length=sequence_length,
            forecast_horizon=forecast_horizon
        ).to(self.device)

        self.is_trained: bool = False

    def predict_future(
        self, recent_sequence: np.ndarray
    ) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        self.model.eval()
        with torch.no_grad():
            if recent_sequence.ndim == 2:
                x_in = torch.tensor(recent_sequence, dtype=torch.float32).unsqueeze(0).to(self.device)
            else:
                x_in = torch.tensor(recent_sequence, dtype=torch.float32).to(self.device)

            pred_states, stage_logits, risk_curve = self.model(x_in)
            stage_probs = torch.softmax(stage_logits, dim=-1).cpu().numpy()[0]
            future_states = pred_states.cpu().numpy()[0]
            risk_forecast = risk_curve.cpu().numpy()[0]

            return future_states, stage_probs, risk_forecast
