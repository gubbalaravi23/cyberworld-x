"""
CYBERWORLD-X: Model Loader & Factory
NTRO SIH 2026 | Problem Statement ID: 26153
"""

from typing import Optional, Union
from models.lstm_model import LSTMWorldModelWrapper
from models.transformer_model import TransformerWorldModelWrapper
from models.baseline_model import BaselineClassifier


def get_world_model(
    model_type: str = "LSTM",
    input_size: int = 14,
    hidden_size: int = 64,
    num_layers: int = 2,
    dropout: float = 0.2,
    sequence_length: int = 10,
    forecast_horizon: int = 5
) -> Union[LSTMWorldModelWrapper, TransformerWorldModelWrapper]:
    """
    Factory function instantiating the selected temporal World Model architecture.
    """
    if model_type.upper() == "TRANSFORMER":
        return TransformerWorldModelWrapper(
            input_size=input_size,
            d_model=hidden_size,
            sequence_length=sequence_length,
            forecast_horizon=forecast_horizon
        )
    else:
        return LSTMWorldModelWrapper(
            input_size=input_size,
            hidden_size=hidden_size,
            num_layers=num_layers,
            dropout=dropout,
            sequence_length=sequence_length,
            forecast_horizon=forecast_horizon
        )


def get_baseline_classifier() -> BaselineClassifier:
    """
    Factory function for the static baseline classifier.
    """
    return BaselineClassifier()
