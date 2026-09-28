"""
CYBERWORLD-X: Feature Normalization & Scaling Module
NTRO SIH 2026 | Problem Statement ID: 26153
"""

from typing import Dict, List, Optional, Tuple
import numpy as np
import pandas as pd
from sklearn.preprocessing import RobustScaler, StandardScaler


class NetworkFeatureScaler:
    """
    Robust feature normalization designed for long-tailed network traffic metrics
    (e.g., packet bursts, byte spikes).
    """

    def __init__(self, method: str = "robust"):
        self.method = method
        self.scaler = RobustScaler() if method == "robust" else StandardScaler()
        self.feature_names: List[str] = []
        self.is_fitted: bool = False

    def fit(self, df: pd.DataFrame, feature_cols: List[str]) -> "NetworkFeatureScaler":
        """
        Fits the scaler on the selected numeric network state features.
        """
        self.feature_names = [c for c in feature_cols if c in df.columns]
        if not self.feature_names:
            raise ValueError("None of the specified feature columns found in dataframe.")

        X = df[self.feature_names].replace([np.inf, -np.inf], np.nan).fillna(0).values
        self.scaler.fit(X)
        self.is_fitted = True
        return self

    def transform(self, df: pd.DataFrame) -> np.ndarray:
        """
        Transforms input dataframe into normalized numpy array.
        """
        if not self.is_fitted:
            # Auto-fit if not explicitly fitted
            feature_cols = [c for c in self.feature_names if c in df.columns]
            if not feature_cols:
                numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
                feature_cols = numeric_cols[:14]
            self.fit(df, feature_cols)

        X = df[self.feature_names].replace([np.inf, -np.inf], np.nan).fillna(0).values
        X_scaled = self.scaler.transform(X)
        # Clip extreme outliers to prevent gradient explosion in PyTorch LSTM
        return np.clip(X_scaled, -10.0, 10.0)

    def fit_transform(self, df: pd.DataFrame, feature_cols: List[str]) -> np.ndarray:
        return self.fit(df, feature_cols).transform(df)

    def inverse_transform(self, X_scaled: np.ndarray) -> np.ndarray:
        if not self.is_fitted:
            return X_scaled
        return self.scaler.inverse_transform(X_scaled)
