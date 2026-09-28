"""
CYBERWORLD-X: Baseline Model (Logistic Regression) & Comparative Evaluation
NTRO SIH 2026 | Problem Statement ID: 26153

Provides a static Logistic Regression baseline classifier on engineered features
to benchmark against the temporal LSTM World Model.
Strictly reports real empirical metrics or "Not evaluated yet" if untrained.
"""

from typing import Dict, Optional, Tuple, Union
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix


class BaselineClassifier:
    """
    Standard linear baseline model mapping static network features to attack status.
    """

    def __init__(self):
        self.model = LogisticRegression(max_iter=500, random_state=42)
        self.is_trained: bool = False
        self.metrics: Optional[Dict[str, Union[float, str]]] = None

    def fit_and_evaluate(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_test: np.ndarray,
        y_test: np.ndarray
    ) -> Dict[str, Union[float, str]]:
        """
        Fits baseline and calculates genuine empirical metrics.
        No fabricated or hardcoded benchmark numbers.
        """
        if len(np.unique(y_train)) < 2:
            return {
                "precision": "Insufficient classes",
                "recall": "Insufficient classes",
                "f1_score": "Insufficient classes",
                "false_positive_rate": "Insufficient classes",
                "status": "untrained"
            }

        self.model.fit(X_train, y_train)
        self.is_trained = True

        y_pred = self.model.predict(X_test)

        prec = float(precision_score(y_test, y_pred, average="weighted", zero_division=0))
        rec = float(recall_score(y_test, y_pred, average="weighted", zero_division=0))
        f1 = float(f1_score(y_test, y_pred, average="weighted", zero_division=0))

        # Calculate FPR from confusion matrix if binary or aggregated
        cm = confusion_matrix(y_test, y_pred)
        if cm.shape == (2, 2):
            tn, fp, fn, tp = cm.ravel()
            fpr = float(fp / max(1, (fp + tn)))
        else:
            # Macro average FPR across multi-class
            fpr_list = []
            for i in range(len(cm)):
                fp_i = cm[:, i].sum() - cm[i, i]
                tn_i = cm.sum() - (cm[i, :].sum() + cm[:, i].sum() - cm[i, i])
                fpr_list.append(fp_i / max(1, (fp_i + tn_i)))
            fpr = float(np.mean(fpr_list))

        self.metrics = {
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "false_positive_rate": round(fpr, 4),
            "status": "evaluated"
        }
        return self.metrics

    def predict(self, X: np.ndarray) -> np.ndarray:
        if not self.is_trained:
            raise RuntimeError("Baseline model has not been trained yet.")
        return self.model.predict(X)

    def get_metrics_display(self) -> Dict[str, Union[float, str]]:
        if not self.is_trained or not self.metrics:
            return {
                "precision": "Not evaluated yet",
                "recall": "Not evaluated yet",
                "f1_score": "Not evaluated yet",
                "false_positive_rate": "Not evaluated yet",
                "status": "Not evaluated yet"
            }
        return self.metrics
