"""
Logistic Regression URL Classifier - Layer 2
Trains on URL features and provides probability + feature importance
"""

import os
import pickle
import numpy as np
from typing import Dict, Tuple, Optional, List
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, roc_auc_score

from .url_features import FEATURE_NAMES, extract_features

MODEL_PATH = os.path.join(os.path.dirname(__file__), "../../training/saved_models/lr_model.pkl")


class URLLogisticModel:
    def __init__(self):
        self.pipeline: Optional[Pipeline] = None
        self.feature_weights: Dict[str, float] = {}
        self.is_trained = False
        self._load_model()

    def _load_model(self):
        """Load pre-trained model if available."""
        path = os.path.abspath(MODEL_PATH)
        if os.path.exists(path):
            with open(path, "rb") as f:
                saved = pickle.load(f)
            self.pipeline = saved["pipeline"]
            self.feature_weights = saved["feature_weights"]
            self.is_trained = True
            print("[URLModel] Loaded pre-trained LR model.")
        else:
            print("[URLModel] No saved model found. Using rule-based fallback.")
            self._init_default_pipeline()

    def _init_default_pipeline(self):
        """Initialize pipeline with default weights (not trained)."""
        self.pipeline = Pipeline([
            ("scaler", StandardScaler()),
            ("lr", LogisticRegression(C=1.0, max_iter=1000, random_state=42)),
        ])
        # Default feature weights from literature
        default_coefs = [
            0.45, 0.30, 0.20, 0.33, 0.62, 0.89, 0.78, 0.55,
            0.38, 0.58, 0.44, 0.25, 0.15, 0.10, -0.35, 0.67,
            0.61, 0.41, 0.72, 0.65, 0.28, 0.29, 0.40, 0.35, 0.70,
        ]
        self.feature_weights = dict(zip(FEATURE_NAMES, default_coefs))
        self.is_trained = False

    def train(self, X: np.ndarray, y: np.ndarray) -> Dict:
        """Train the logistic regression model."""
        from sklearn.model_selection import cross_val_score
        self.pipeline.fit(X, y)
        coefs = self.pipeline.named_steps["lr"].coef_[0]
        self.feature_weights = dict(zip(FEATURE_NAMES, coefs.tolist()))
        self.is_trained = True

        # Evaluate
        y_pred_proba = self.pipeline.predict_proba(X)[:, 1]
        y_pred = self.pipeline.predict(X)
        auc = roc_auc_score(y, y_pred_proba)
        report = classification_report(y, y_pred, output_dict=True)

        return {
            "auc": round(auc, 4),
            "accuracy": round(report["accuracy"], 4),
            "f1": round(report["weighted avg"]["f1-score"], 4),
            "feature_weights": self.feature_weights,
        }

    def predict(self, url: str) -> Tuple[float, Dict[str, float], List[str]]:
        """
        Predict phishing probability for a URL.
        Returns (probability, feature_dict, triggered_features)
        """
        from .url_features import get_triggered_features
        feature_vector, feature_dict = extract_features(url)
        triggered = get_triggered_features(feature_dict)

        if self.is_trained and self.pipeline:
            X = feature_vector.reshape(1, -1)
            try:
                prob = float(self.pipeline.predict_proba(X)[0][1])
            except Exception:
                prob = self._rule_based_score(feature_dict)
        else:
            prob = self._rule_based_score(feature_dict)

        return prob, feature_dict, triggered

    def _rule_based_score(self, feature_dict: Dict[str, float]) -> float:
        """Fallback rule-based scoring using default weights."""
        score = 0.0
        for feat, weight in self.feature_weights.items():
            val = feature_dict.get(feat, 0)
            # Normalize large values
            if feat in ("url_length", "hostname_length", "path_length", "query_length"):
                val = min(val / 200, 1.0)
            elif feat in ("subdomain_depth", "path_depth"):
                val = min(val / 5, 1.0)
            elif feat in ("entropy",):
                val = min(val / 6, 1.0)
            elif feat in ("dot_count", "slash_count"):
                val = min(val / 10, 1.0)
            score += weight * val
        # Sigmoid
        return round(1 / (1 + np.exp(-score + 1.0)), 4)

    def get_feature_importance(self) -> List[Dict]:
        """Return sorted feature importance for visualization."""
        importance = [
            {"feature": k, "weight": round(v, 4), "abs_weight": round(abs(v), 4)}
            for k, v in self.feature_weights.items()
        ]
        return sorted(importance, key=lambda x: x["abs_weight"], reverse=True)

    def save(self):
        """Save trained model to disk."""
        os.makedirs(os.path.dirname(os.path.abspath(MODEL_PATH)), exist_ok=True)
        with open(os.path.abspath(MODEL_PATH), "wb") as f:
            pickle.dump({
                "pipeline": self.pipeline,
                "feature_weights": self.feature_weights,
            }, f)
        print(f"[URLModel] Saved to {MODEL_PATH}")


# Singleton
_model_instance: Optional[URLLogisticModel] = None


def get_url_model() -> URLLogisticModel:
    global _model_instance
    if _model_instance is None:
        _model_instance = URLLogisticModel()
    return _model_instance
