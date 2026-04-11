"""
Autoencoder-based Anomaly Detection - Layer 1
Trained only on BENIGN traffic from IoT/N-BaIoT dataset.
Reconstruction error → anomaly score.
"""

import os
import pickle
import numpy as np
from typing import Optional, Dict, List, Tuple

MODEL_PATH = os.path.join(os.path.dirname(__file__), "../../training/saved_models/autoencoder_model.pkl")
THRESHOLD_PATH = os.path.join(os.path.dirname(__file__), "../../training/saved_models/ae_threshold.pkl")


class AutoencoderModel:
    """
    Sklearn-compatible Autoencoder using neural network layers.
    Falls back to IsolationForest if TF/PyTorch unavailable.
    """

    def __init__(self):
        self.model = None
        self.threshold = 0.5
        self.scaler = None
        self.n_features = 115
        self.is_trained = False
        self.backend = "none"
        self._load_model()

    def _load_model(self):
        """Load pre-trained autoencoder if available."""
        model_path = os.path.abspath(MODEL_PATH)
        threshold_path = os.path.abspath(THRESHOLD_PATH)
        if os.path.exists(model_path):
            with open(model_path, "rb") as f:
                saved = pickle.load(f)
            self.model = saved.get("model")
            self.scaler = saved.get("scaler")
            self.n_features = saved.get("n_features", 115)
            self.backend = saved.get("backend", "sklearn")
            if os.path.exists(threshold_path):
                with open(threshold_path, "rb") as f:
                    self.threshold = pickle.load(f)
            self.is_trained = True
            print(f"[Autoencoder] Loaded model (backend={self.backend})")
        else:
            print("[Autoencoder] No saved model. Will use statistical fallback.")

    def _build_sklearn_ae(self, n_features: int):
        """Build a sklearn MLP-based autoencoder."""
        from sklearn.neural_network import MLPRegressor
        encoding_dim = max(16, n_features // 8)
        return MLPRegressor(
            hidden_layer_sizes=(encoding_dim * 2, encoding_dim, encoding_dim * 2),
            activation="relu",
            max_iter=200,
            random_state=42,
            early_stopping=True,
            validation_fraction=0.1,
        )

    def train(self, X_benign: np.ndarray) -> Dict:
        """Train autoencoder on benign-only data."""
        from sklearn.preprocessing import StandardScaler

        print(f"[Autoencoder] Training on {len(X_benign)} benign samples, {X_benign.shape[1]} features")
        self.n_features = X_benign.shape[1]
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X_benign)

        # Try sklearn MLPRegressor as autoencoder
        try:
            self.model = self._build_sklearn_ae(self.n_features)
            self.model.fit(X_scaled, X_scaled)
            self.backend = "sklearn_mlp"
            print("[Autoencoder] Trained with sklearn MLPRegressor")
        except Exception as e:
            print(f"[Autoencoder] MLP failed ({e}), falling back to IsolationForest")
            from sklearn.ensemble import IsolationForest
            self.model = IsolationForest(contamination=0.05, random_state=42, n_jobs=-1)
            self.model.fit(X_scaled)
            self.backend = "isolation_forest"

        # Calculate threshold from benign reconstruction errors
        errors = self._reconstruction_errors(X_scaled)
        self.threshold = float(np.percentile(errors, 95))

        self.is_trained = True
        metrics = {
            "backend": self.backend,
            "n_samples": len(X_benign),
            "n_features": self.n_features,
            "threshold": round(self.threshold, 6),
            "mean_benign_error": round(float(np.mean(errors)), 6),
        }
        return metrics

    def _reconstruction_errors(self, X_scaled: np.ndarray) -> np.ndarray:
        """Calculate per-sample reconstruction error."""
        if self.backend == "sklearn_mlp":
            X_reconstructed = self.model.predict(X_scaled)
            return np.mean((X_scaled - X_reconstructed) ** 2, axis=1)
        elif self.backend == "isolation_forest":
            scores = self.model.score_samples(X_scaled)
            # Convert IF scores to [0,1] (higher = more anomalous)
            return -scores
        else:
            return np.zeros(len(X_scaled))

    def predict(self, x: np.ndarray) -> Tuple[float, bool]:
        """
        Predict anomaly score for a single sample or batch.
        Returns (anomaly_score 0-1, is_anomaly bool)
        """
        if not self.is_trained or self.model is None:
            return self._statistical_fallback(x)

        if len(x.shape) == 1:
            x = x.reshape(1, -1)

        # Pad/truncate to expected feature count
        if x.shape[1] != self.n_features:
            if x.shape[1] < self.n_features:
                x = np.pad(x, ((0, 0), (0, self.n_features - x.shape[1])))
            else:
                x = x[:, :self.n_features]

        x_scaled = self.scaler.transform(x)
        errors = self._reconstruction_errors(x_scaled)
        error = float(np.mean(errors))

        # Normalize to [0, 1] relative to threshold
        normalized = min(error / (self.threshold * 2 + 1e-8), 1.0)
        is_anomaly = error > self.threshold

        return round(normalized, 4), is_anomaly

    def _statistical_fallback(self, x: np.ndarray) -> Tuple[float, bool]:
        """Simple statistical anomaly detection when model not loaded."""
        if len(x.shape) == 1:
            x = x.reshape(1, -1)
        # Use Z-score based detection
        mean = np.zeros(x.shape[1])
        std = np.ones(x.shape[1])
        z_scores = np.abs((x - mean) / (std + 1e-8))
        score = float(np.mean(z_scores > 3))  # Fraction of features beyond 3-sigma
        return round(min(score * 2, 1.0), 4), score > 0.2

    def save(self):
        """Save model to disk."""
        os.makedirs(os.path.dirname(os.path.abspath(MODEL_PATH)), exist_ok=True)
        with open(os.path.abspath(MODEL_PATH), "wb") as f:
            pickle.dump({
                "model": self.model,
                "scaler": self.scaler,
                "n_features": self.n_features,
                "backend": self.backend,
            }, f)
        with open(os.path.abspath(THRESHOLD_PATH), "wb") as f:
            pickle.dump(self.threshold, f)
        print(f"[Autoencoder] Saved model to {MODEL_PATH}")


# Singleton
_ae_instance: Optional[AutoencoderModel] = None


def get_autoencoder() -> AutoencoderModel:
    global _ae_instance
    if _ae_instance is None:
        _ae_instance = AutoencoderModel()
    return _ae_instance
