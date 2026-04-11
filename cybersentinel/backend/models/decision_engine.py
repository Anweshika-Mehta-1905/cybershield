"""
Final Decision Engine
Combines outputs from all 3 layers into a unified risk score.
final_score = w1 * anomaly_score + w2 * ml_score + w3 * wfa_score
"""

import numpy as np
from typing import Optional, Dict, Any
from dataclasses import dataclass

from .autoencoder_model import get_autoencoder
from .lr_model import get_url_model
from .wfa_model import get_wfa


# Layer weights (tunable)
W1_ANOMALY = 0.25   # Network anomaly layer
W2_ML = 0.40        # Logistic regression URL layer
W3_WFA = 0.35       # WFA rule-based layer

MALICIOUS_THRESHOLD = 0.50


@dataclass
class PredictionResult:
    is_malicious: bool
    anomaly_score: float
    ml_score: float
    wfa_score: float
    final_score: float
    risk_level: str
    explanation: Dict[str, Any]
    ml_features: Dict[str, float]
    wfa_path: list
    wfa_transitions: list
    triggered_features: list
    feature_importance: list


def predict(url: str, network_features: Optional[list] = None) -> PredictionResult:
    """
    Run full 3-layer hybrid prediction on a URL.
    
    Args:
        url: URL string to analyze
        network_features: Optional list of 115 network flow features
    
    Returns:
        PredictionResult with all scores and explanation
    """

    # ──── LAYER 1: Network Anomaly Detection ────
    anomaly_score = 0.0
    if network_features and len(network_features) > 0:
        ae = get_autoencoder()
        net_arr = np.array(network_features, dtype=float)
        anomaly_score, _ = ae.predict(net_arr)
    # If no network features, use neutral 0.5 so it doesn't dominate
    effective_w1 = W1_ANOMALY if network_features else 0.0
    effective_w2 = W2_ML if not network_features else W2_ML
    effective_w3 = W3_WFA if not network_features else W3_WFA
    # Renormalize
    total_w = effective_w1 + effective_w2 + effective_w3
    if total_w > 0:
        effective_w1 /= total_w
        effective_w2 /= total_w
        effective_w3 /= total_w

    # ──── LAYER 2: Logistic Regression (URL features) ────
    lr_model = get_url_model()
    ml_score, feature_dict, triggered_url_features = lr_model.predict(url)
    feature_importance = lr_model.get_feature_importance()

    # ──── LAYER 3: WFA (Rule-based TOC) ────
    # Optionally pass feature weights from LR to WFA for dynamic weighting
    lr_weights_for_wfa = {
        "url_length": abs(lr_model.feature_weights.get("url_length", 0.45)),
        "subdomain_depth": abs(lr_model.feature_weights.get("subdomain_depth", 0.62)),
        "has_ip": abs(lr_model.feature_weights.get("has_ip_host", 0.89)),
        "has_at": abs(lr_model.feature_weights.get("has_at_sign", 0.78)),
        "has_double_slash": abs(lr_model.feature_weights.get("has_double_slash", 0.55)),
        "has_dash_in_domain": abs(lr_model.feature_weights.get("has_dash_in_domain", 0.38)),
        "has_encoding": abs(lr_model.feature_weights.get("has_encoding", 0.67)),
        "path_depth": abs(lr_model.feature_weights.get("path_depth", 0.41)),
        "has_suspicious_tld": abs(lr_model.feature_weights.get("has_suspicious_tld", 0.72)),
        "has_port": abs(lr_model.feature_weights.get("has_port", 0.58)),
        "digit_ratio": abs(lr_model.feature_weights.get("digit_ratio", 0.44)),
        "has_https": lr_model.feature_weights.get("has_https", -0.35),
        "has_unicode": abs(lr_model.feature_weights.get("has_unicode", 0.61)),
        "query_length": abs(lr_model.feature_weights.get("query_length", 0.33)),
        "fragment_present": abs(lr_model.feature_weights.get("has_fragment", 0.29)),
    }

    wfa = get_wfa(lr_weights_for_wfa)
    wfa_result = wfa.compute_score(url)
    wfa_score = wfa_result.normalized_score

    # ──── FINAL DECISION ────
    if network_features:
        final_score = (
            effective_w1 * anomaly_score +
            effective_w2 * ml_score +
            effective_w3 * wfa_score
        )
    else:
        final_score = effective_w2 * ml_score + effective_w3 * wfa_score

    final_score = round(min(max(final_score, 0.0), 1.0), 4)
    is_malicious = final_score > MALICIOUS_THRESHOLD

    # Risk level
    if final_score >= 0.80:
        risk_level = "CRITICAL"
    elif final_score >= 0.60:
        risk_level = "HIGH"
    elif final_score >= 0.40:
        risk_level = "MEDIUM"
    elif final_score >= 0.20:
        risk_level = "LOW"
    else:
        risk_level = "SAFE"

    # Merge triggered features
    all_triggered = list(set(triggered_url_features + wfa_result.triggered_patterns))

    explanation = {
        "triggered_features": all_triggered,
        "wfa_path": wfa_result.path,
        "wfa_final_state": wfa_result.final_state,
        "layer_scores": {
            "anomaly_layer": round(anomaly_score, 4),
            "ml_layer": round(ml_score, 4),
            "wfa_layer": round(wfa_score, 4),
        },
        "layer_weights": {
            "w1_anomaly": round(effective_w1, 3),
            "w2_ml": round(effective_w2, 3),
            "w3_wfa": round(effective_w3, 3),
        },
        "risk_level": risk_level,
        "threshold": MALICIOUS_THRESHOLD,
    }

    return PredictionResult(
        is_malicious=is_malicious,
        anomaly_score=round(anomaly_score, 4),
        ml_score=round(ml_score, 4),
        wfa_score=round(wfa_score, 4),
        final_score=final_score,
        risk_level=risk_level,
        explanation=explanation,
        ml_features=feature_dict,
        wfa_path=wfa_result.path,
        wfa_transitions=wfa_result.transitions_taken,
        triggered_features=all_triggered,
        feature_importance=feature_importance[:10],  # Top 10
    )
