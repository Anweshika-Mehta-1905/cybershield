"""
FastAPI Backend - Cybersecurity Hybrid Detection System
Serves prediction API for the React frontend
"""

from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator
from typing import Optional, List, Dict, Any
import io
import csv
import json
import numpy as np

# Add parent to path
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.decision_engine import predict
from models.lr_model import get_url_model
from models.wfa_model import get_wfa
from models.url_features import extract_features, FEATURE_NAMES

app = FastAPI(
    title="Hybrid Cybersecurity Detection API",
    description="3-Layer: Autoencoder + Logistic Regression + WFA",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ──── Request / Response Models ────

class PredictRequest(BaseModel):
    url: str
    network_features: Optional[List[float]] = None

    @field_validator("url")
    @classmethod
    def validate_url(cls, v):
        v = v.strip()
        if not v:
            raise ValueError("URL cannot be empty")
        if len(v) > 2048:
            raise ValueError("URL too long (max 2048 chars)")
        return v


class LayerScores(BaseModel):
    anomaly_layer: float
    ml_layer: float
    wfa_layer: float


class LayerWeights(BaseModel):
    w1_anomaly: float
    w2_ml: float
    w3_wfa: float


class Explanation(BaseModel):
    triggered_features: List[str]
    wfa_path: List[str]
    wfa_final_state: str
    layer_scores: LayerScores
    layer_weights: LayerWeights
    risk_level: str
    threshold: float


class WFATransition(BaseModel):
    from_state: str
    to_state: str
    symbol: str
    raw_value: str
    weight: float
    description: str


class FeatureImportance(BaseModel):
    feature: str
    weight: float
    abs_weight: float


class PredictResponse(BaseModel):
    is_malicious: bool
    anomaly_score: float
    ml_score: float
    wfa_score: float
    final_score: float
    risk_level: str
    explanation: Dict[str, Any]
    ml_features: Dict[str, float]
    wfa_path: List[str]
    wfa_transitions: List[Dict[str, Any]]
    triggered_features: List[str]
    feature_importance: List[Dict[str, Any]]


# ──── Endpoints ────

@app.get("/")
def root():
    return {"status": "ok", "message": "Hybrid Cybersecurity Detection API v1.0"}


@app.get("/health")
def health():
    lr_model = get_url_model()
    ae_loaded = os.path.exists(
        os.path.join(os.path.dirname(__file__), "../training/saved_models/autoencoder_model.pkl")
    )
    return {
        "status": "healthy",
        "lr_model_trained": lr_model.is_trained,
        "autoencoder_trained": ae_loaded,
        "feature_count": len(FEATURE_NAMES),
    }


@app.post("/predict", response_model=PredictResponse)
def predict_url(request: PredictRequest):
    """
    Main prediction endpoint.
    Runs all 3 layers and returns combined risk score + explanations.
    """
    try:
        result = predict(request.url, request.network_features)
        return PredictResponse(
            is_malicious=result.is_malicious,
            anomaly_score=result.anomaly_score,
            ml_score=result.ml_score,
            wfa_score=result.wfa_score,
            final_score=result.final_score,
            risk_level=result.risk_level,
            explanation=result.explanation,
            ml_features=result.ml_features,
            wfa_path=result.wfa_path,
            wfa_transitions=result.wfa_transitions,
            triggered_features=result.triggered_features,
            feature_importance=result.feature_importance,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/predict/wfa-only")
def predict_wfa_only(request: PredictRequest):
    """
    Rule-based WFA prediction only (no ML).
    Useful for comparing TOC vs ML approaches.
    """
    try:
        wfa = get_wfa()
        result = wfa.compute_score(request.url)
        is_malicious = result.normalized_score > 0.50
        risk_level = (
            "CRITICAL" if result.normalized_score >= 0.80 else
            "HIGH" if result.normalized_score >= 0.60 else
            "MEDIUM" if result.normalized_score >= 0.40 else
            "LOW" if result.normalized_score >= 0.20 else "SAFE"
        )
        return {
            "model": "WFA (Rule-based)",
            "is_malicious": is_malicious,
            "wfa_score": result.normalized_score,
            "raw_score": result.raw_score,
            "final_state": result.final_state,
            "risk_level": risk_level,
            "path": result.path,
            "transitions": result.transitions_taken,
            "triggered_patterns": result.triggered_patterns,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/predict/ml-only")
def predict_ml_only(request: PredictRequest):
    """
    ML-only prediction (Logistic Regression on URL features).
    """
    try:
        lr_model = get_url_model()
        ml_score, feature_dict, triggered = lr_model.predict(request.url)
        is_malicious = ml_score > 0.50
        risk_level = (
            "CRITICAL" if ml_score >= 0.80 else
            "HIGH" if ml_score >= 0.60 else
            "MEDIUM" if ml_score >= 0.40 else
            "LOW" if ml_score >= 0.20 else "SAFE"
        )
        return {
            "model": "Logistic Regression (ML)",
            "is_malicious": is_malicious,
            "ml_score": ml_score,
            "risk_level": risk_level,
            "triggered_features": triggered,
            "features": feature_dict,
            "feature_importance": lr_model.get_feature_importance()[:10],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/upload/network-csv")
async def upload_network_csv(file: UploadFile = File(...)):
    """
    Upload a CSV row of network features (115 values).
    Returns the parsed feature array for use in /predict.
    """
    try:
        content = await file.read()
        text = content.decode("utf-8")
        reader = csv.reader(io.StringIO(text))
        rows = list(reader)
        if not rows:
            raise HTTPException(status_code=400, detail="Empty CSV file")
        # Take first data row (skip header if present)
        data_row = rows[0]
        try:
            float(data_row[0])
        except ValueError:
            data_row = rows[1] if len(rows) > 1 else rows[0][1:]

        features = [float(v) for v in data_row if v.strip()]
        return {
            "status": "ok",
            "n_features": len(features),
            "features": features[:115],  # Cap at 115
            "message": f"Parsed {len(features)} features from CSV",
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"CSV parsing error: {str(e)}")


@app.get("/model/status")
def model_status():
    """Check training status of all models."""
    lr_model = get_url_model()
    lr_path = os.path.join(
        os.path.dirname(__file__), "../training/saved_models/lr_model.pkl"
    )
    ae_path = os.path.join(
        os.path.dirname(__file__), "../training/saved_models/autoencoder_model.pkl"
    )
    return {
        "lr_model": {
            "trained": lr_model.is_trained,
            "saved": os.path.exists(os.path.abspath(lr_path)),
            "top_features": lr_model.get_feature_importance()[:5],
        },
        "autoencoder": {
            "saved": os.path.exists(os.path.abspath(ae_path)),
        },
        "wfa": {
            "states": ["Q0", "Q1", "Q2", "Q3", "Q4", "Q5", "Q6", "Q7", "Q8"],
            "accepting_states": ["Q7", "Q8"],
        },
    }


@app.get("/wfa/diagram")
def wfa_diagram():
    """Return WFA state/transition data for frontend visualization."""
    wfa = get_wfa()
    nodes = [
        {"id": s, "label": s, "risk": i / 8, "is_accepting": s in ["Q7", "Q8"]}
        for i, s in enumerate(wfa.STATES)
    ]
    edges = [
        {
            "from": t.from_state,
            "to": t.to_state,
            "label": t.symbol,
            "weight": round(t.weight, 3),
            "description": t.description,
        }
        for t in wfa.transitions
    ]
    return {"nodes": nodes, "edges": edges}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
