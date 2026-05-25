# 🛡️ CyberShield — Hybrid Cybersecurity Detection System

> **3-Layer Hybrid System**: Autoencoder (IoT Anomaly) + Logistic Regression (URL ML) + Weighted Finite Automaton (TOC)
> 
> **Case Study**: Weighted Automata for Phishing URL Detection · BCSE304L · Dr Padmavathy T

---

## 📁 Project Structure

```
cybersec-system/
├── backend/
│   ├── api/
│   │   └── main.py               # FastAPI server (all endpoints)
│   ├── models/
│   │   ├── __init__.py
│   │   ├── wfa_model.py          # Weighted Finite Automaton (Layer 3 - TOC)
│   │   ├── url_features.py       # URL feature extractor (25 features)
│   │   ├── lr_model.py           # Logistic Regression wrapper (Layer 2)
│   │   ├── autoencoder_model.py  # Autoencoder anomaly detector (Layer 1)
│   │   └── decision_engine.py    # Final score combiner
│   └── requirements.txt
│
├── frontend/
│   ├── public/index.html
│   ├── src/
│   │   ├── App.js                # Main UI (tabs, inputs, all views)
│   │   ├── index.js
│   │   ├── utils/api.js          # Axios API calls
│   │   └── components/
│   │       ├── RiskMeter.js      # Animated SVG gauge
│   │       ├── WFADiagram.js     # State transition diagram
│   │       ├── FeatureImportanceChart.js  # Recharts bar chart
│   │       ├── ScoreComparison.js         # ML vs WFA side-by-side
│   │       ├── TransitionsTable.js        # WFA step-by-step table
│   │       └── NetworkUploader.js         # CSV file picker
│   └── package.json
│
├── training/
│   ├── train_url_model.py        # Train Logistic Regression on URL dataset
│   ├── train_anomaly_model.py    # Train Autoencoder on N-BaIoT dataset
│   └── saved_models/             # Auto-created, stores .pkl files
│
├── demo.py                       # Quick local test (no server needed)
└── README.md
```

---

## ⚡ Quick Start (VSCode Terminal)

### Step 1 — Clone / Open in VSCode

Open the `cybersec-system/` folder in VSCode.

### Step 2 — Backend Setup

```bash
# Navigate to backend
cd cybersec-system/backend

# Create virtual environment
python -m venv venv

# Activate it
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Step 3 — Run the Backend

```bash
# From cybersec-system/backend/api/
cd api
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

Backend will be live at: **http://localhost:8000**  
Interactive API docs: **http://localhost:8000/docs**

### Step 4 — Frontend Setup

Open a **second terminal** in VSCode (`Ctrl+Shift+\``)

```bash
cd cybersec-system/frontend
npm install
npm start
```

Frontend will open at: **http://localhost:3000**

---

## 🧠 Model Training

### Option A: Train URL/Logistic Regression Model

```bash
cd cybersec-system

# With your own phishing URL CSV (columns: url, label)
python training/train_url_model.py --dataset /path/to/phishing_urls.csv

# OR use built-in synthetic data (2000 samples for testing)
python training/train_url_model.py --synthetic 2000
```

Saved to: `training/saved_models/lr_model.pkl`

**CSV format for URL dataset:**
```
url,label
https://github.com/user/repo,0
http://paypal-login.tk/verify,1
```

---

### Option B: Train Autoencoder (N-BaIoT IoT Dataset)

```bash
cd cybersec-system

# Option 1: Point to N-BaIoT dataset directory
# (directory should have device folders with benign_traffic.csv + attack/ subfolders)
python training/train_anomaly_model.py --dataset-dir /path/to/N-BaIoT/

# Option 2: Single merged CSV with 'label' column (0=benign, 1=attack)
python training/train_anomaly_model.py --csv /path/to/network_traffic.csv

# Option 3: Use file picker — run training then select CSV from terminal
python training/train_anomaly_model.py --csv training/data/my_traffic.csv

# Option 4: Synthetic data (for testing, no real dataset needed)
python training/train_anomaly_model.py --synthetic --n-samples 10000
```

Saved to: `training/saved_models/autoencoder_model.pkl`

**N-BaIoT CSV format** (115 numeric features + label):
```
feature_1,feature_2,...,feature_115,label
0.012,0.003,...,0.091,0
0.891,0.752,...,0.934,1
```

---

## 🚀 Quick Demo (No Server Needed)

```bash
cd cybersec-system
python demo.py
```

Tests 7 URLs locally and prints scores for all 3 layers.

---

## 🌐 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/predict` | Full 3-layer hybrid prediction |
| POST | `/predict/ml-only` | Logistic Regression only |
| POST | `/predict/wfa-only` | WFA rule-based only |
| POST | `/upload/network-csv` | Upload CSV for network features |
| GET | `/wfa/diagram` | WFA state/transition graph data |
| GET | `/model/status` | Training status of all models |
| GET | `/health` | Health check |

### Example request:
```bash
curl -X POST http://localhost:8000/predict \
  -H "Content-Type: application/json" \
  -d '{"url": "http://paypal-secure.tk/login"}'
```

### Example response:
```json
{
  "is_malicious": true,
  "anomaly_score": 0.0,
  "ml_score": 0.8721,
  "wfa_score": 0.7834,
  "final_score": 0.8342,
  "risk_level": "CRITICAL",
  "explanation": {
    "triggered_features": ["Suspicious TLD (.tk)", "Credential keyword mimicry"],
    "wfa_path": ["Q0", "Q1", "Q5", "Q6", "Q8"],
    "wfa_final_state": "Q8",
    "layer_scores": { "anomaly_layer": 0.0, "ml_layer": 0.8721, "wfa_layer": 0.7834 },
    "layer_weights": { "w1_anomaly": 0.0, "w2_ml": 0.533, "w3_wfa": 0.467 }
  }
}
```

---

## 🔵 WFA States

| State | Name | Risk Level | Description |
|-------|------|-----------|-------------|
| Q0 | Initial | None | Clean start state |
| Q1 | Protocol | Very Low | Protocol detected |
| Q2 | IP Host | Critical | IP address as hostname |
| Q3 | Subdomain | Medium | Deep subdomain nesting |
| Q4 | Encoded | Medium-High | Obfuscation chars detected |
| Q5 | Path | Low-Medium | Suspicious path structure |
| Q6 | Credential | High | Credential/brand keywords |
| Q7 | Anomaly | Very High | Multiple anomalies |
| Q8 | Terminal | Critical | Malicious accepting state |

**Final Score Formula:**
```
final_score = w1 × anomaly_score + w2 × ml_score + w3 × wfa_score
           = 0.25 × anomaly + 0.40 × ML + 0.35 × WFA
           (weights renormalized if no network features provided)
```

---

## 📦 Dependencies

**Backend:**
- `fastapi` · `uvicorn` — REST API
- `scikit-learn` — Logistic Regression + Autoencoder (MLPRegressor)
- `numpy` · `pandas` — Data processing
- `python-multipart` — File uploads

**Frontend:**
- `react` — UI framework
- `recharts` — Feature importance bar charts
- `axios` — API communication
- `lucide-react` — Icons

---

## 🛠️ VSCode Tips

1. **Split terminals**: `Ctrl+Shift+\`` for backend, another for frontend
2. **Recommended extensions**: Python, ESLint, Prettier
3. **Debug backend**: Add `--reload` flag to uvicorn for hot reload
4. **Proxy**: Frontend `package.json` already has `"proxy": "http://localhost:8000"`

