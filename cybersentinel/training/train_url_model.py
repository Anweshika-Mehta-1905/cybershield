"""
Training Script: Logistic Regression URL Classifier (Layer 2)

Usage:
    python training/train_url_model.py --dataset training/data/phishing_urls.csv

Dataset format (CSV):
    url, label  (label: 1=phishing/malicious, 0=benign)

Or use built-in synthetic data for testing.
"""

import os
import sys
import argparse
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score, confusion_matrix

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.models.url_features import extract_features, FEATURE_NAMES
from backend.models.lr_model import URLLogisticModel


def generate_synthetic_data(n_samples: int = 2000):
    """Generate synthetic URL dataset for testing when no real dataset available."""
    import random
    import string

    benign_domains = [
        "google.com", "github.com", "stackoverflow.com", "amazon.com",
        "wikipedia.org", "microsoft.com", "apple.com", "youtube.com",
        "reddit.com", "linkedin.com", "twitter.com", "facebook.com",
    ]

    phishing_patterns = [
        lambda: f"http://{'.'.join(str(random.randint(1,255)) for _ in range(4))}/login",
        lambda: f"http://{''.join(random.choices(string.ascii_lowercase, k=8))}.tk/verify",
        lambda: f"https://paypal-secure-{''.join(random.choices(string.ascii_lowercase, k=6))}.com/update",
        lambda: f"http://login.{''.join(random.choices(string.ascii_lowercase, k=5))}.account.verify.suspicious.xyz/signin",
        lambda: f"http://google.com.{''.join(random.choices(string.ascii_lowercase, k=8))}.ru/phish",
        lambda: f"https://secure-bank.{''.join(random.choices(string.ascii_lowercase, k=6))}.top/account/verify?token={''.join(random.choices(string.hexdigits, k=32))}",
        lambda: f"http://{''.join(random.choices(string.ascii_lowercase, k=10))}.ml/update?username=victim@email.com",
    ]

    urls = []
    labels = []

    # Benign URLs
    for _ in range(n_samples // 2):
        domain = random.choice(benign_domains)
        path = "/" + "/".join(random.choices(["docs", "about", "products", "blog", "api"], k=random.randint(0, 2)))
        urls.append(f"https://{domain}{path}")
        labels.append(0)

    # Phishing URLs
    for _ in range(n_samples // 2):
        gen = random.choice(phishing_patterns)
        urls.append(gen())
        labels.append(1)

    return urls, labels


def load_dataset(csv_path: str):
    """Load URL dataset from CSV file."""
    df = pd.read_csv(csv_path)

    # Auto-detect column names
    url_col = None
    label_col = None
    for col in df.columns:
        if col.lower() in ("url", "urls", "link", "address"):
            url_col = col
        if col.lower() in ("label", "class", "target", "phishing", "malicious", "result"):
            label_col = col

    if url_col is None or label_col is None:
        # Assume first col = url, last col = label
        url_col = df.columns[0]
        label_col = df.columns[-1]
        print(f"Auto-detected: url='{url_col}', label='{label_col}'")

    urls = df[url_col].astype(str).tolist()
    labels = df[label_col].tolist()

    # Normalize labels to 0/1
    unique_labels = set(labels)
    if unique_labels <= {0, 1}:
        labels = [int(l) for l in labels]
    elif unique_labels <= {"0", "1"}:
        labels = [int(l) for l in labels]
    elif "phishing" in unique_labels or "malicious" in unique_labels or "bad" in unique_labels:
        labels = [1 if str(l).lower() in ("phishing", "malicious", "bad", "1") else 0 for l in labels]
    else:
        # Try numeric
        try:
            labels = [1 if float(l) > 0 else 0 for l in labels]
        except Exception:
            raise ValueError(f"Cannot parse labels. Unique values: {unique_labels}")

    print(f"Loaded {len(urls)} URLs: {sum(labels)} malicious, {len(labels)-sum(labels)} benign")
    return urls, labels


def extract_all_features(urls: list) -> np.ndarray:
    """Extract features for all URLs with progress."""
    features = []
    for i, url in enumerate(urls):
        if i % 500 == 0:
            print(f"  Extracting features: {i}/{len(urls)}")
        try:
            fv, _ = extract_features(url)
            features.append(fv)
        except Exception:
            features.append(np.zeros(len(FEATURE_NAMES)))
    return np.array(features)


def main():
    parser = argparse.ArgumentParser(description="Train URL Logistic Regression model")
    parser.add_argument("--dataset", type=str, default=None, help="Path to URL CSV dataset")
    parser.add_argument("--test-size", type=float, default=0.2, help="Test split ratio")
    parser.add_argument("--synthetic", type=int, default=2000, help="Synthetic samples if no dataset")
    args = parser.parse_args()

    os.makedirs("training/saved_models", exist_ok=True)

    print("=" * 60)
    print("URL Logistic Regression Training")
    print("=" * 60)

    # Load or generate data
    if args.dataset and os.path.exists(args.dataset):
        print(f"\nLoading dataset: {args.dataset}")
        urls, labels = load_dataset(args.dataset)
    else:
        print(f"\nNo dataset provided. Generating {args.synthetic} synthetic samples...")
        urls, labels = generate_synthetic_data(args.synthetic)

    labels = np.array(labels)

    # Extract features
    print(f"\nExtracting {len(FEATURE_NAMES)} features from {len(urls)} URLs...")
    X = extract_all_features(urls)
    y = labels

    # Train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=args.test_size, random_state=42, stratify=y
    )
    print(f"\nTrain: {len(X_train)}, Test: {len(X_test)}")

    # Train
    print("\nTraining Logistic Regression...")
    model = URLLogisticModel()
    metrics = model.train(X_train, y_train)

    # Evaluate on test set
    print("\nEvaluating on test set...")
    y_pred = model.pipeline.predict(X_test)
    y_prob = model.pipeline.predict_proba(X_test)[:, 1]
    auc = roc_auc_score(y_test, y_prob)

    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)
    print(classification_report(y_test, y_pred, target_names=["Benign", "Malicious"]))
    print(f"ROC-AUC: {auc:.4f}")
    print("\nConfusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(f"  TN={cm[0,0]}  FP={cm[0,1]}")
    print(f"  FN={cm[1,0]}  TP={cm[1,1]}")

    print("\nTop 10 Feature Weights:")
    importance = model.get_feature_importance()
    for f in importance[:10]:
        bar = "█" * int(abs(f["weight"]) * 20)
        sign = "+" if f["weight"] > 0 else "-"
        print(f"  {f['feature']:35s} {sign}{f['abs_weight']:.4f} {bar}")

    # Save
    model.save()
    print(f"\nModel saved to training/saved_models/lr_model.pkl")
    print("Training complete!")


if __name__ == "__main__":
    main()
