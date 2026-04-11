"""
Training Script: Autoencoder Anomaly Detection (Layer 1)
Uses N-BaIoT / IoT Botnet dataset (115 features)

Usage:
    # With real N-BaIoT dataset directory:
    python training/train_anomaly_model.py --dataset-dir /path/to/NBaIoT/

    # With a single merged CSV:
    python training/train_anomaly_model.py --csv training/data/network_traffic.csv

    # With synthetic data (for testing):
    python training/train_anomaly_model.py --synthetic

N-BaIoT Dataset Structure:
    Each device folder contains:
        benign_traffic.csv  → use for training
        attack/...          → use for testing anomaly detection
"""

import os
import sys
import argparse
import numpy as np
import pandas as pd
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.models.autoencoder_model import AutoencoderModel


CHUNK_SIZE = 50_000  # For large CSV loading


def load_nbaiot_dataset(dataset_dir: str):
    """
    Load N-BaIoT dataset from directory structure.
    Expects folders with benign_traffic.csv files.
    Returns X_benign, X_attack arrays.
    """
    dataset_path = Path(dataset_dir)
    benign_frames = []
    attack_frames = []

    print(f"\nScanning dataset directory: {dataset_path}")

    for device_dir in sorted(dataset_path.iterdir()):
        if not device_dir.is_dir():
            continue
        print(f"  Device: {device_dir.name}")

        # Benign traffic
        for f in device_dir.rglob("*benign*"):
            if f.suffix == ".csv":
                print(f"    Loading benign: {f.name}")
                try:
                    for chunk in pd.read_csv(f, chunksize=CHUNK_SIZE):
                        benign_frames.append(chunk.select_dtypes(include=[np.number]))
                except Exception as e:
                    print(f"    Warning: {e}")

        # Attack traffic
        for attack_dir in device_dir.iterdir():
            if attack_dir.is_dir() and "attack" in attack_dir.name.lower():
                for f in attack_dir.rglob("*.csv"):
                    print(f"    Loading attack: {f.name}")
                    try:
                        for chunk in pd.read_csv(f, chunksize=CHUNK_SIZE):
                            attack_frames.append(chunk.select_dtypes(include=[np.number]))
                    except Exception as e:
                        print(f"    Warning: {e}")

    if not benign_frames:
        raise ValueError(f"No benign traffic CSV files found in {dataset_dir}")

    X_benign = pd.concat(benign_frames, ignore_index=True).values
    X_attack = pd.concat(attack_frames, ignore_index=True).values if attack_frames else None

    print(f"\nLoaded: {len(X_benign):,} benign samples, {len(X_attack):,} attack samples" if X_attack is not None
          else f"\nLoaded: {len(X_benign):,} benign samples (no attack data found)")

    return X_benign, X_attack


def load_single_csv(csv_path: str):
    """
    Load from a single merged CSV with a 'label' column.
    label: 0=benign, 1=attack
    """
    print(f"\nLoading CSV: {csv_path}")
    frames = []
    for chunk in pd.read_csv(csv_path, chunksize=CHUNK_SIZE):
        frames.append(chunk)
    df = pd.concat(frames, ignore_index=True)

    print(f"Shape: {df.shape}")

    # Find label column
    label_col = None
    for col in df.columns:
        if col.lower() in ("label", "class", "target", "attack"):
            label_col = col
            break

    if label_col:
        labels = df[label_col].values
        # Normalize: benign=0
        if set(labels) - {0, 1}:  # Non-binary
            labels = (labels != 0).astype(int)
        X = df.drop(columns=[label_col]).select_dtypes(include=[np.number]).values
        X_benign = X[labels == 0]
        X_attack = X[labels == 1]
        print(f"  Benign: {len(X_benign):,}, Attack: {len(X_attack):,}")
    else:
        # Assume all data is benign
        print("  No label column found — assuming all benign traffic")
        X_benign = df.select_dtypes(include=[np.number]).values
        X_attack = None

    return X_benign, X_attack


def generate_synthetic_data(n_benign: int = 10000, n_attack: int = 2000, n_features: int = 115):
    """Generate synthetic N-BaIoT-like data for testing."""
    print(f"\nGenerating synthetic data: {n_benign} benign, {n_attack} attack, {n_features} features")
    rng = np.random.default_rng(42)

    # Benign: low-amplitude, correlated features (normal network behavior)
    X_benign = rng.normal(loc=0.3, scale=0.1, size=(n_benign, n_features))
    X_benign = np.clip(X_benign, 0, 1)

    # Attack: high-amplitude, unusual patterns (botnet behavior)
    X_attack = rng.normal(loc=0.8, scale=0.3, size=(n_attack, n_features))
    X_attack = np.clip(X_attack, 0, 2)
    # Add spike anomalies
    spike_indices = rng.integers(0, n_features, size=(n_attack, 10))
    for i, spikes in enumerate(spike_indices):
        X_attack[i, spikes] = rng.uniform(2.0, 5.0, size=len(spikes))

    return X_benign, X_attack


def evaluate_model(model: AutoencoderModel, X_benign_test, X_attack):
    """Evaluate anomaly detection performance."""
    print("\n" + "=" * 60)
    print("EVALUATION")
    print("=" * 60)

    # Test on benign samples
    benign_scores = []
    for i in range(min(len(X_benign_test), 1000)):
        score, _ = model.predict(X_benign_test[i])
        benign_scores.append(score)

    print(f"\nBenign samples (n={len(benign_scores)}):")
    print(f"  Mean anomaly score: {np.mean(benign_scores):.4f}")
    print(f"  Max anomaly score:  {np.max(benign_scores):.4f}")
    print(f"  False Positive Rate (score > 0.5): {np.mean(np.array(benign_scores) > 0.5):.2%}")

    if X_attack is not None and len(X_attack) > 0:
        attack_scores = []
        for i in range(min(len(X_attack), 1000)):
            score, _ = model.predict(X_attack[i])
            attack_scores.append(score)

        print(f"\nAttack samples (n={len(attack_scores)}):")
        print(f"  Mean anomaly score: {np.mean(attack_scores):.4f}")
        print(f"  Min anomaly score:  {np.min(attack_scores):.4f}")
        print(f"  True Positive Rate (score > 0.5): {np.mean(np.array(attack_scores) > 0.5):.2%}")

        # AUC approximation
        from sklearn.metrics import roc_auc_score
        all_scores = benign_scores + attack_scores
        all_labels = [0] * len(benign_scores) + [1] * len(attack_scores)
        try:
            auc = roc_auc_score(all_labels, all_scores)
            print(f"\n  ROC-AUC: {auc:.4f}")
        except Exception:
            pass


def main():
    parser = argparse.ArgumentParser(description="Train Autoencoder Anomaly Detection Model")
    parser.add_argument("--dataset-dir", type=str, default=None, help="N-BaIoT dataset directory")
    parser.add_argument("--csv", type=str, default=None, help="Single merged CSV file")
    parser.add_argument("--synthetic", action="store_true", help="Use synthetic data")
    parser.add_argument("--n-samples", type=int, default=10000, help="Synthetic sample count")
    parser.add_argument("--n-features", type=int, default=115, help="Feature count")
    parser.add_argument("--max-samples", type=int, default=500000, help="Max benign samples to use")
    args = parser.parse_args()

    os.makedirs("training/saved_models", exist_ok=True)

    print("=" * 60)
    print("Autoencoder Anomaly Detection Training")
    print("=" * 60)

    # Load data
    if args.dataset_dir and os.path.isdir(args.dataset_dir):
        X_benign, X_attack = load_nbaiot_dataset(args.dataset_dir)
    elif args.csv and os.path.exists(args.csv):
        X_benign, X_attack = load_single_csv(args.csv)
    else:
        if not args.synthetic:
            print("No dataset found. Defaulting to synthetic data.")
            print("To use real data: --dataset-dir /path/to/NBaIoT/ OR --csv file.csv")
        X_benign, X_attack = generate_synthetic_data(args.n_samples, args.n_samples // 5, args.n_features)

    # Handle NaN/Inf
    X_benign = np.nan_to_num(X_benign, nan=0.0, posinf=1.0, neginf=0.0)
    if X_attack is not None:
        X_attack = np.nan_to_num(X_attack, nan=0.0, posinf=1.0, neginf=0.0)

    # Cap sample count for memory efficiency
    if len(X_benign) > args.max_samples:
        print(f"\nCapping benign samples to {args.max_samples:,} (from {len(X_benign):,})")
        idx = np.random.choice(len(X_benign), args.max_samples, replace=False)
        X_benign = X_benign[idx]

    # Train/test split for benign
    split = int(0.9 * len(X_benign))
    X_train = X_benign[:split]
    X_val = X_benign[split:]

    print(f"\nTraining set: {len(X_train):,} benign samples")
    print(f"Validation set: {len(X_val):,} benign samples")
    print(f"Features: {X_train.shape[1]}")

    # Train model
    print("\nTraining Autoencoder...")
    model = AutoencoderModel()
    metrics = model.train(X_train)

    print("\n" + "=" * 60)
    print("TRAINING METRICS")
    print("=" * 60)
    for k, v in metrics.items():
        print(f"  {k}: {v}")

    # Evaluate
    evaluate_model(model, X_val, X_attack)

    # Save
    model.save()
    print(f"\nModel saved to training/saved_models/autoencoder_model.pkl")
    print("Training complete!")


if __name__ == "__main__":
    main()
