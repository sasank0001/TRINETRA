"""
TRINETRA - Machine Learning Model Training Pipeline
===================================================

Trains a high-performance Random Forest Classifier to distinguish
legitimate links from phishing URLs.

Evaluation metrics calculated on an unseen test split:
  - Accuracy
  - Precision
  - Recall
  - F1-Score
  - ROC AUC
  - Confusion Matrix
  - Feature Importances

Saves:
  - `model/trinetra_rf_model.joblib`: The trained model artifact, metadata, and feature names.
  - `model/metrics.json`: Authentic evaluation metrics displayed in the dashboard and about page.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split

from feature_extraction import FEATURE_NAMES

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_CSV = os.path.join(BASE_DIR, "dataset", "processed_urls.csv")
MODEL_DIR = os.path.join(BASE_DIR, "model")
MODEL_PATH = os.path.join(MODEL_DIR, "trinetra_rf_model.joblib")
METRICS_PATH = os.path.join(MODEL_DIR, "metrics.json")


def train(test_size: float = 0.20, random_state: int = 42):
    if not os.path.exists(DATASET_CSV):
        print(f"[-] Processed dataset not found at {DATASET_CSV}.")
        print("[*] Running prepare_dataset.py to generate dataset...")
        from prepare_dataset import prepare_dataset
        prepare_dataset(sample_size_per_class=15000)

    print(f"[*] Loading processed dataset from {DATASET_CSV}...")
    df = pd.read_csv(DATASET_CSV)
    print(f"    Loaded {len(df)} samples.")

    # Validate feature columns
    missing = [f for f in FEATURE_NAMES if f not in df.columns]
    if missing:
        raise ValueError(f"Dataset is missing required features: {missing}")

    X = df[FEATURE_NAMES]
    y = df["label"].astype(int)

    print(f"[*] Class distribution in full dataset:")
    print(y.value_counts().rename({0: "0 (Legitimate)", 1: "1 (Phishing)"}))

    # Split dataset into training and test sets
    print(f"[*] Splitting dataset: {int((1-test_size)*100)}% Train, {int(test_size*100)}% Test (stratified)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=y
    )
    print(f"    Train size: {len(X_train)}, Test size: {len(X_test)}")

    # Initialize Random Forest Classifier
    # n_estimators=120, max_depth=25, n_jobs=-1 for fast parallel training
    print("[*] Initializing and training Random Forest Classifier...")
    rf = RandomForestClassifier(
        n_estimators=120,
        max_depth=25,
        min_samples_split=4,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=random_state,
        n_jobs=-1,
    )
    start_time = datetime.now()
    rf.fit(X_train, y_train)
    duration = (datetime.now() - start_time).total_seconds()
    print(f"[+] Model training completed in {duration:.2f} seconds.")

    # Evaluation on unseen test set
    print("[*] Evaluating model on unseen test set...")
    y_pred = rf.predict(X_test)
    y_prob = rf.predict_proba(X_test)[:, 1]

    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred))
    rec = float(recall_score(y_test, y_pred))
    f1 = float(f1_score(y_test, y_pred))
    auc = float(roc_auc_score(y_test, y_prob))
    cm = confusion_matrix(y_test, y_pred).tolist()

    print(f"----------------------------------------")
    print(f"  Accuracy:  {acc * 100:.2f}%")
    print(f"  Precision: {prec * 100:.2f}%")
    print(f"  Recall:    {rec * 100:.2f}%")
    print(f"  F1-Score:  {f1 * 100:.2f}%")
    print(f"  ROC AUC:   {auc:.4f}")
    print(f"----------------------------------------")
    print(f"Confusion Matrix [ [TN, FP], [FN, TP] ]:")
    print(np.array(cm))
    print(f"----------------------------------------")

    # Feature importances
    importances = rf.feature_importances_
    sorted_idx = np.argsort(importances)[::-1]
    top_features = [
        {"feature": FEATURE_NAMES[i], "importance": round(float(importances[i]), 5)}
        for i in sorted_idx
    ]
    print("[*] Top 10 most influential features:")
    for item in top_features[:10]:
        print(f"    - {item['feature']}: {item['importance']:.4f}")

    # Save model bundle
    os.makedirs(MODEL_DIR, exist_ok=True)
    bundle = {
        "model": rf,
        "feature_names": FEATURE_NAMES,
        "phishing_label": 1,
        "legitimate_label": 0,
        "version": "1.0.0",
        "algorithm": "RandomForestClassifier",
        "trained_at": datetime.now().isoformat(),
        "n_samples": len(df),
        "test_size": test_size,
    }
    joblib.dump(bundle, MODEL_PATH, compress=3)
    print(f"[+] Model bundle saved to {MODEL_PATH}")

    # Save authentic metrics
    metrics = {
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "roc_auc": round(auc, 4),
        "confusion_matrix": {
            "tn": cm[0][0],
            "fp": cm[0][1],
            "fn": cm[1][0],
            "tp": cm[1][1],
        },
        "train_samples": len(X_train),
        "test_samples": len(X_test),
        "total_samples": len(df),
        "top_features": top_features,
        "trained_at": bundle["trained_at"],
        "algorithm": "Random Forest Classifier",
        "version": "1.0.0",
    }
    with open(METRICS_PATH, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
    print(f"[+] Evaluation metrics saved to {METRICS_PATH}")
    return metrics


if __name__ == "__main__":
    train()
