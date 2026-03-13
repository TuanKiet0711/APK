"""
Train a Random-Forest classifier on the Drebin-215 dataset and save model + metadata.

Usage:
    python3 ml/train_model.py
"""
from __future__ import annotations
import json
import pickle
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.preprocessing import LabelEncoder

BASE_DIR   = Path(__file__).resolve().parent.parent
CSV_PATH   = BASE_DIR / "drebin-215-dataset-5560malware-9476-benign.csv"
MODEL_DIR  = BASE_DIR / "ml"
MODEL_PATH = MODEL_DIR / "model.pkl"
META_PATH  = MODEL_DIR / "model_meta.json"
METRICS_PATH = MODEL_DIR / "model_metrics.json"


def main() -> None:
    print(f"[*] Loading dataset: {CSV_PATH}")
    df = pd.read_csv(CSV_PATH, low_memory=False)
    print(f"    Shape: {df.shape}")
    print(f"    Label distribution:\n{df['class'].value_counts()}\n")

    # ── Features & label ────────────────────────────────────────────────────
    feature_cols = [c for c in df.columns if c != "class"]
    X = df[feature_cols].apply(pd.to_numeric, errors="coerce").fillna(0).values
    y_raw = df["class"].values          # 'S' = malware, 'B' = benign

    le = LabelEncoder()
    y  = le.fit_transform(y_raw)        # B → 0, S → 1 (alphabetical)
    classes = le.classes_.tolist()      # ['B', 'S']
    print(f"    Classes (encoded): {dict(zip(classes, le.transform(classes)))}")

    # ── Train / test split ──────────────────────────────────────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    print(f"    Train size: {X_train.shape[0]}  |  Test size: {X_test.shape[0]}\n")

    # ── Model ───────────────────────────────────────────────────────────────
    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        min_samples_leaf=1,
        n_jobs=-1,
        random_state=42,
        class_weight="balanced",
    )

    # 5-fold CV on training split
    print("[*] 5-fold cross-validation on training split …")
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_val_score(clf, X_train, y_train, cv=cv, scoring="f1")
    print(f"    CV F1: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}\n")

    # Final fit
    print("[*] Fitting final model …")
    clf.fit(X_train, y_train)

    # ── Evaluation ──────────────────────────────────────────────────────────
    y_pred = clf.predict(X_test)
    y_prob = clf.predict_proba(X_test)[:, classes.index("S")]

    acc    = accuracy_score(y_test, y_pred)
    roc    = roc_auc_score(y_test, y_prob)
    cm     = confusion_matrix(y_test, y_pred).tolist()
    report = classification_report(y_test, y_pred, target_names=classes, output_dict=True)

    print("[*] Test-set results:")
    print(classification_report(y_test, y_pred, target_names=classes))
    print("Confusion matrix:")
    print(np.array(cm))
    print(f"ROC-AUC: {roc:.4f}\n")

    # ── Save ────────────────────────────────────────────────────────────────
    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    with open(MODEL_PATH, "wb") as f:
        pickle.dump(clf, f)
    print(f"[+] Model saved → {MODEL_PATH}")

    meta = {
        "feature_cols":  feature_cols,
        "classes":       classes,
        "malware_label": "S",
        "malware_index": classes.index("S"),
    }
    META_PATH.write_text(json.dumps(meta, indent=2))
    print(f"[+] Meta saved  → {META_PATH}")

    metrics = {
        "algorithm":   "Random Forest (n=200, balanced)",
        "dataset":     "Drebin-215",
        "n_samples":   int(len(df)),
        "n_malware":   int((df["class"] == "S").sum()),
        "n_benign":    int((df["class"] == "B").sum()),
        "n_features":  len(feature_cols),
        "test_size":   0.20,
        "accuracy":    round(acc, 4),
        "roc_auc":     round(roc, 4),
        "cv_f1_mean":  round(float(cv_scores.mean()), 4),
        "cv_f1_std":   round(float(cv_scores.std()), 4),
        "confusion_matrix": cm,
        "classification_report": report,
    }
    METRICS_PATH.write_text(json.dumps(metrics, indent=2))
    print(f"[+] Metrics saved → {METRICS_PATH}")
    print("\nDone.")


if __name__ == "__main__":
    main()
