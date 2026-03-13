"""
Train a Random-Forest classifier on the Drebin-215 dataset and save model + metadata.

Usage:
    python3 ml/train_model.py
"""
from __future__ import annotations
import json
import pickle
from pathlib import Path
from typing import List, Tuple

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
LOCAL_LABELS_PATH = MODEL_DIR / "local_labels.json"


def _load_local_samples(feature_cols: List[str], class_to_int: dict) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    """
    Optional local adaptation set from ml/local_labels.json.

    Format:
    [
      {"apk_path": "C:/.../file.apk", "label": "S", "weight": 40},
      {"apk_path": "C:/.../file2.apk", "label": "B", "weight": 15}
    ]
    """
    if not LOCAL_LABELS_PATH.exists():
        return np.empty((0, len(feature_cols))), np.empty((0,), dtype=int), np.empty((0,), dtype=float)

    try:
        rows = json.loads(LOCAL_LABELS_PATH.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"[!] Could not parse {LOCAL_LABELS_PATH}: {exc}")
        return np.empty((0, len(feature_cols))), np.empty((0,), dtype=int), np.empty((0,), dtype=float)

    if not isinstance(rows, list):
        print(f"[!] {LOCAL_LABELS_PATH} must be a JSON list.")
        return np.empty((0, len(feature_cols))), np.empty((0,), dtype=int), np.empty((0,), dtype=float)

    # Late imports: only needed if local adaptation data is provided.
    import sys
    if str(BASE_DIR) not in sys.path:
        sys.path.insert(0, str(BASE_DIR))
    import apk_analyzer
    from ml.feature_extractor import extract_features

    X_loc: List[List[int]] = []
    y_loc: List[int] = []
    w_loc: List[float] = []

    print(f"[*] Loading local labeled APKs from: {LOCAL_LABELS_PATH}")
    for i, row in enumerate(rows, start=1):
        if not isinstance(row, dict):
            continue
        apk_path = Path(str(row.get("apk_path", "")).strip())
        label = str(row.get("label", "")).strip().upper()
        weight = float(row.get("weight", 20))

        if not apk_path.exists():
            print(f"    - [{i}] skip (missing): {apk_path}")
            continue
        if label not in class_to_int:
            print(f"    - [{i}] skip (unknown label '{label}'): {apk_path.name}")
            continue

        try:
            data = apk_analyzer.analyze_apk(apk_path)
            vec = extract_features(data, feature_cols)
            X_loc.append(vec)
            y_loc.append(int(class_to_int[label]))
            w_loc.append(weight)
            print(f"    - [{i}] ok  {apk_path.name}  label={label}  weight={weight}")
        except SystemExit:
            raise
        except Exception as exc:
            print(f"    - [{i}] failed {apk_path.name}: {exc}", file=sys.stderr)

    if not X_loc:
        return np.empty((0, len(feature_cols))), np.empty((0,), dtype=int), np.empty((0,), dtype=float)

    return np.array(X_loc), np.array(y_loc), np.array(w_loc, dtype=float)


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
    class_to_int = {c: int(le.transform([c])[0]) for c in classes}
    print(f"    Classes (encoded): {dict(zip(classes, le.transform(classes)))}")

    # ── Train / test split ──────────────────────────────────────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    print(f"    Train size: {X_train.shape[0]}  |  Test size: {X_test.shape[0]}\n")

    # Optional: add local, user-labeled APKs into the final training fit.
    X_loc, y_loc, w_loc = _load_local_samples(feature_cols, class_to_int)
    if len(y_loc) > 0:
        print(f"    Local adaptation samples: {len(y_loc)}")
    else:
        print("    Local adaptation samples: 0")

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
    if len(y_loc) > 0:
        X_fit = np.vstack([X_train, X_loc])
        y_fit = np.concatenate([y_train, y_loc])
        base_w = np.ones(X_train.shape[0], dtype=float)
        sample_weight = np.concatenate([base_w, w_loc])
        clf.fit(X_fit, y_fit, sample_weight=sample_weight)
        print(f"    Final fit uses base={X_train.shape[0]} + local={X_loc.shape[0]} samples")
    else:
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
    print(f"[+] Model saved -> {MODEL_PATH}")

    meta = {
        "feature_cols":  feature_cols,
        "classes":       classes,
        "malware_label": "S",
        "malware_index": classes.index("S"),
    }
    META_PATH.write_text(json.dumps(meta, indent=2))
    print(f"[+] Meta saved  -> {META_PATH}")

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
    print(f"[+] Metrics saved -> {METRICS_PATH}")
    print("\nDone.")


if __name__ == "__main__":
    main()
