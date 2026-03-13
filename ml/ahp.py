"""
AHP (Analytic Hierarchy Process) scoring for APK risk assessment.

Full derivation shown:
  1. Pairwise comparison matrix A (Saaty 1–9 scale)
  2. Column-normalised matrix  → priority vector w (geometric-mean method)
  3. Weighted-sum vector  v = A × w
  4. λ_i = v_i / w_i for each criterion
  5. λ_max = mean(λ_i)
  6. CI  = (λ_max − n) / (n − 1)
  7. RI(n=4) = 0.90  (Saaty's random index)
  8. CR  = CI / RI   → must be < 0.10 to be consistent

Final scoring:
  AHP_score = Σ w_i × S_i          (S_i = n_found_i / N_total_i)
  combined  = w_ML × P_ML + (1 − w_ML) × AHP_score
"""

import math
import re
from typing import Dict, List, Set, Tuple

# ---------------------------------------------------------------------------
# Pairwise comparison matrix  (4×4, same order: C1 C2 C3 C4)
# ---------------------------------------------------------------------------

_CRITERIA = ["C1", "C2", "C3", "C4"]
_CRITERIA_LABELS = {
    "C1": "Permissions",
    "C2": "API Calls",
    "C3": "Intents",
    "C4": "Commands/IPC",
}

# Raw pairwise matrix (row i vs col j)
_A_RAW: List[List[float]] = [
    [1,      2,      4,      3   ],   # C1
    [1/2,    1,      3,      2   ],   # C2
    [1/4,    1/3,    1,      1/2 ],   # C3
    [1/3,    1/2,    2,      1   ],   # C4
]

# Random Consistency Index (Saaty 1977) by matrix size
_RI = {1: 0.00, 2: 0.00, 3: 0.58, 4: 0.90, 5: 1.12,
       6: 1.24, 7: 1.32, 8: 1.41, 9: 1.45, 10: 1.49}

# Weight of the ML model vs AHP sub-scores
W_ML: float = 0.4

# (upper_bound, display_label, CSS_class)
_VERDICTS = [
    (0.30, "AN TOÀN",   "safe"),
    (0.70, "NGHI NGỜ",  "warn"),
    (1.01, "NGUY HIỂM", "bad"),
]


# ---------------------------------------------------------------------------
# AHP derivation (computed once at import)
# ---------------------------------------------------------------------------

def _derive_ahp(A: List[List[float]]) -> Dict:
    """Full AHP derivation: weights, consistency check, all intermediate steps."""
    n = len(A)

    # ── Step 1: column sums ──────────────────────────────────────────────────
    col_sums = [sum(A[r][c] for r in range(n)) for c in range(n)]

    # ── Step 2: column-normalised matrix ────────────────────────────────────
    norm = [[A[r][c] / col_sums[c] for c in range(n)] for r in range(n)]

    # ── Step 3: priority vector  (row means of normalised matrix) ───────────
    w = [sum(norm[r]) / n for r in range(n)]

    # ── Step 4: weighted-sum vector  v = A × w ──────────────────────────────
    v = [sum(A[r][c] * w[c] for c in range(n)) for r in range(n)]

    # ── Step 5: λ_i per criterion ───────────────────────────────────────────
    lambdas = [v[i] / w[i] for i in range(n)]

    # ── Step 6: λ_max ───────────────────────────────────────────────────────
    lam_max = sum(lambdas) / n

    # ── Step 7–8: CI, RI, CR ────────────────────────────────────────────────
    CI = (lam_max - n) / (n - 1)
    RI = _RI.get(n, 1.49)
    CR = CI / RI if RI > 0 else 0.0
    consistent = CR < 0.10

    return {
        "n":           n,
        "A":           A,
        "col_sums":    [round(x, 4) for x in col_sums],
        "norm_matrix": [[round(x, 4) for x in row] for row in norm],
        "weights":     {_CRITERIA[i]: round(w[i], 4) for i in range(n)},
        "weights_list": [round(x, 4) for x in w],
        "v":           [round(x, 4) for x in v],
        "lambdas":     {_CRITERIA[i]: round(lambdas[i], 4) for i in range(n)},
        "lam_max":     round(lam_max, 4),
        "CI":          round(CI, 4),
        "RI":          RI,
        "CR":          round(CR, 4),
        "consistent":  consistent,
        "criteria":    _CRITERIA,
        "criteria_labels": _CRITERIA_LABELS,
        "w_ml":        W_ML,
    }


# Compute once
_AHP_INFO: Dict = _derive_ahp(_A_RAW)
WEIGHTS: Dict[str, float] = _AHP_INFO["weights"]


# ---------------------------------------------------------------------------
# Feature → group assignment
# ---------------------------------------------------------------------------

_PERM_RE = re.compile(r'^[A-Z][A-Z0-9_]+$')

_C4_NAMES: Set[str] = {
    'chmod', 'chown', 'mount', 'remount', 'su', 'busybox', 'createSubprocess',
    'transact', 'onBind', 'onServiceConnected', 'bindService', 'attachInterface',
    'getBinder', 'getCallingUid', 'getCallingPid', 'abortBroadcast',
    'divideMessage', 'sendMultipartTextMessage', 'sendDataMessage',
    'PackageInstaller', 'MessengerService', 'IRemoteService', 'KeySpec', 'SecretKey',
    'Binder', 'IBinder', 'ClassLoader', 'URLClassLoader', 'ServiceConnection',
    'HttpGet.init', 'HttpPost.init', 'HttpUriRequest', 'Process.start',
    'Context.bindService',
}

_GROUP_CACHE: Dict[str, str] = {}


def _classify_feature(feat: str) -> str:
    fl = feat.lower()
    if 'intent' in fl or feat.startswith('android.intent'):
        return 'C3'
    if feat.startswith('/') or feat in _C4_NAMES:
        return 'C4'
    if _PERM_RE.match(feat):
        return 'C1'
    return 'C2'


def _get_group_indices(feature_cols: List[str]) -> Dict[str, List[int]]:
    groups: Dict[str, List[int]] = {'C1': [], 'C2': [], 'C3': [], 'C4': []}
    for i, feat in enumerate(feature_cols):
        g = _GROUP_CACHE.get(feat)
        if g is None:
            g = _classify_feature(feat)
            _GROUP_CACHE[feat] = g
        groups[g].append(i)
    return groups


# ---------------------------------------------------------------------------
# Main public function
# ---------------------------------------------------------------------------

def compute_ahp(vec, feature_cols: List[str], ml_prob: float) -> Dict:
    """
    Compute AHP-based risk score.

    Returns all derivation info (weights, consistency) plus per-APK scores.
    """
    groups = _get_group_indices(feature_cols)
    info = _AHP_INFO   # pre-computed derivation

    result: Dict = {
        # ── derivation / consistency (static, same for every APK) ──────
        "weights":       info["weights"],
        "weights_list":  info["weights_list"],
        "norm_matrix":   info["norm_matrix"],
        "col_sums":      info["col_sums"],
        "lambdas":       info["lambdas"],
        "lam_max":       info["lam_max"],
        "CI":            info["CI"],
        "RI":            info["RI"],
        "CR":            info["CR"],
        "consistent":    info["consistent"],
        "criteria":      info["criteria"],
        "criteria_labels": info["criteria_labels"],
        "A_matrix":      info["A"],
        "v":             info["v"],
        # ── ML weight ──────────────────────────────────────────────────
        "w_ml":          W_ML,
        "ml_prob":       round(float(ml_prob), 4),
    }

    ahp_score = 0.0
    for key in _CRITERIA:
        idxs = groups[key]
        N = len(idxs)
        n = int(sum(vec[i] for i in idxs))
        S = n / N if N > 0 else 0.0
        result[f"n_{key}"] = n
        result[f"N_{key}"] = N
        result[f"S_{key}"] = round(S, 4)
        ahp_score += WEIGHTS[key] * S

    # Weighted contribution per criterion (for UI breakdown)
    result["contrib"] = {
        k: round(WEIGHTS[k] * result[f"S_{k}"], 4) for k in _CRITERIA
    }

    result["ahp_score"] = round(ahp_score, 4)

    combined = W_ML * float(ml_prob) + (1.0 - W_ML) * ahp_score
    combined = max(0.0, min(1.0, combined))
    result["combined"] = round(combined, 4)

    for threshold, label, cls in _VERDICTS:
        if combined < threshold:
            result["verdict"] = label
            result["verdict_class"] = cls
            break
    else:
        result["verdict"] = "NGUY HIỂM"
        result["verdict_class"] = "bad"

    return result


def get_ahp_info() -> Dict:
    """Return static AHP derivation info (no per-APK data needed)."""
    return _AHP_INFO

