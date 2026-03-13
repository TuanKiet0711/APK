import json
import pickle
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional

from django.db.models import Avg, Count
from django.http import HttpResponseBadRequest, JsonResponse
from django.views.decorators.csrf import csrf_exempt

# ---------------------------------------------------------------------------
# Lazy-load ML model once per process
# ---------------------------------------------------------------------------

_ML_MODEL:   Any = None
_ML_META:    Optional[Dict[str, Any]] = None
_ML_METRICS: Optional[Dict[str, Any]] = None
_ML_LOADED:  bool = False

def _load_ml():
    global _ML_MODEL, _ML_META, _ML_METRICS, _ML_LOADED
    if _ML_LOADED:
        return
    _ML_LOADED = True
    base = Path(__file__).resolve().parent.parent
    model_path   = base / "ml" / "model.pkl"
    meta_path    = base / "ml" / "model_meta.json"
    metrics_path = base / "ml" / "model_metrics.json"
    try:
        with open(model_path, "rb") as f:
            _ML_MODEL = pickle.load(f)
        _ML_META = json.loads(meta_path.read_text())
        if metrics_path.exists():
            _ML_METRICS = json.loads(metrics_path.read_text())
    except Exception as exc:
        _ML_MODEL   = None
        _ML_META    = None
        _ML_METRICS = None
        print(f"[ML] Could not load model: {exc}", file=sys.stderr)


def _ml_predict(apk_data: dict) -> Optional[Dict[str, Any]]:
    """Return ML prediction + AHP scoring dict, or None if model unavailable."""
    _load_ml()
    if _ML_MODEL is None or _ML_META is None:
        return None

    try:
        # Import feature extractor and AHP module from ml/ directory
        ml_dir = Path(__file__).resolve().parent.parent / "ml"
        if str(ml_dir) not in sys.path:
            sys.path.insert(0, str(ml_dir))
        import importlib
        import feature_extractor as _fe_mod  # type: ignore
        import ahp as _ahp_mod               # type: ignore
        importlib.reload(_fe_mod)
        importlib.reload(_ahp_mod)

        extract_features = _fe_mod.extract_features
        compute_ahp      = _ahp_mod.compute_ahp

        feature_cols  = _ML_META["feature_cols"]
        malware_index = _ML_META["malware_index"]
        classes       = _ML_META["classes"]

        vec  = extract_features(apk_data, feature_cols)
        prob = _ML_MODEL.predict_proba([vec])[0]
        pred = _ML_MODEL.predict([vec])[0]

        malware_prob = float(prob[malware_index])
        label        = classes[int(pred)]

        matched = [feature_cols[i] for i, v in enumerate(vec) if v == 1]

        # AHP scoring
        ahp_result = compute_ahp(vec, feature_cols, malware_prob)

        return {
            "label":            label,
            "is_malware":       label == _ML_META.get("malware_label", "S"),
            "probability":      round(malware_prob, 4),
            "score":            round(malware_prob * 100, 1),
            "features_matched": len(matched),
            "matched":          matched,
            "ahp":              ahp_result,
            "model_metrics":    _ML_METRICS,
        }
    except Exception as exc:
        import traceback
        return {"error": str(exc), "traceback": traceback.format_exc()}


# ---------------------------------------------------------------------------
# View
# ---------------------------------------------------------------------------

def _save_result(filename: str, data: dict, ml: Optional[Dict[str, Any]]) -> None:
    """Persist analysis result to the ApkAnalysis table."""
    try:
        from web.models import ApkAnalysis
        meta = data.get("metadata") or {}
        ahp  = (ml or {}).get("ahp") or {}
        ApkAnalysis.objects.create(
            filename          = filename,
            package_name      = meta.get("package_name", "") or "",
            version_name      = meta.get("version_name", "") or "",
            ml_label          = (ml or {}).get("label", ""),
            ml_is_malware     = (ml or {}).get("is_malware"),
            ml_probability    = (ml or {}).get("probability"),
            ml_score          = (ml or {}).get("score"),
            ml_features_matched = (ml or {}).get("features_matched"),
            ahp_score         = ahp.get("ahp_score"),
            ahp_combined      = ahp.get("combined"),
            ahp_verdict       = ahp.get("verdict", ""),
            s_c1 = ahp.get("S_C1"), s_c2 = ahp.get("S_C2"),
            s_c3 = ahp.get("S_C3"), s_c4 = ahp.get("S_C4"),
            n_c1 = ahp.get("n_C1"), n_c2 = ahp.get("n_C2"),
            n_c3 = ahp.get("n_C3"), n_c4 = ahp.get("n_C4"),
            full_result = {
                "metadata": data.get("metadata"),
                "ml_prediction": ml,
            },
        )
    except Exception as exc:
        print(f"[DB] Failed to save result: {exc}", file=sys.stderr)


@csrf_exempt
def ahp_info(request):
    """Return static AHP derivation info (matrix, weights, consistency)."""
    ml_dir = Path(__file__).resolve().parent.parent / "ml"
    if str(ml_dir) not in sys.path:
        sys.path.insert(0, str(ml_dir))
    try:
        import importlib
        import ahp as _ahp_mod
        importlib.reload(_ahp_mod)
        return JsonResponse(_ahp_mod.get_ahp_info())
    except Exception as exc:
        return JsonResponse({"error": str(exc)}, status=500)


@csrf_exempt
def stats(request):
    """Return aggregated statistics from stored analyses."""
    from web.models import ApkAnalysis
    qs = ApkAnalysis.objects.all()

    total    = qs.count()
    malware  = qs.filter(ml_is_malware=True).count()
    benign   = qs.filter(ml_is_malware=False).count()
    unknown  = total - malware - benign

    verdict_counts = {
        "AN TOÀN":  qs.filter(ahp_verdict="AN TOÀN").count(),
        "NGHI NGỜ": qs.filter(ahp_verdict="NGHI NGỜ").count(),
        "NGUY HIỂM": qs.filter(ahp_verdict="NGUY HIỂM").count(),
    }

    avgs = qs.aggregate(
        avg_combined = Avg("ahp_combined"),
        avg_ml_prob  = Avg("ml_probability"),
        avg_s_c1     = Avg("s_c1"),
        avg_s_c2     = Avg("s_c2"),
        avg_s_c3     = Avg("s_c3"),
        avg_s_c4     = Avg("s_c4"),
    )

    recent = list(
        qs.values(
            "id", "filename", "package_name", "analyzed_at",
            "ml_label", "ml_is_malware", "ml_probability",
            "ahp_combined", "ahp_verdict",
            "s_c1", "s_c2", "s_c3", "s_c4",
        )[:50]
    )
    # Convert datetime to string
    for r in recent:
        if r["analyzed_at"]:
            r["analyzed_at"] = r["analyzed_at"].strftime("%Y-%m-%d %H:%M")

    # Score histogram buckets (0–10, 10–20, … 90–100)
    histogram = [0] * 10
    for row in qs.values_list("ahp_combined", flat=True):
        if row is not None:
            bucket = min(9, int(row * 10))
            histogram[bucket] += 1

    return JsonResponse({
        "total": total, "malware": malware, "benign": benign, "unknown": unknown,
        "verdict_counts": verdict_counts,
        "averages": {k: round(v, 4) if v is not None else None for k, v in avgs.items()},
        "histogram": histogram,
        "recent": recent,
    })


@csrf_exempt
def analyze_apk(request):
    if request.method != "POST":
        return HttpResponseBadRequest("POST only")

    if "apk" not in request.FILES:
        return HttpResponseBadRequest("Missing file field: apk")

    apk_file = request.FILES["apk"]

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)
        apk_path = tmpdir_path / apk_file.name
        with apk_path.open("wb") as f:
            for chunk in apk_file.chunks():
                f.write(chunk)

        out_json = tmpdir_path / "out.json"
        analyzer_path = Path(__file__).resolve().parent.parent / "apk_analyzer.py"
        cmd = [
            sys.executable,
            str(analyzer_path),
            str(apk_path),
            str(out_json),
            "--fast",
        ]

        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as exc:
            return JsonResponse(
                {"error": "analyzer_failed", "stderr": exc.stderr, "stdout": exc.stdout},
                status=500,
            )

        data = json.loads(out_json.read_text(encoding="utf-8"))

        # Attach ML prediction + AHP
        ml = _ml_predict(data)
        data["ml_prediction"] = ml

        # Persist to database
        _save_result(apk_file.name, data, ml)

        return JsonResponse(data, json_dumps_params={"ensure_ascii": True, "indent": 2})
