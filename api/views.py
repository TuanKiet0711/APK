import json
import logging
import pickle
import subprocess
import sys
import tempfile
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

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
_ML_LOAD_ERROR: Optional[str] = None
_ML_MODEL_MTIME_NS: Optional[int] = None
_ML_META_MTIME_NS: Optional[int] = None
_ANALYSIS_LOGGER: Optional[logging.Logger] = None


def _get_analysis_logger() -> logging.Logger:
    """Create a rotating JSON-line logger for APK decision traces."""
    global _ANALYSIS_LOGGER
    if _ANALYSIS_LOGGER is not None:
        return _ANALYSIS_LOGGER

    base = Path(__file__).resolve().parent.parent
    log_dir = base / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / "apk_analysis.log"

    logger = logging.getLogger("apk_analysis")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    if not logger.handlers:
        handler = RotatingFileHandler(
            log_path,
            maxBytes=2_000_000,
            backupCount=3,
            encoding="utf-8",
        )
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)

    _ANALYSIS_LOGGER = logger
    return logger


def _count_exported_components(data: Dict[str, Any]) -> int:
    comps = data.get("components") or {}
    count = 0
    for key in ("activities", "services", "receivers", "providers"):
        for comp in comps.get(key) or []:
            if isinstance(comp, dict) and comp.get("exported") is True:
                count += 1
    return count


def _normalize_perms(values: List[str]) -> Set[str]:
    out: Set[str] = set()
    for val in values:
        s = str(val or "").strip()
        if not s:
            continue
        out.add(s)
        if "." in s:
            out.add(s.rsplit(".", 1)[1])
        if "/" in s:
            out.add(s.rsplit("/", 1)[1])
    return out


_SENSITIVE_PERMS: Set[str] = {
    "SEND_SMS",
    "READ_SMS",
    "RECEIVE_SMS",
    "WRITE_SMS",
    "READ_PHONE_STATE",
    "GET_ACCOUNTS",
    "READ_CONTACTS",
    "READ_CALL_LOG",
    "WRITE_CALL_LOG",
    "SYSTEM_ALERT_WINDOW",
    "REQUEST_INSTALL_PACKAGES",
    "INSTALL_PACKAGES",
    "DELETE_PACKAGES",
    "REBOOT",
    "BIND_DEVICE_ADMIN",
    "DEVICE_ADMIN",
    "ACCESS_FINE_LOCATION",
    "ACCESS_COARSE_LOCATION",
    "RECORD_AUDIO",
}

_SUSPICIOUS_APIS: List[str] = [
    "Runtime.exec",
    "ProcessBuilder",
    "DexClassLoader",
    "PathClassLoader",
    "defineClass",
    "System.loadLibrary",
    "Runtime.load",
    "Class.forName",
    "getDeclaredField",
    "getMethod",
    "getDeviceId",
    "getSubscriberId",
    "getLine1Number",
]


def _build_risk_assessment(data: Dict[str, Any], ml: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Risk score from ML + AHP only (no heuristic/rule contribution).
    """
    ml_obj = ml or {}
    ahp = ml_obj.get("ahp") or {}

    ml_score = ml_obj.get("score")
    if not isinstance(ml_score, (int, float)):
        ml_score = None

    ahp_combined = ahp.get("combined")
    ahp_pct = float(ahp_combined) * 100 if isinstance(ahp_combined, (int, float)) else None

    if ml_score is not None:
        score = float(ml_score)
    elif ahp_pct is not None:
        # Fallback only when ML score is unavailable.
        score = ahp_pct
    else:
        score = 0.0

    score = max(0.0, min(100.0, score))

    if score < 25.0:
        verdict = "AN TOÀN"
        verdict_class = "safe"
    elif score < 55.0:
        verdict = "NGHI NGỜ"
        verdict_class = "warn"
    else:
        verdict = "NGUY HIỂM"
        verdict_class = "bad"

    reasons: List[str] = []
    if ml_score is not None:
        reasons.append(f"ML score: {float(ml_score):.1f}")
    if ahp_pct is not None:
        reasons.append(f"AHP combined: {ahp_pct:.1f}")
    if not reasons:
        reasons.append("Thiếu dữ liệu ML/AHP")

    return {
        "score": round(score, 1),
        "verdict": verdict,
        "verdict_class": verdict_class,
        "heuristic_score": None,
        "ml_score": round(float(ml_score), 1) if ml_score is not None else None,
        "ahp_score": round(float(ahp_pct), 1) if ahp_pct is not None else None,
        "net_ioc_count": None,
        "exported_count": None,
        "hit_permissions": [],
        "hit_apis": [],
        "reasons": reasons,
    }


def _log_analysis_trace(filename: str, data: Dict[str, Any], ml: Optional[Dict[str, Any]], fast_flag: bool) -> None:
    """Write one structured decision log entry for each analyzed APK."""
    try:
        meta = data.get("metadata") or {}
        perms = data.get("permissions") or {}
        net = data.get("network") or {}
        ml_obj = ml or {}
        ahp = ml_obj.get("ahp") or {}
        matched = ml_obj.get("matched") or []

        requested = perms.get("requested") or []
        declared = perms.get("declared") or []
        urls = net.get("urls") or []
        domains = net.get("domains") or []
        ips = net.get("ips") or []
        net_count = len(urls) + len(domains) + len(ips)

        record: Dict[str, Any] = {
            "filename": filename,
            "package_name": meta.get("package_name"),
            "version_name": meta.get("version_name"),
            "analysis_mode": "fast" if fast_flag else "full",
            "counts": {
                "permissions_requested": len(requested),
                "permissions_declared": len(declared),
                "api_calls": len(data.get("api_calls") or []),
                "strings": len(data.get("strings") or []),
                "network_ioc": net_count,
                "exported_components": _count_exported_components(data),
            },
            "ml": {
                "error": ml_obj.get("error"),
                "label": ml_obj.get("label"),
                "is_malware": ml_obj.get("is_malware"),
                "probability": ml_obj.get("probability"),
                "score": ml_obj.get("score"),
                "features_matched": ml_obj.get("features_matched"),
                "matched_top30": matched[:30],
            },
            "ahp": {
                "score": ahp.get("ahp_score"),
                "combined": ahp.get("combined"),
                "verdict": ahp.get("verdict"),
                "S_C1": ahp.get("S_C1"),
                "S_C2": ahp.get("S_C2"),
                "S_C3": ahp.get("S_C3"),
                "S_C4": ahp.get("S_C4"),
            },
            "risk_assessment": data.get("risk_assessment"),
        }

        p = ml_obj.get("probability")
        if isinstance(p, (int, float)):
            if p < 0.05 and net_count >= 1000:
                record["warning"] = "very_low_ml_prob_but_very_high_network_ioc"

        _get_analysis_logger().info(json.dumps(record, ensure_ascii=False))
    except Exception as exc:
        print(f"[LOG] Failed to write analysis trace: {exc}", file=sys.stderr)

def _load_ml():
    global _ML_MODEL, _ML_META, _ML_METRICS, _ML_LOADED, _ML_LOAD_ERROR
    global _ML_MODEL_MTIME_NS, _ML_META_MTIME_NS
    base = Path(__file__).resolve().parent.parent
    model_path   = base / "ml" / "model.pkl"
    meta_path    = base / "ml" / "model_meta.json"
    metrics_path = base / "ml" / "model_metrics.json"

    try:
        model_mtime_ns = model_path.stat().st_mtime_ns
        meta_mtime_ns = meta_path.stat().st_mtime_ns
    except Exception as exc:
        _ML_MODEL   = None
        _ML_META    = None
        _ML_METRICS = None
        _ML_LOADED = False
        _ML_MODEL_MTIME_NS = None
        _ML_META_MTIME_NS = None
        _ML_LOAD_ERROR = str(exc)
        print(f"[ML] Could not load model: {_ML_LOAD_ERROR}", file=sys.stderr)
        return

    if (
        _ML_LOADED
        and _ML_MODEL is not None
        and _ML_META is not None
        and _ML_MODEL_MTIME_NS == model_mtime_ns
        and _ML_META_MTIME_NS == meta_mtime_ns
    ):
        return

    try:
        with open(model_path, "rb") as f:
            _ML_MODEL = pickle.load(f)
        _ML_META = json.loads(meta_path.read_text())
        _ML_METRICS = None
        if metrics_path.exists():
            _ML_METRICS = json.loads(metrics_path.read_text())
        _ML_LOADED = True
        _ML_MODEL_MTIME_NS = model_mtime_ns
        _ML_META_MTIME_NS = meta_mtime_ns
        _ML_LOAD_ERROR = None
    except Exception as exc:
        _ML_MODEL   = None
        _ML_META    = None
        _ML_METRICS = None
        _ML_LOADED = False
        _ML_MODEL_MTIME_NS = None
        _ML_META_MTIME_NS = None
        _ML_LOAD_ERROR = str(exc)
        print(f"[ML] Could not load model: {_ML_LOAD_ERROR}", file=sys.stderr)


def _ml_predict(apk_data: dict) -> Optional[Dict[str, Any]]:
    """Return ML prediction + AHP scoring dict, or None if model unavailable."""
    _load_ml()
    if _ML_MODEL is None or _ML_META is None:
        return {
            "error": "ml_unavailable",
            "detail": _ML_LOAD_ERROR or "Model is not loaded.",
        }

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

    def _risk_from_ml_prob(p: Optional[float]):
        if p is None:
            return None, "—", "safe"
        score = max(0.0, min(100.0, float(p) * 100.0))
        if score < 25.0:
            return round(score, 1), "AN TOÀN", "safe"
        if score < 55.0:
            return round(score, 1), "NGHI NGỜ", "warn"
        return round(score, 1), "NGUY HIỂM", "bad"

    verdict_counts = {"AN TOÀN": 0, "NGHI NGỜ": 0, "NGUY HIỂM": 0}
    for p in qs.values_list("ml_probability", flat=True):
        _, verdict, _ = _risk_from_ml_prob(p)
        if verdict in verdict_counts:
            verdict_counts[verdict] += 1

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
        risk_score, risk_verdict, risk_class = _risk_from_ml_prob(r.get("ml_probability"))
        r["risk_score"] = risk_score
        r["risk_verdict"] = risk_verdict
        r["risk_class"] = risk_class

    # Score histogram buckets (0–10, 10–20, … 90–100)
    histogram = [0] * 10
    for row in qs.values_list("ml_probability", flat=True):
        if row is not None:
            bucket = min(9, int(float(row) * 10))
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
        # Default to full analysis for better detection quality.
        # Client can still force fast mode by sending fast=1.
        fast_flag = str(request.POST.get("fast", "")).strip().lower() in {"1", "true", "yes", "on"}
        cmd = [
            sys.executable,
            str(analyzer_path),
            str(apk_path),
            str(out_json),
        ]
        if fast_flag:
            cmd.append("--fast")

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
        data["risk_assessment"] = _build_risk_assessment(data, ml)
        _log_analysis_trace(apk_file.name, data, ml, fast_flag)

        # Persist to database
        _save_result(apk_file.name, data, ml)

        return JsonResponse(data, json_dumps_params={"ensure_ascii": True, "indent": 2})
