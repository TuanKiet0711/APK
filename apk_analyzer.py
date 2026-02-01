
from __future__ import annotations
import argparse
import json
import re
import sys
from collections import Counter
from csv import DictReader
from hashlib import sha256
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import logging


URL_RE = re.compile(
    r"\b((?:https?|wss?)://[^\s\"'<>]+)", re.IGNORECASE
)
DOMAIN_RE = re.compile(
    r"\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b", re.IGNORECASE
)
IP_RE = re.compile(
    r"\b((?:\d{1,3}\.){3}\d{1,3})\b"
)


def _require_androguard() -> None:
    try:
        import androguard  # noqa: F401
    except Exception as exc:  # pragma: no cover
        print(
            "ERROR: androguard is required. Install with: pip install androguard",
            file=sys.stderr,
        )
        raise SystemExit(2) from exc


def _safe_list(obj: Optional[List[str]]) -> List[str]:
    return list(obj) if obj else []


def _intent_filters(apk_obj: Any, comp_type: str, name: str) -> Dict[str, List[str]]:
    data: Dict[str, List[str]] = {"actions": [], "categories": [], "data": []}
    try:
        filters = apk_obj.get_intent_filters(comp_type, name) or {}
    except Exception:
        return data

    data["actions"] = _safe_list(filters.get("action"))
    data["categories"] = _safe_list(filters.get("category"))
    data["data"] = _safe_list(filters.get("data"))
    return data


def _component_attr(apk_obj: Any, comp_type: str, name: str, attr: str) -> Optional[str]:
    try:
        # androguard APK supports attribute_filter by name
        return apk_obj.get_attribute_value(comp_type, attr, name=name)
    except Exception:
        return None


def _to_bool(val: Optional[str]) -> Optional[bool]:
    if val is None:
        return None
    if isinstance(val, str):
        return val.strip().lower() in {"1", "true", "yes"}
    return bool(val)


def _dex_strings(dex_list: List[Any]) -> List[str]:
    out: List[str] = []
    for d in dex_list:
        try:
            out.extend(d.get_strings() or [])
        except Exception:
            continue
    # Deduplicate while preserving order
    seen: Set[str] = set()
    uniq: List[str] = []
    for s in out:
        if s not in seen:
            seen.add(s)
            uniq.append(s)
    return uniq


def _extract_urls_domains_ips(strings: List[str]) -> Tuple[List[str], List[str], List[str]]:
    urls: Set[str] = set()
    domains: Set[str] = set()
    ips: Set[str] = set()
    for s in strings:
        for m in URL_RE.findall(s):
            urls.add(m)
        for m in DOMAIN_RE.findall(s):
            domains.add(m.lower())
        for m in IP_RE.findall(s):
            ips.add(m)
    return sorted(urls), sorted(domains), sorted(ips)


def _class_package_roots(dex_list: List[Any], app_package: str) -> Dict[str, int]:
    roots: Counter[str] = Counter()
    app_root = app_package.split(".")[0] if app_package else ""
    for d in dex_list:
        try:
            classes = d.get_classes() or []
        except Exception:
            continue
        for c in classes:
            name = c.get_name()  # e.g., Lcom/example/Foo;
            if not name or not name.startswith("L") or "/" not in name:
                continue
            pkg = name[1:].split(";")[0].replace("/", ".")
            root = pkg.split(".")[0]
            if not root:
                continue
            roots[root] += 1

    # Filter obvious SDK roots and the app root
    filtered = {
        k: v
        for k, v in roots.items()
        if k not in {"android", "java", "javax", "kotlin", "kotlinx", "dalvik", "org"}
        and k != app_root
    }
    return dict(sorted(filtered.items(), key=lambda kv: (-kv[1], kv[0])))


def _api_calls(dx: Any) -> List[Dict[str, Any]]:
    calls: List[Dict[str, Any]] = []
    try:
        methods = dx.get_methods() or []
    except Exception:
        return calls

    seen: Set[str] = set()
    for m in methods:
        try:
            method = m.get_method()
            class_name = method.get_class_name()
            name = method.get_name()
            desc = method.get_descriptor()
            signature = f"{class_name}->{name}{desc}"
            if signature in seen:
                continue
            seen.add(signature)
            is_external = False
            if hasattr(method, "is_external"):
                try:
                    is_external = bool(method.is_external())
                except Exception:
                    is_external = False
            calls.append(
                {
                    "class": class_name,
                    "name": name,
                    "descriptor": desc,
                    "signature": signature,
                    "is_external": is_external,
                }
            )
        except Exception:
            continue
    return calls


def _is_debuggable_apk(apk_obj: Any) -> Optional[bool]:
    try:
        val = apk_obj.get_attribute_value("application", "debuggable")
        if val is None:
            return None
        if isinstance(val, str):
            return val.strip().lower() in {"1", "true", "yes"}
        return bool(val)
    except Exception:
        return None


def _get_requested_permissions(apk_obj: Any) -> List[str]:
    if hasattr(apk_obj, "get_requested_permissions"):
        try:
            return _safe_list(apk_obj.get_requested_permissions())
        except Exception:
            return []
    # androguard APK fallback
    perms: List[str] = []
    if hasattr(apk_obj, "get_permissions"):
        try:
            perms.extend(_safe_list(apk_obj.get_permissions()))
        except Exception:
            pass
    if hasattr(apk_obj, "get_requested_aosp_permissions"):
        try:
            perms.extend(_safe_list(apk_obj.get_requested_aosp_permissions()))
        except Exception:
            pass
    if hasattr(apk_obj, "get_requested_third_party_permissions"):
        try:
            perms.extend(_safe_list(apk_obj.get_requested_third_party_permissions()))
        except Exception:
            pass
    # Deduplicate while preserving order
    seen: Set[str] = set()
    uniq: List[str] = []
    for p in perms:
        if p not in seen:
            seen.add(p)
            uniq.append(p)
    return uniq


def _get_declared_permissions(apk_obj: Any) -> List[str]:
    if hasattr(apk_obj, "get_permissions"):
        try:
            return _safe_list(apk_obj.get_permissions())
        except Exception:
            return []
    if hasattr(apk_obj, "get_declared_permissions"):
        try:
            return _safe_list(apk_obj.get_declared_permissions())
        except Exception:
            return []
    return []


def _get_certificates_info(apk_obj: Any) -> List[Dict[str, Any]]:
    certs: List[Dict[str, Any]] = []
    # Prefer DER if available
    for meth in ("get_certificates_der_v3", "get_certificates_der_v2", "get_certificates_der_v1"):
        if hasattr(apk_obj, meth):
            try:
                der_list = getattr(apk_obj, meth)() or []
                for der in der_list:
                    if not der:
                        continue
                    certs.append(
                        {
                            "sha256": sha256(der).hexdigest(),
                            "source": meth,
                        }
                    )
            except Exception:
                continue
    # Fallback: string representation
    if not certs and hasattr(apk_obj, "get_certificates"):
        try:
            for c in apk_obj.get_certificates() or []:
                certs.append({"repr": str(c), "source": "get_certificates"})
        except Exception:
            pass
    return certs


def _get_native_libs(apk_obj: Any) -> List[str]:
    libs: List[str] = []
    try:
        files = apk_obj.get_files() or []
    except Exception:
        return libs
    for f in files:
        if f.startswith("lib/") and f.endswith(".so"):
            libs.append(f)
    return sorted(libs)


def _get_file_type_counts(apk_obj: Any) -> Dict[str, int]:
    counts: Counter[str] = Counter()
    try:
        files = apk_obj.get_files() or []
    except Exception:
        return {}
    for f in files:
        ext = f.rsplit(".", 1)[-1].lower() if "." in f else ""
        counts[ext] += 1
    return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))


def analyze_apk(apk_path: Path) -> Dict[str, Any]:
    _require_androguard()
    logging.getLogger("androguard").setLevel(logging.WARNING)
    from androguard.misc import AnalyzeAPK  # type: ignore
    a, d, dx = AnalyzeAPK(str(apk_path))
    dex_list: List[Any] = d if isinstance(d, list) else [d]

    package_name = a.get_package()

    activities = _safe_list(a.get_activities())
    services = _safe_list(a.get_services())
    receivers = _safe_list(a.get_receivers())
    providers = _safe_list(a.get_providers())

    components = {
        "activities": [
            {
                "name": n,
                "intent_filters": _intent_filters(a, "activity", n),
                "exported": _to_bool(_component_attr(a, "activity", n, "exported")),
                "permission": _component_attr(a, "activity", n, "permission"),
            }
            for n in activities
        ],
        "services": [
            {
                "name": n,
                "intent_filters": _intent_filters(a, "service", n),
                "exported": _to_bool(_component_attr(a, "service", n, "exported")),
                "permission": _component_attr(a, "service", n, "permission"),
            }
            for n in services
        ],
        "receivers": [
            {
                "name": n,
                "intent_filters": _intent_filters(a, "receiver", n),
                "exported": _to_bool(_component_attr(a, "receiver", n, "exported")),
                "permission": _component_attr(a, "receiver", n, "permission"),
            }
            for n in receivers
        ],
        "providers": [
            {
                "name": n,
                "intent_filters": _intent_filters(a, "provider", n),
                "exported": _to_bool(_component_attr(a, "provider", n, "exported")),
                "permission": _component_attr(a, "provider", n, "permission"),
            }
            for n in providers
        ],
    }

    strings = _dex_strings(dex_list)
    urls, domains, ips = _extract_urls_domains_ips(strings)

    data: Dict[str, Any] = {
        "apk": {
            "path": str(apk_path),
            "size_bytes": apk_path.stat().st_size,
        },
        "metadata": {
            "package_name": package_name,
            "version_name": a.get_androidversion_name(),
            "version_code": a.get_androidversion_code(),
            "min_sdk": a.get_min_sdk_version(),
            "target_sdk": a.get_target_sdk_version(),
            "debuggable": _is_debuggable_apk(a),
        },
        "permissions": {
            "requested": _get_requested_permissions(a),
            "declared": _get_declared_permissions(a),
        },
        "components": components,
        "api_calls": _api_calls(dx),
        "strings": strings,
        "certificates": _get_certificates_info(a),
        "native_libs": _get_native_libs(a),
        "file_types": _get_file_type_counts(a),
        "network": {
            "urls": urls,
            "domains": domains,
            "ips": ips,
        },
        "package_roots": _class_package_roots(dex_list, package_name),
    }
    return data


def analyze_apk_fast(apk_path: Path) -> Dict[str, Any]:
    _require_androguard()
    logging.getLogger("androguard").setLevel(logging.WARNING)
    from androguard.core.apk import APK  # type: ignore
    from androguard.core.dex import DEX  # type: ignore

    a = APK(str(apk_path))
    dex_list: List[Any] = []
    for dex_bytes in a.get_all_dex():
        try:
            dex_list.append(DEX(dex_bytes))
        except Exception:
            continue

    package_name = a.get_package()

    activities = _safe_list(a.get_activities())
    services = _safe_list(a.get_services())
    receivers = _safe_list(a.get_receivers())
    providers = _safe_list(a.get_providers())

    components = {
        "activities": [
            {
                "name": n,
                "intent_filters": _intent_filters(a, "activity", n),
                "exported": _to_bool(_component_attr(a, "activity", n, "exported")),
                "permission": _component_attr(a, "activity", n, "permission"),
            }
            for n in activities
        ],
        "services": [
            {
                "name": n,
                "intent_filters": _intent_filters(a, "service", n),
                "exported": _to_bool(_component_attr(a, "service", n, "exported")),
                "permission": _component_attr(a, "service", n, "permission"),
            }
            for n in services
        ],
        "receivers": [
            {
                "name": n,
                "intent_filters": _intent_filters(a, "receiver", n),
                "exported": _to_bool(_component_attr(a, "receiver", n, "exported")),
                "permission": _component_attr(a, "receiver", n, "permission"),
            }
            for n in receivers
        ],
        "providers": [
            {
                "name": n,
                "intent_filters": _intent_filters(a, "provider", n),
                "exported": _to_bool(_component_attr(a, "provider", n, "exported")),
                "permission": _component_attr(a, "provider", n, "permission"),
            }
            for n in providers
        ],
    }

    strings = _dex_strings(dex_list)
    urls, domains, ips = _extract_urls_domains_ips(strings)

    # In fast mode, avoid expensive analysis; API calls are method refs from DEX only.
    api_calls: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    for d in dex_list:
        try:
            methods = d.get_methods() or []
        except Exception:
            continue
        for m in methods:
            try:
                class_name = m.get_class_name()
                name = m.get_name()
                desc = m.get_descriptor()
                signature = f"{class_name}->{name}{desc}"
                if signature in seen:
                    continue
                seen.add(signature)
                api_calls.append(
                    {
                        "class": class_name,
                        "name": name,
                        "descriptor": desc,
                        "signature": signature,
                        "is_external": False,
                    }
                )
            except Exception:
                continue

    data: Dict[str, Any] = {
        "apk": {
            "path": str(apk_path),
            "size_bytes": apk_path.stat().st_size,
        },
        "metadata": {
            "package_name": package_name,
            "version_name": a.get_androidversion_name(),
            "version_code": a.get_androidversion_code(),
            "min_sdk": a.get_min_sdk_version(),
            "target_sdk": a.get_target_sdk_version(),
            "debuggable": _is_debuggable_apk(a),
        },
        "permissions": {
            "requested": _get_requested_permissions(a),
            "declared": _get_declared_permissions(a),
        },
        "components": components,
        "api_calls": api_calls,
        "strings": strings,
        "certificates": _get_certificates_info(a),
        "native_libs": _get_native_libs(a),
        "file_types": _get_file_type_counts(a),
        "network": {
            "urls": urls,
            "domains": domains,
            "ips": ips,
        },
        "package_roots": _class_package_roots(dex_list, package_name),
    }
    return data


def _write_report(data: Dict[str, Any], out_path: Path) -> None:
    lines: List[str] = []
    meta = data.get("metadata", {})
    lines.append(f"Package: {meta.get('package_name')}")
    lines.append(f"Version: {meta.get('version_name')} ({meta.get('version_code')})")
    lines.append(f"SDK: min={meta.get('min_sdk')} target={meta.get('target_sdk')}")
    lines.append(f"Debuggable: {meta.get('debuggable')}")
    lines.append("")

    perms = data.get("permissions", {})
    lines.append("Requested Permissions:")
    for p in perms.get("requested", []):
        lines.append(f"- {p}")
    lines.append("")

    comps = data.get("components", {})
    for key in ("activities", "services", "receivers", "providers"):
        lines.append(key.capitalize() + ":")
        for c in comps.get(key, []):
            lines.append(f"- {c.get('name')}")
        lines.append("")

    net = data.get("network", {})
    lines.append("URLs:")
    for u in net.get("urls", []):
        lines.append(f"- {u}")
    lines.append("")
    lines.append("Domains:")
    for d in net.get("domains", []):
        lines.append(f"- {d}")
    lines.append("")
    lines.append("IPs:")
    for i in net.get("ips", []):
        lines.append(f"- {i}")
    lines.append("")

    lines.append("Top Package Roots (3rd party):")
    for k, v in (data.get("package_roots") or {}).items():
        lines.append(f"- {k}: {v}")

    certs = data.get("certificates", []) or []
    if certs:
        lines.append("")
        lines.append("Certificates (SHA-256):")
        for c in certs:
            sha = c.get("sha256") or c.get("repr")
            if sha:
                lines.append(f"- {sha}")

    libs = data.get("native_libs", []) or []
    if libs:
        lines.append("")
        lines.append("Native Libraries:")
        for l in libs:
            lines.append(f"- {l}")

    ftypes = data.get("file_types", {}) or {}
    if ftypes:
        lines.append("")
        lines.append("File Types:")
        for k, v in ftypes.items():
            lines.append(f"- {k}: {v}")

    important = data.get("important_only")
    if isinstance(important, dict):
        lines.append("")
        lines.append("Important Features (matched):")
        for key in ("permissions", "api_calls", "intents", "strings", "network"):
            vals = important.get(key) or []
            if not vals:
                continue
            lines.append(f"{key}:")
            for v in vals:
                lines.append(f"- {v}")

    out_path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Analyze an APK and output JSON (and optional text report)."
    )
    parser.add_argument("apk", nargs="?", help="Path to APK file")
    parser.add_argument("output", help="Path to output JSON file")
    parser.add_argument("--report", help="Optional text report path", default=None)
    parser.add_argument(
        "--pick",
        action="store_true",
        help="Open a file picker to choose the APK (requires Tkinter)",
    )
    parser.add_argument(
        "--fast",
        action="store_true",
        help="Fast mode: skip heavy analysis to avoid long runtimes",
    )
    parser.add_argument(
        "--important-features",
        help="CSV file with a 'feature' column (e.g., top_features.csv)",
        default=None,
    )
    parser.add_argument(
        "--important-top",
        type=int,
        default=50,
        help="How many top features to use from the CSV (default: 50)",
    )
    args = parser.parse_args()

    apk_path: Optional[Path] = Path(args.apk) if args.apk else None
    if args.pick or apk_path is None:
        try:
            import tkinter as tk
            from tkinter import filedialog
        except Exception as exc:
            print("ERROR: Tkinter is not available for file picker.", file=sys.stderr)
            raise SystemExit(2) from exc

        root = tk.Tk()
        root.withdraw()
        file_path = filedialog.askopenfilename(
            title="Select APK",
            filetypes=[("APK files", "*.apk"), ("All files", "*.*")],
        )
        root.destroy()
        if not file_path:
            print("ERROR: No APK selected.", file=sys.stderr)
            return 1
        apk_path = Path(file_path)

    if apk_path is None:
        print("ERROR: APK path is required.", file=sys.stderr)
        return 1
    if not apk_path.exists():
        print(f"ERROR: APK not found: {apk_path}", file=sys.stderr)
        return 1

    data = analyze_apk_fast(apk_path) if args.fast else analyze_apk(apk_path)
    if args.important_features:
        important_path = Path(args.important_features)
        if not important_path.exists():
            print(f"ERROR: important features CSV not found: {important_path}", file=sys.stderr)
            return 1
        features: List[str] = []
        with important_path.open(newline="", encoding="utf-8") as f:
            reader = DictReader(f)
            if "feature" in (reader.fieldnames or []):
                for row in reader:
                    feat = (row.get("feature") or "").strip()
                    if feat:
                        features.append(feat)
            else:
                f.seek(0)
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    feat = line.split(",")[0].strip()
                    if feat and feat.lower() != "feature":
                        features.append(feat)
        if args.important_top > 0:
            features = features[: args.important_top]

        perms = set((data.get("permissions", {}) or {}).get("requested", [])) | set(
            (data.get("permissions", {}) or {}).get("declared", [])
        )
        intents: Set[str] = set()
        for comp_list in (data.get("components", {}) or {}).values():
            for comp in comp_list or []:
                if not isinstance(comp, dict):
                    continue
                filt = comp.get("intent_filters") or {}
                for key in ("actions", "categories", "data"):
                    for v in filt.get(key, []) or []:
                        intents.add(v)

        api_simple: Set[str] = set()
        for call in data.get("api_calls", []) or []:
            if not isinstance(call, dict):
                continue
            cls = (call.get("class") or "").strip()
            name = (call.get("name") or "").strip()
            if cls.startswith("L") and cls.endswith(";"):
                cls = cls[1:-1]
            cls = cls.replace("/", ".")
            if cls and name:
                api_simple.add(f"{cls}.{name}")
            sig = (call.get("signature") or "").strip()
            if sig:
                api_simple.add(sig)

        strings = set(data.get("strings", []) or [])
        net = data.get("network", {}) or {}
        net_set = set(net.get("urls", []) or []) | set(net.get("domains", []) or []) | set(
            net.get("ips", []) or []
        )

        all_tokens = perms | intents | api_simple | strings | net_set
        matched: List[str] = [f for f in features if f in all_tokens]
        data["important_only"] = {
            "features": matched,
            "permissions": sorted([p for p in perms if p in features]),
            "api_calls": sorted([a for a in api_simple if a in features]),
            "intents": sorted([i for i in intents if i in features]),
            "strings": sorted([s for s in strings if s in features]),
            "network": sorted([n for n in net_set if n in features]),
        }
    Path(args.output).write_text(
        json.dumps(data, ensure_ascii=True, indent=2), encoding="utf-8"
    )
    if args.report:
        _write_report(data, Path(args.report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
