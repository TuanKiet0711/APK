"""
Map apk_analyzer JSON output → binary feature vector matching
drebin-215-dataset-5560malware-9476-benign.csv columns.

Feature categories in the CSV:
  P  – Android permissions (ALL_CAPS_UNDERSCORE)
  I  – Intent actions    (contains 'intent')
  A  – API calls         (L-prefix / Class.method / bare class/method)
  S  – System strings    (/system/…, shell commands)

Key insight: In fast mode, apk_analyzer extracts DEX *defined* methods, NOT
external calls. BUT androguard's DEX.get_strings() returns the full string pool
which includes every class descriptor referenced anywhere (e.g.,
"Ldalvik/system/DexClassLoader;").  We mine this pool to recover API features.
"""
from __future__ import annotations
import re
from typing import Any, Dict, List, Set, Tuple

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_PERM_RE = re.compile(r'^[A-Z][A-Z0-9_]+$')   # e.g. SEND_SMS
# Matches a DEX class descriptor: Lsome/class/Name;
_DEX_CLASS_RE = re.compile(r'L([\w/$]+);')
# Method name heuristic: camelCase or lowercase identifiers, len >= 3
_METHOD_NAME_RE = re.compile(r'^[a-z][a-zA-Z0-9_]{2,}$')


def _norm_perms(perm_list: List[str]) -> Set[str]:
    """Return a set that contains both the full string and its last segment."""
    out: Set[str] = set()
    for p in perm_list:
        if not p:
            continue
        s = str(p).strip()
        out.add(s)
        for sep in ('.', '/'):
            if sep in s:
                out.add(s.rsplit(sep, 1)[1])
    return out


def _dex_to_dot(cls: str) -> str:
    """Ljava/lang/Class;  →  java.lang.Class"""
    return cls.lstrip('L').rstrip(';').replace('/', '.')


def _build_api_indices(api_calls: List[Dict[str, Any]], raw_strings: List[str]):
    """
    Build class/method lookup sets from:
      1. api_calls  – methods returned by apk_analyzer (defined methods in fast mode;
                      all call-graph methods in full mode)
      2. raw_strings – the DEX string pool, which in both modes contains class
                       descriptors for ALL referenced classes (including externals)

    Returns:
        class_set  : set of dotted class names, simple names, L-notation names
        method_set : set of method names
        pair_set   : set of (some_class_form, method_name) tuples
    """
    class_set:  Set[str] = set()
    method_set: Set[str] = set()
    pair_set:   Set[Tuple[str, str]] = set()

    # ── 1. From api_calls (works well in full mode) ─────────────────────────
    for call in api_calls:
        raw_cls = str(call.get('class', ''))
        method  = str(call.get('name',  ''))
        dot_cls = _dex_to_dot(raw_cls)
        simple  = dot_cls.rsplit('.', 1)[-1] if dot_cls else ''

        class_set.add(raw_cls)
        class_set.add(dot_cls)
        if simple:
            class_set.add(simple)
        if method:
            method_set.add(method)
        for some_cls in (dot_cls, simple, raw_cls):
            if some_cls and method:
                pair_set.add((some_cls, method))

    # ── 2. Mine DEX string pool for class descriptors ───────────────────────
    # DEX stores EVERY referenced class name in the string table as "Lpath/to/Class;"
    # This covers external classes (DexClassLoader, TelephonyManager …) in fast mode.
    # DEX ALSO stores every method name as a string (method_ids reference strings).
    # So we can recover external method names too.
    string_method_set: Set[str] = set()
    for s in raw_strings:
        # Mine class descriptors
        for m in _DEX_CLASS_RE.finditer(s):
            inner   = m.group(1)                    # e.g. dalvik/system/DexClassLoader
            dot_cls = inner.replace('/', '.')        # dalvik.system.DexClassLoader
            simple  = dot_cls.rsplit('.', 1)[-1]     # DexClassLoader
            l_cls   = 'L' + inner + ';'             # Ldalvik/system/DexClassLoader;

            class_set.add(l_cls)
            class_set.add(dot_cls)
            if simple:
                class_set.add(simple)

        # Mine short strings that look like method names (camelCase / lowercase)
        # These are stored in the DEX string pool as method name references.
        s_stripped = s.strip()
        if _METHOD_NAME_RE.match(s_stripped):
            string_method_set.add(s_stripped)

    # Merge string-pool method names into method_set so Class.method lookups work
    method_set |= string_method_set

    return class_set, method_set, pair_set


def _extract_method_pairs_from_sigs(api_calls: List[Dict[str, Any]]) -> Set[Tuple[str, str]]:
    """Extract (class, method) pairs from the 'signature' field (full-mode call graph)."""
    pairs: Set[Tuple[str, str]] = set()
    for call in api_calls:
        sig = str(call.get('signature', ''))
        # Format: Lsome/Class;->methodName(desc)RetType
        arrow = sig.find('->')
        if arrow == -1:
            continue
        cls_part    = sig[:arrow]
        method_part = sig[arrow + 2:]
        paren       = method_part.find('(')
        method_name = method_part[:paren] if paren != -1 else method_part

        dot_cls = _dex_to_dot(cls_part)
        simple  = dot_cls.rsplit('.', 1)[-1]

        for c in (dot_cls, simple, cls_part):
            if c and method_name:
                pairs.add((c, method_name))
    return pairs


def _intent_actions_from_components(components: Dict[str, Any]) -> Set[str]:
    actions: Set[str] = set()
    for comp_type in ('activities', 'services', 'receivers', 'providers'):
        for comp in components.get(comp_type, []):
            filters = comp.get('intent_filters', {}) or {}
            for a in filters.get('actions', []):
                actions.add(str(a))
            for c in filters.get('categories', []):
                actions.add(str(c))
            for d in filters.get('data', []):
                actions.add(str(d))
    return actions


# ---------------------------------------------------------------------------
# Core feature check
# ---------------------------------------------------------------------------

def _check(
    feat: str,
    perms:      Set[str],
    class_set:  Set[str],
    method_set: Set[str],
    pair_set:   Set[Tuple[str, str]],
    intents:    Set[str],
    strings:    Set[str],
) -> int:
    """Return 1 if the feature is detected, 0 otherwise."""

    # ── 1. Permission  (ALL_CAPS_UNDERSCORE, no dots) ────────────────────────
    if _PERM_RE.match(feat):
        return int(feat in perms)

    # ── 2. Intent action / category ─────────────────────────────────────────
    if 'intent' in feat.lower():
        return int(feat in intents or feat in strings)

    # ── 3. System paths (/system/bin, /system/app, chmod, mount …) ──────────
    if feat.startswith('/'):
        return int(any(feat in s for s in strings))

    # System shell commands that appear as string constants
    _SHELL_CMDS = {'chmod', 'chown', 'mount', 'remount', 'su', 'busybox'}
    if feat in _SHELL_CMDS:
        return int(feat in strings or any(feat == s.strip() for s in strings))

    # ── 4. L-prefix API: Ljava.lang.Class.getCanonicalName  ─────────────────
    if feat.startswith('L') and '.' in feat:
        inner    = feat[1:]                         # java.lang.Class.getCanonicalName
        last_dot = inner.rfind('.')
        if last_dot == -1:
            return int(inner in class_set or feat in class_set)
        last_part = inner[last_dot + 1:]
        cls_path  = inner[:last_dot]

        if last_part and last_part[0].islower():
            # method reference
            return int(
                (cls_path, last_part) in pair_set
                or cls_path in class_set
            )
        else:
            # class reference
            simple = last_part
            return int(inner in class_set or simple in class_set or feat in class_set)

    # ── 5. Full dotted class / class-method ─────────────────────────────────
    if feat.startswith(('android.', 'javax.', 'java.')):
        last_dot  = feat.rfind('.')
        last_part = feat[last_dot + 1:]
        cls_path  = feat[:last_dot]

        if last_part and last_part[0].islower():
            return int((cls_path, last_part) in pair_set or cls_path in class_set)
        else:
            simple = last_part
            return int(feat in class_set or simple in class_set)

    # ── 6. Short Class.method: TelephonyManager.getDeviceId, Runtime.exec … ─
    if '.' in feat:
        dot_idx    = feat.index('.')
        cls_short  = feat[:dot_idx]               # TelephonyManager
        method_raw = feat[dot_idx + 1:]           # getDeviceId / init

        if method_raw == 'init':
            methods_to_try = ('<init>', 'init')
        else:
            methods_to_try = (method_raw,)

        for m in methods_to_try:
            if (cls_short, m) in pair_set:
                return 1
        # Looser: class in class_set AND method known OR class substring matches
        if cls_short in class_set:
            for m in methods_to_try:
                if m in method_set:
                    return 1
        # Substring fallback: class_set already has simple names from string pool mining
        for cls in class_set:
            last = cls.rsplit('.', 1)[-1]
            if last == cls_short:
                for m in methods_to_try:
                    if (cls, m) in pair_set or (cls_short, m) in pair_set:
                        return 1
        return 0

    # ── 7. Bare name: DexClassLoader, transact, onBind … ────────────────────
    # class_set now includes simple names mined from DEX string pool
    return int(
        feat in class_set
        or feat in method_set
        or feat in strings
        or feat in perms
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_features(apk_json: Dict[str, Any], feature_cols: List[str]) -> List[int]:
    """
    Convert the JSON produced by apk_analyzer into a binary feature vector
    whose columns match *feature_cols* (the CSV column order, excluding 'class').
    """
    perms_raw = (
        apk_json.get('permissions', {}).get('requested', [])
        + apk_json.get('permissions', {}).get('declared', [])
    )
    perms = _norm_perms(perms_raw)

    api_calls  = apk_json.get('api_calls', [])
    raw_strings: List[str] = apk_json.get('strings', [])

    # Build class/method indices (uses both api_calls AND string pool mining)
    class_set, method_set, pair_set = _build_api_indices(api_calls, raw_strings)

    # Add method pairs from signatures (full-mode call graph)
    pair_set |= _extract_method_pairs_from_sigs(api_calls)

    components = apk_json.get('components', {})
    intents    = _intent_actions_from_components(components)
    for s in raw_strings:
        if 'intent' in s.lower() or s.startswith('android.intent'):
            intents.add(s)

    strings = set(raw_strings)

    vector = [
        _check(feat, perms, class_set, method_set, pair_set, intents, strings)
        for feat in feature_cols
    ]
    return vector

