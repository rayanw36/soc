"""
shared_features.py
==================
Shared feature-extraction utilities for the SOC alert-triage v2 pipeline.
Imported by every phase script so that training, evaluation and the live
watcher all produce byte-identical 26-dim feature vectors.

Public API
----------
build_combined_text(alert) -> str
class AgentHistory
extract_features_v2(alert, agent_hist_features=None) -> list[float]   (len 26)
parse_timestamp(alert) -> datetime | None
assign_label(ts, windows) -> int
assign_phase(ts) -> str
load_lnx_detections(filepath, experiment_start, experiment_end) -> pd.DataFrame
"""

import json
from collections import deque
from datetime import datetime, timezone

import pandas as pd

from shared_constants import (
    KEYWORDS, FEATURE_COLS_V2, NUM_FEATURES_V2,
    MITRE_INJECT, MITRE_TACTIC_MAP, AGENT_CRITICALITY_MAP,
    ATTACK_WINDOWS_LNX,
)

# Wazuh rule groups that denote an authentication failure.
_AUTH_FAIL_GROUPS = {
    "authentication_failed", "authentication_failures", "invalid_login",
    "win_authentication_failed", "adduser", "account_changed",
}
# Tokens that denote a web-application attack.
_WEB_ATTACK_TOKENS = {
    "web", "apache", "nginx", "web_scan", "sql_injection", "xss",
    "attack", "web_attack", "appsec",
}


# ---------------------------------------------------------------------------
# Small dict-walk helpers (tolerant of missing / non-dict nodes)
# ---------------------------------------------------------------------------
def _get(d, *path, default=None):
    cur = d
    for k in path:
        if isinstance(cur, dict) and k in cur:
            cur = cur[k]
        else:
            return default
    return cur


def _as_list(x):
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


# ---------------------------------------------------------------------------
# 1. build_combined_text
# ---------------------------------------------------------------------------
def build_combined_text(alert):
    """Join the human-readable text fields of a Wazuh alert and append
    MITRE-tactic keyword injections.  Returns a lowercase string."""
    parts = [
        _get(alert, "rule", "description", default="") or "",
        alert.get("full_log", "") or "",
        _get(alert, "data", "win", "eventdata", "commandLine", default="") or "",
        _get(alert, "data", "win", "system", "message", default="") or "",
    ]

    # MITRE tactic keyword injection
    for tactic in _as_list(_get(alert, "rule", "mitre", "tactic")):
        inj = MITRE_INJECT.get(str(tactic).lower())
        if inj:
            parts.append(inj)

    return " ".join(str(p) for p in parts).lower()


def _keyword_flags(text):
    """Return list[int] of len(KEYWORDS): 1 if keyword present in text."""
    return [1 if kw in text else 0 for kw in KEYWORDS]


def _is_auth_failure(alert):
    groups = set(g.lower() for g in _as_list(_get(alert, "rule", "groups")))
    return 1 if groups & _AUTH_FAIL_GROUPS else 0


def _is_web_attack(alert):
    groups = set(g.lower() for g in _as_list(_get(alert, "rule", "groups")))
    if groups & _WEB_ATTACK_TOKENS:
        return 1
    desc = (_get(alert, "rule", "description", default="") or "").lower()
    if any(t in desc for t in ("sql injection", "xss", "web attack", "directory traversal")):
        return 1
    return 0


def _mitre_tactic_id(alert):
    """First mapped MITRE tactic id, or -1 when none is present."""
    for tactic in _as_list(_get(alert, "rule", "mitre", "tactic")):
        tid = MITRE_TACTIC_MAP.get(str(tactic).lower())
        if tid is not None:
            return tid
    return -1


def _rule_id_encoded(alert):
    rid = _get(alert, "rule", "id", default=None)
    try:
        return float(int(rid))
    except (TypeError, ValueError):
        return 0.0


def _agent_criticality(alert):
    name = (_get(alert, "agent", "name", default="") or "").lower()
    for key, val in AGENT_CRITICALITY_MAP.items():
        if key in name:
            return float(val)
    return 0.0


def _kill_chain_stage(mitre_tactic_id):
    t = mitre_tactic_id
    if 0 <= t <= 2:
        return 0          # recon / initial access
    if t == 3:
        return 1          # execution
    if 4 <= t <= 6:
        return 2          # persistence / priv-esc / defense evasion
    if t == 7:
        return 3          # credential access
    if 8 <= t <= 9:
        return 2          # discovery / lateral movement
    if 10 <= t <= 12:
        return 4          # collection / c2 / exfil  (exfil/impact emphasis)
    return 2              # default


def _src_ip(alert):
    return _get(alert, "data", "srcip", default=None)


# ---------------------------------------------------------------------------
# 2. AgentHistory
# ---------------------------------------------------------------------------
class AgentHistory:
    """Per-agent rolling buffer of the last 20 alerts used to derive the
    temporal / behavioural features (columns 18-25 of FEATURE_COLS_V2)."""

    def __init__(self, maxlen=20):
        self.buf = deque(maxlen=maxlen)

    def add(self, alert, timestamp):
        """Store a compact record for *alert* observed at *timestamp*."""
        text = build_combined_text(alert)
        kw = dict(zip(KEYWORDS, _keyword_flags(text)))
        level = _get(alert, "rule", "level", default=0)
        try:
            level = float(level)
        except (TypeError, ValueError):
            level = 0.0
        self.buf.append({
            "ts": timestamp,
            "level": level,
            "rule_id": _get(alert, "rule", "id", default=None),
            "srcip": _src_ip(alert),
            "is_auth_failure": _is_auth_failure(alert),
            "kw_scan": kw["scan"],
            "kw_brute": kw["brute"],
        })

    def compute_features(self, current_ts):
        """Compute the 8 history features as of *current_ts* (datetime)."""
        feats = {
            "alert_rate_1min": 0,
            "failed_login_5min": 0,
            "unique_src_ip_10min": 0,
            "high_sev_ratio_20": 0.0,
            "rule_diversity_10min": 0,
            "time_since_last_high": 999.0,
            "scan_preceded": 0,
            "brute_preceded": 0,
        }
        if current_ts is None or not self.buf:
            return feats

        srcips_10m = set()
        rule_ids_10m = set()
        high_count = 0
        last_high_dt = None

        for rec in self.buf:
            rts = rec["ts"]
            dt = None
            if rts is not None:
                dt = (current_ts - rts).total_seconds()

            if rec["level"] >= 8:
                high_count += 1

            if dt is None or dt < 0:
                continue

            if dt <= 60:
                feats["alert_rate_1min"] += 1
            if dt <= 300 and rec["is_auth_failure"]:
                feats["failed_login_5min"] += 1
            if dt <= 600:
                if rec["srcip"]:
                    srcips_10m.add(rec["srcip"])
                if rec["rule_id"] is not None:
                    rule_ids_10m.add(rec["rule_id"])
                if rec["kw_scan"]:
                    feats["scan_preceded"] = 1
                if rec["kw_brute"]:
                    feats["brute_preceded"] = 1
            if rec["level"] >= 10:
                if last_high_dt is None or dt < last_high_dt:
                    last_high_dt = dt

        n = len(self.buf)
        feats["unique_src_ip_10min"] = len(srcips_10m)
        feats["rule_diversity_10min"] = len(rule_ids_10m)
        feats["high_sev_ratio_20"] = high_count / n if n else 0.0
        if last_high_dt is not None:
            feats["time_since_last_high"] = float(last_high_dt)
        return feats


# ---------------------------------------------------------------------------
# 3. extract_features_v2
# ---------------------------------------------------------------------------
def extract_features_v2(alert, agent_hist_features=None):
    """Return a list of 26 floats matching FEATURE_COLS_V2."""
    text = build_combined_text(alert)

    desc = _get(alert, "rule", "description", default="") or ""
    desc_len = float(len(desc))

    level = _get(alert, "rule", "level", default=0)
    try:
        rule_level = float(level)
    except (TypeError, ValueError):
        rule_level = 0.0

    kw = _keyword_flags(text)                       # 10 ints

    mitre_id = _mitre_tactic_id(alert)
    is_auth = _is_auth_failure(alert)
    is_web = _is_web_attack(alert)
    rid = _rule_id_encoded(alert)
    crit = _agent_criticality(alert)

    h = agent_hist_features or {}
    alert_rate_1min      = float(h.get("alert_rate_1min", 0))
    failed_login_5min    = float(h.get("failed_login_5min", 0))
    unique_src_ip_10min  = float(h.get("unique_src_ip_10min", 0))
    high_sev_ratio_20    = float(h.get("high_sev_ratio_20", 0.0))
    rule_diversity_10min = float(h.get("rule_diversity_10min", 0))
    time_since_last_high = float(h.get("time_since_last_high", 999))
    scan_preceded        = float(h.get("scan_preceded", 0))
    brute_preceded       = float(h.get("brute_preceded", 0))

    kill_chain = float(_kill_chain_stage(mitre_id))

    feats = [
        desc_len, rule_level,
        *[float(x) for x in kw],                    # cols 3-12
        float(mitre_id),                            # 13
        float(is_auth),                             # 14
        float(is_web),                              # 15
        rid,                                        # 16
        crit,                                       # 17
        alert_rate_1min,                            # 18
        failed_login_5min,                          # 19
        unique_src_ip_10min,                        # 20
        high_sev_ratio_20,                          # 21
        rule_diversity_10min,                       # 22
        time_since_last_high,                       # 23
        scan_preceded,                              # 24
        brute_preceded,                             # 25
        kill_chain,                                 # 26
    ]
    assert len(feats) == NUM_FEATURES_V2, f"expected {NUM_FEATURES_V2}, got {len(feats)}"
    return feats


# ---------------------------------------------------------------------------
# 4. parse_timestamp
# ---------------------------------------------------------------------------
def parse_timestamp(alert_or_str):
    """Parse a timestamp from an alert dict (tries 'timestamp' then
    '@timestamp') or from a raw string. Returns a tz-aware UTC datetime or
    None."""
    if isinstance(alert_or_str, str):
        candidates = [alert_or_str]
    elif isinstance(alert_or_str, dict):
        candidates = [alert_or_str.get("timestamp"), alert_or_str.get("@timestamp")]
    else:
        return None

    for raw in candidates:
        if not raw:
            continue
        dt = _parse_iso(raw)
        if dt is not None:
            return dt
    return None


def _parse_iso(raw):
    s = str(raw).strip()
    if not s:
        return None
    # Normalise trailing Z and +0000 style offsets for fromisoformat
    norm = s.replace("Z", "+00:00")
    # turn +0000 / -0300 into +00:00 / -03:00
    if len(norm) >= 5 and norm[-5] in "+-" and norm[-3] != ":":
        norm = norm[:-2] + ":" + norm[-2:]
    try:
        dt = datetime.fromisoformat(norm)
    except ValueError:
        for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S",
                    "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
            try:
                dt = datetime.strptime(s, fmt)
                break
            except ValueError:
                dt = None
        if dt is None:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


# ---------------------------------------------------------------------------
# 5. assign_label
# ---------------------------------------------------------------------------
def assign_label(ts, windows):
    """1 if *ts* falls inside any window. Each window is either
    (start_iso, end_iso) or (technique, phase, start_iso, end_iso)."""
    if ts is None:
        return 0
    for w in windows:
        if len(w) == 2:
            start, end = w
        elif len(w) >= 4:
            start, end = w[2], w[3]
        else:
            continue
        s, e = _parse_iso(start), _parse_iso(end)
        if s is not None and e is not None and s <= ts <= e:
            return 1
    return 0


# ---------------------------------------------------------------------------
# 6. assign_phase
# ---------------------------------------------------------------------------
def assign_phase(ts):
    """Return 'AIT-ADS', 'NOVEL' or 'benign' using ATTACK_WINDOWS_LNX."""
    if ts is None:
        return "benign"
    for tech, phase, start, end in ATTACK_WINDOWS_LNX:
        s, e = _parse_iso(start), _parse_iso(end)
        if s is not None and e is not None and s <= ts <= e:
            return phase
    return "benign"


def assign_technique(ts):
    """Return the matching technique id from ATTACK_WINDOWS_LNX, else ''."""
    if ts is None:
        return ""
    for tech, phase, start, end in ATTACK_WINDOWS_LNX:
        s, e = _parse_iso(start), _parse_iso(end)
        if s is not None and e is not None and s <= ts <= e:
            return tech
    return ""


# ---------------------------------------------------------------------------
# 7. load_lnx_detections
# ---------------------------------------------------------------------------
def load_lnx_detections(filepath, experiment_start, experiment_end):
    """Load the lnx-dmz watcher detections (JSON-lines), filter to the
    experiment window, label / phase each record and re-extract the 26
    features from original_alert using per-agent history.

    Returns a DataFrame with columns:
        timestamp, ai_score, label, phase, technique, + FEATURE_COLS_V2
    """
    start_dt = _parse_iso(experiment_start)
    end_dt = _parse_iso(experiment_end)

    rows = []
    with open(filepath, "r", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            oa = rec.get("original_alert", rec)
            # canonical timestamp: outer detection ts, fallback to alert ts
            ts = parse_timestamp(rec.get("timestamp")) or parse_timestamp(oa)
            if ts is None:
                continue
            if start_dt and end_dt and not (start_dt <= ts <= end_dt):
                continue
            rows.append((ts, float(rec.get("score", 0.0) or 0.0), oa,
                         _get(oa, "agent", "name", default="unknown")))

    rows.sort(key=lambda r: r[0])

    histories = {}
    out = []
    for ts, score, oa, agent in rows:
        hist = histories.setdefault(agent, AgentHistory())
        hfeat = hist.compute_features(ts)
        feats = extract_features_v2(oa, hfeat)
        hist.add(oa, ts)

        out.append({
            "timestamp": ts,
            "ai_score": score,
            "label": assign_label(ts, ATTACK_WINDOWS_LNX),
            "phase": assign_phase(ts),
            "technique": assign_technique(ts),
            **dict(zip(FEATURE_COLS_V2, feats)),
        })

    return pd.DataFrame(out)
