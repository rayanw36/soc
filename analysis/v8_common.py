"""
v8_common.py -- shared extraction helpers for the Windows recalibration (v8).
All feature extraction is the 22-feature normalized representation
(normalize_schema.extract_normalized), process_depth=0, per-agent AgentHistory
built fresh for each session (never mixed across sessions).
"""
import json
from datetime import datetime, timedelta, timezone

import numpy as np
import pandas as pd

from shared_constants import ATTACK_WINDOWS_LNX, WINDOWS_ATTACK_WINDOWS
from shared_constants_v2 import ATTACK_WINDOWS_LNX_V2
from shared_features import AgentHistory, _parse_iso
from normalize_schema import extract_normalized, FEATURE_COLS_NORM

MARGIN = timedelta(minutes=60)


def _parse_dt(ts_str):
    if not ts_str:
        return None
    ts_str = str(ts_str).strip()
    for fmt in ["%Y-%m-%dT%H:%M:%S.%f+0000", "%Y-%m-%dT%H:%M:%S.%f+00:00",
                "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ",
                "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%dT%H:%M:%S.%f%z"]:
        try:
            dt = datetime.strptime(ts_str, fmt)
            return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt
        except ValueError:
            pass
    return None


def _win_systime(alert):
    try:
        st = alert["data"]["win"]["system"]["systemTime"]
        return pd.Timestamp(st).to_pydatetime().astimezone(timezone.utc)
    except Exception:
        return _parse_dt(alert.get("timestamp"))


# ---------------------------------------------------------------------------
# Source 1 (old, cross-session): testAlerts Windows benign pool, high-confidence
# (>=60min outside WINDOWS_ATTACK_WINDOWS), used to reproduce the 70/30 split
# task3_xplatform_benign.py already established (train=7928 / holdout=3398).
# ---------------------------------------------------------------------------
def extract_win_oldpool_benign():
    WIN_WINS = [(datetime.fromisoformat(s.replace("Z", "+00:00")),
                 datetime.fromisoformat(e.replace("Z", "+00:00")))
                for s, e in WINDOWS_ATTACK_WINDOWS]

    raw = []
    for fname in ["ossec-alerts-23.json", "ossec-alerts-24.json"]:
        with open(f"testAlerts/Alerts/{fname}", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                ts = _parse_dt(str(rec.get("timestamp", "") or ""))
                if ts is None:
                    continue
                raw.append((ts, rec))
    raw.sort(key=lambda r: r[0])

    hist = {}
    feats, kept_ts = [], []
    for ts, rec in raw:
        agent = (rec.get("agent", {}).get("name", "")
                 or rec.get("data", {}).get("win", {}).get("system", {}).get("computer", "")
                 or "unknown")
        h = hist.setdefault(agent, AgentHistory())
        hfeat = h.compute_features(ts)
        f = extract_normalized(rec, hfeat, process_depth=0)
        h.add(rec, ts)
        is_benign = all(ts < (s - MARGIN) or ts > (e + MARGIN) for s, e in WIN_WINS)
        if is_benign:
            feats.append(f)
            kept_ts.append(ts)

    X = np.array(feats, dtype=np.float64)
    return X, kept_ts


def split_win_oldpool(X, seed=42, train_frac=0.70):
    """Reproduce task3_xplatform_benign.py's exact 70/30 split (same seed,
    same permutation call) so the calibration holdout (3,398 rows) is
    identical to the one v7 never trained on."""
    rng = np.random.default_rng(seed)
    n = len(X)
    idx = rng.permutation(n)
    n_train = int(train_frac * n)
    return X[idx[:n_train]], X[idx[n_train:]]


# ---------------------------------------------------------------------------
# Source 2 (old, cross-session): lnx_dmz_ai_detections.json, high-confidence
# Linux benign (>=60min outside the 14 ATTACK_WINDOWS_LNX_V2 windows).
# ---------------------------------------------------------------------------
def extract_lnx_oldpool_benign():
    LNX_WINS = []
    for row in ATTACK_WINDOWS_LNX_V2:
        s, e = _parse_iso(row[2]), _parse_iso(row[3])
        if s and e:
            LNX_WINS.append((s, e))

    raw = []
    with open("lnx_dmz_ai_detections.json", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            ts = _parse_iso(str(rec.get("timestamp", "") or ""))
            if ts is None:
                continue
            raw.append((ts, rec))
    raw.sort(key=lambda r: r[0])

    hist = {}
    feats = []
    for ts, rec in raw:
        oa = rec.get("original_alert", rec)
        agent = str(oa.get("agent", {}).get("name", "unknown") or "unknown")
        h = hist.setdefault(agent, AgentHistory())
        hfeat = h.compute_features(ts)
        f = extract_normalized(oa, hfeat, process_depth=0)
        h.add(oa, ts)
        is_benign = all(ts < (s - MARGIN) or ts > (e + MARGIN) for s, e in LNX_WINS)
        if is_benign:
            feats.append(f)

    return np.array(feats, dtype=np.float64)


# ---------------------------------------------------------------------------
# Source 3 (fresh, matched, guarded): collection_benign_{lnx,win}_alerts.json
# ALL benign by construction (dedicated single-session collection).
# ---------------------------------------------------------------------------
def extract_fresh_benign(path, platform):
    raw = []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            a = json.loads(line)
            ts = _win_systime(a) if platform == "windows" else _parse_iso(a.get("timestamp"))
            raw.append((ts, a))
    raw.sort(key=lambda r: (r[0] is None, r[0]))

    hist = {}
    feats = []
    for ts, a in raw:
        agent = a.get("agent", {}).get("name", "unknown")
        h = hist.setdefault(agent, AgentHistory())
        hfeat = h.compute_features(ts)
        f = extract_normalized(a, hfeat, process_depth=0)
        h.add(a, ts)
        feats.append(f)
    return np.array(feats, dtype=np.float64)
