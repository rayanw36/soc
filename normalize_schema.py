"""
normalize_schema.py
===================
ECS/OCSF normalization layer for cross-platform SOC alert triage (v7).

Replaces the platform-bound `rule_id_encoded` and raw `kw_*` keyword flags with
semantic ECS field categories and four new text-derived features that target the
SUID-detection gap identified in Phase 1.

Normalized feature set  (NUM_FEATURES_NORM = 22):
───────────────────────────────────────────────────────────────────
  From v6 (kept, platform-independent):
    severity_norm          rule_level / 15.0
    mitre_tactic_id        same as v6
    is_auth_failure        same as v6
    is_web_attack          same as v6
    agent_criticality      same as v6
    alert_rate_1min        behavioral aggregate
    failed_login_5min      behavioral aggregate
    unique_src_ip_10min    behavioral aggregate
    high_sev_ratio_20      behavioral aggregate
    rule_diversity_10min   behavioral aggregate
    time_since_last_high   behavioral aggregate
    scan_preceded          behavioral aggregate
    brute_preceded         behavioral aggregate
    kill_chain_stage       behavioral aggregate

  New ECS/OCSF semantic (integers):
    event_category    0=authentication 1=process 2=file 3=network 4=iam 5=configuration
    event_type        0=start 1=end 2=access 3=creation 4=deletion 5=info
    event_outcome     0=success 1=failure 2=denied 3=unknown
    actor_type        0=user 1=service 2=system 3=root

  New text-derived (targeting SUID and sensitive-path detection gap):
    touches_sensitive_path  1 if /etc/shadow /etc/passwd SAM NTDS in alert text
    is_suid_check           1 if suid setuid find -perm in alert text
    cmdline_priv_tokens     count of priv-escalation tokens in alert text (0-capped at 5)
    process_depth           0 until Phase 2 process trees exist

Dropped vs v6:
    rule_id_encoded         platform-specific; leaks OS rule taxonomy into cross-OS model
    kw_scan … kw_virus      raw keyword flags replaced by event_category/type/outcome
    desc_len                redundant with event_category; noisy across platforms
───────────────────────────────────────────────────────────────────

Public API:
    extract_normalized(alert, hfeat, process_depth=0) -> list[float]  (22 values)
    v6_to_normalized(X_v6, feat_cols_v6)               -> np.ndarray  (N × 22)
    coverage_report(alerts_iter)                        -> dict
"""

from __future__ import annotations

import re
from typing import Any

import numpy as np

# ---------------------------------------------------------------------------
# Feature columns and constants
# ---------------------------------------------------------------------------

FEATURE_COLS_NORM: list[str] = [
    # v6 carry-overs
    "severity_norm",
    "mitre_tactic_id",
    "is_auth_failure",
    "is_web_attack",
    "agent_criticality",
    "alert_rate_1min",
    "failed_login_5min",
    "unique_src_ip_10min",
    "high_sev_ratio_20",
    "rule_diversity_10min",
    "time_since_last_high",
    "scan_preceded",
    "brute_preceded",
    "kill_chain_stage",
    # ECS/OCSF semantic
    "event_category",
    "event_type",
    "event_outcome",
    "actor_type",
    # Text-derived (SUID gap)
    "touches_sensitive_path",
    "is_suid_check",
    "cmdline_priv_tokens",
    "process_depth",
]

NUM_FEATURES_NORM: int = len(FEATURE_COLS_NORM)  # 22

# ECS event_category values
EC_AUTHENTICATION  = 0
EC_PROCESS         = 1
EC_FILE            = 2
EC_NETWORK         = 3
EC_IAM             = 4
EC_CONFIGURATION   = 5

# ECS event_type values
ET_START     = 0
ET_END       = 1
ET_ACCESS    = 2
ET_CREATION  = 3
ET_DELETION  = 4
ET_INFO      = 5

# ECS event_outcome values
EO_SUCCESS = 0
EO_FAILURE = 1
EO_DENIED  = 2
EO_UNKNOWN = 3

# OCSF actor_type values
AT_USER    = 0
AT_SERVICE = 1
AT_SYSTEM  = 2
AT_ROOT    = 3

# ---------------------------------------------------------------------------
# Rule-group → category mappings (Wazuh rule.groups, works on Linux + Windows)
# ---------------------------------------------------------------------------

# Each entry: (frozenset of substrings ANY of which triggers) → (category, type, outcome, actor)
# Evaluated in priority order; first match wins.
_GROUP_RULES: list[tuple[frozenset, tuple[int, int, int, int]]] = [
    # IAM — highest priority (sudo/privilege/useradd before auth)
    (frozenset({"sudo", "privilege_escalation", "adduser"}),
     (EC_IAM, ET_ACCESS, EO_UNKNOWN, AT_ROOT)),
    # Authentication
    (frozenset({"authentication_failed", "authentication_failures", "invalid_login"}),
     (EC_AUTHENTICATION, ET_ACCESS, EO_FAILURE, AT_USER)),
    (frozenset({"authentication_success"}),
     (EC_AUTHENTICATION, ET_ACCESS, EO_SUCCESS, AT_USER)),
    (frozenset({"sshd", "pam"}),
     (EC_AUTHENTICATION, ET_ACCESS, EO_UNKNOWN, AT_USER)),
    # Process (Sysmon EID 1, PowerShell, audit execve)
    (frozenset({"sysmon_eid1", "sysmon_process", "powershell", "execve"}),
     (EC_PROCESS, ET_START, EO_UNKNOWN, AT_USER)),
    # File (Sysmon EID 11, syscheck)
    (frozenset({"sysmon_eid11", "syscheck", "syscheck_entry_added", "syscheck_entry_modified"}),
     (EC_FILE, ET_CREATION, EO_UNKNOWN, AT_USER)),
    # Network (web, Sysmon EID 3)
    (frozenset({"web", "web_scan", "accesslog", "sysmon_eid3"}),
     (EC_NETWORK, ET_ACCESS, EO_UNKNOWN, AT_USER)),
    # IAM (Windows security logon)
    (frozenset({"windows_security"}),
     (EC_AUTHENTICATION, ET_ACCESS, EO_UNKNOWN, AT_USER)),
    # Configuration (cron, dpkg, service)
    (frozenset({"cron", "dpkg", "config_changed", "systemd", "service", "sca"}),
     (EC_CONFIGURATION, ET_INFO, EO_UNKNOWN, AT_SYSTEM)),
    # Process fallback for Sysmon catch-all
    (frozenset({"sysmon", "sysmon_eid1_detections"}),
     (EC_PROCESS, ET_START, EO_UNKNOWN, AT_USER)),
]

# Per-rule overrides — highest specificity wins before group matching
_RULE_OVERRIDES: dict[str, tuple[int, int, int, int]] = {
    # sudo
    "5401": (EC_IAM, ET_ACCESS, EO_FAILURE, AT_ROOT),   # Failed sudo
    "5402": (EC_IAM, ET_ACCESS, EO_SUCCESS, AT_ROOT),   # Sudo to ROOT success
    "5503": (EC_IAM, ET_ACCESS, EO_DENIED,  AT_USER),   # PAM auth failed
    "5501": (EC_AUTHENTICATION, ET_START, EO_SUCCESS, AT_USER),  # PAM session open
    "5502": (EC_AUTHENTICATION, ET_END,   EO_SUCCESS, AT_USER),  # PAM session close
    "5710": (EC_AUTHENTICATION, ET_ACCESS, EO_FAILURE, AT_USER), # SSH non-existent user
    "5712": (EC_AUTHENTICATION, ET_ACCESS, EO_FAILURE, AT_USER), # SSH brute force
    "5758": (EC_AUTHENTICATION, ET_ACCESS, EO_DENIED,  AT_USER), # Max auth exceeded
    "5901": (EC_IAM, ET_CREATION, EO_SUCCESS, AT_SYSTEM),  # New group added
    "5902": (EC_IAM, ET_CREATION, EO_SUCCESS, AT_SYSTEM),  # New user added
    "2832": (EC_CONFIGURATION, ET_CREATION, EO_SUCCESS, AT_USER),  # Crontab changed
    "2833": (EC_CONFIGURATION, ET_CREATION, EO_SUCCESS, AT_ROOT),  # Root crontab changed
    "2901": (EC_CONFIGURATION, ET_INFO,     EO_SUCCESS, AT_SYSTEM), # dpkg install request
    "2902": (EC_CONFIGURATION, ET_CREATION, EO_SUCCESS, AT_SYSTEM), # dpkg installed
    "2904": (EC_CONFIGURATION, ET_INFO,     EO_UNKNOWN, AT_SYSTEM), # dpkg half-configured
    "31101": (EC_NETWORK, ET_ACCESS, EO_FAILURE, AT_USER),  # Web 400 error
    "31151": (EC_NETWORK, ET_ACCESS, EO_FAILURE, AT_USER),  # Web scan
    "31104": (EC_NETWORK, ET_ACCESS, EO_FAILURE, AT_USER),  # Common web attack
    "31516": (EC_NETWORK, ET_ACCESS, EO_FAILURE, AT_USER),  # Suspicious URL
    "52002": (EC_FILE,    ET_ACCESS, EO_DENIED,  AT_SYSTEM), # AppArmor DENIED
    "550":   (EC_FILE, ET_ACCESS, EO_UNKNOWN, AT_SYSTEM),   # Integrity checksum changed
    "554":   (EC_FILE, ET_CREATION, EO_UNKNOWN, AT_USER),   # File added
    "60106": (EC_AUTHENTICATION, ET_START, EO_SUCCESS, AT_USER),  # Windows logon success
    "60118": (EC_AUTHENTICATION, ET_START, EO_SUCCESS, AT_USER),  # Workstation logon
    "60122": (EC_AUTHENTICATION, ET_ACCESS, EO_FAILURE, AT_USER), # Logon failure
    "63104": (EC_FILE, ET_DELETION, EO_SUCCESS, AT_USER),    # Log file cleared
    "92024": (EC_IAM, ET_ACCESS,   EO_SUCCESS, AT_ROOT),    # SAM hive copy → credential access (IAM)
    "92026": (EC_IAM, ET_ACCESS,   EO_SUCCESS, AT_ROOT),    # Dump SAM hive → credential access (IAM)
}

# ---------------------------------------------------------------------------
# Text-derived feature helpers
# ---------------------------------------------------------------------------

_SENSITIVE_PATH_RE = re.compile(
    r"/etc/shadow|/etc/passwd|/etc/sudoers|\bSAM\b|NTDS\.dit|ntds\.dit"
    r"|/etc/cron|/var/spool/cron",
    re.IGNORECASE,
)
_SUID_RE = re.compile(
    r"\bsuid\b|setuid|find\s+-perm\s+-[0-9]*[246][0-9]*|chmod\s+[us]\+s"
    r"|\bsuid_check\b",
    re.IGNORECASE,
)
_PRIV_TOKENS = re.compile(
    r"\bsudo\b|\bsu\b|\broot\b|\bprivilege\b|\bprivesc\b|\belevat",
    re.IGNORECASE,
)


def _get_text(alert: dict) -> str:
    """Concatenate rule description + full_log for text-feature extraction."""
    desc     = str(alert.get("rule", {}).get("description", "") or "")
    full_log = str(alert.get("full_log", "") or "")
    # Windows: also check commandLine from Sysmon eventdata
    ev_data  = alert.get("data", {}).get("win", {}).get("eventdata", {})
    cmd_line = str(ev_data.get("commandLine", "") or "")
    return " ".join([desc, full_log, cmd_line])


def _classify_rule(rule_id: str, groups: list[str]) -> tuple[int, int, int, int]:
    """Map rule_id and groups to (event_category, event_type, event_outcome, actor_type)."""
    # Per-rule override (most specific)
    if rule_id in _RULE_OVERRIDES:
        return _RULE_OVERRIDES[rule_id]

    # Group-based matching
    groups_lower = {g.lower() for g in groups}
    for triggers, values in _GROUP_RULES:
        if any(t in g for t in triggers for g in groups_lower):
            return values

    # Default: configuration / info / unknown / system
    return (EC_CONFIGURATION, ET_INFO, EO_UNKNOWN, AT_SYSTEM)


# ---------------------------------------------------------------------------
# Main per-alert normalized feature extractor
# ---------------------------------------------------------------------------

def extract_normalized(
    alert: dict,
    hfeat: dict,
    process_depth: int = 0,
) -> list[float]:
    """
    Extract FEATURE_COLS_NORM features from a raw Wazuh alert dict.

    Parameters
    ----------
    alert         : raw Wazuh alert dict (with keys 'rule', 'data', 'full_log', etc.)
    hfeat         : AgentHistory.compute_features() output dict (behavioral aggregates)
    process_depth : depth in the process tree (0 until Phase-2 trees populated)

    Returns
    -------
    list of NUM_FEATURES_NORM (22) floats
    """
    rule       = alert.get("rule", {})
    rule_id    = str(rule.get("id", "") or "")
    rule_level = float(rule.get("level", 0) or 0)
    groups     = rule.get("groups", []) or []

    # Mitre tactic
    mitre         = rule.get("mitre", {}) or {}
    mitre_tactics = mitre.get("tactic", []) or []
    from shared_constants import MITRE_TACTIC_MAP
    mitre_tactic_id = -1.0
    for tac in mitre_tactics:
        mapped = MITRE_TACTIC_MAP.get(tac.lower(), -1)
        if mapped >= 0:
            mitre_tactic_id = float(mapped)
            break

    # is_auth_failure and is_web_attack (from v6, same logic)
    groups_lower = {g.lower() for g in groups}
    is_auth_failure = float(
        "authentication_failed" in groups_lower
        or "authentication_failures" in groups_lower
        or "invalid_login" in groups_lower
        or rule_level >= 6 and any(g in groups_lower for g in ["sshd", "pam"])
    )
    is_web_attack = float("web" in groups_lower or "web_scan" in groups_lower)

    # agent_criticality
    from shared_constants import AGENT_CRITICALITY_MAP
    agent_name = str(
        alert.get("agent", {}).get("name", "")
        or alert.get("data", {}).get("win", {}).get("system", {}).get("computer", "")
        or ""
    ).lower()
    agent_criticality = max(
        (v for k, v in AGENT_CRITICALITY_MAP.items() if k in agent_name),
        default=1,
    )

    # Behavioral aggregates (supplied by AgentHistory.compute_features())
    alert_rate_1min      = float(hfeat.get("alert_rate_1min", 0) or 0)
    failed_login_5min    = float(hfeat.get("failed_login_5min", 0) or 0)
    unique_src_ip_10min  = float(hfeat.get("unique_src_ip_10min", 0) or 0)
    high_sev_ratio_20    = float(hfeat.get("high_sev_ratio_20", 0) or 0)
    rule_diversity_10min = float(hfeat.get("rule_diversity_10min", 0) or 0)
    time_since_last_high = float(hfeat.get("time_since_last_high", 999) or 999)
    scan_preceded        = float(hfeat.get("scan_preceded", 0) or 0)
    brute_preceded       = float(hfeat.get("brute_preceded", 0) or 0)
    kill_chain_stage     = float(hfeat.get("kill_chain_stage", 0) or 0)

    # ECS semantic features
    ev_cat, ev_type, ev_out, actor = _classify_rule(rule_id, groups)

    # Text-derived features
    text = _get_text(alert)
    touches_sensitive = float(bool(_SENSITIVE_PATH_RE.search(text)))
    is_suid           = float(bool(_SUID_RE.search(text)))
    priv_tokens       = float(min(len(_PRIV_TOKENS.findall(text)), 5))

    return [
        rule_level / 15.0,          # severity_norm
        mitre_tactic_id,
        is_auth_failure,
        is_web_attack,
        float(agent_criticality),
        alert_rate_1min,
        failed_login_5min,
        unique_src_ip_10min,
        high_sev_ratio_20,
        rule_diversity_10min,
        time_since_last_high,
        scan_preceded,
        brute_preceded,
        kill_chain_stage,
        float(ev_cat),
        float(ev_type),
        float(ev_out),
        float(actor),
        touches_sensitive,
        is_suid,
        priv_tokens,
        float(process_depth),
    ]


# ---------------------------------------------------------------------------
# Vectorised v6-to-normalized mapper  (works on ait_split.npz without re-streaming)
# ---------------------------------------------------------------------------

def v6_to_normalized(X_v6: np.ndarray, feat_cols_v6: list[str]) -> np.ndarray:
    """
    Map a v6 feature matrix (N × 26) to the normalized feature matrix (N × 22).

    Uses heuristic rules on the kw_* and rule_id_encoded columns to approximate
    the ECS semantic features. Text-derived features (touches_sensitive_path,
    is_suid_check, cmdline_priv_tokens) are 0 for AIT-ADS data because the
    raw alert text is not available in ait_split.npz.

    This is explicitly documented as an approximation — the raw AIT-ADS text was
    not retained in the split file, so the four new text features add signal only
    from the live Linux and Windows evaluation runs.
    """
    idx = {c: i for i, c in enumerate(feat_cols_v6)}
    n   = len(X_v6)

    def col(name: str) -> np.ndarray:
        return X_v6[:, idx[name]] if name in idx else np.zeros(n)

    rule_level       = col("rule_level")
    mitre_tactic_id  = col("mitre_tactic_id")
    is_auth_failure  = col("is_auth_failure")
    is_web_attack    = col("is_web_attack")
    agent_criticality= col("agent_criticality")
    kw_root          = col("kw_root")
    kw_priv          = col("kw_privilege")
    kw_shell         = col("kw_shell")
    kw_brute         = col("kw_brute")
    kw_denied        = col("kw_denied")
    rule_id_enc      = col("rule_id_encoded")

    # event_category: web→network; auth→authentication; root/priv→iam; shell→process; else→config
    event_cat = np.full(n, float(EC_CONFIGURATION))
    event_cat[kw_shell > 0]                       = float(EC_PROCESS)
    event_cat[(kw_root > 0) | (kw_priv > 0)]     = float(EC_IAM)
    event_cat[is_auth_failure > 0]                 = float(EC_AUTHENTICATION)
    event_cat[is_web_attack > 0]                   = float(EC_NETWORK)

    # event_type: auth→access; shell→start; brute→access; else→info
    event_type = np.full(n, float(ET_INFO))
    event_type[is_auth_failure > 0] = float(ET_ACCESS)
    event_type[kw_brute > 0]        = float(ET_ACCESS)
    event_type[kw_shell > 0]        = float(ET_START)

    # event_outcome: denied→denied; auth_fail→failure; else→unknown
    event_out = np.full(n, float(EO_UNKNOWN))
    event_out[kw_denied > 0]        = float(EO_DENIED)
    event_out[is_auth_failure > 0]  = float(EO_FAILURE)

    # actor_type: root/priv→root; else→user
    actor = np.full(n, float(AT_USER))
    actor[(kw_root > 0) | (kw_priv > 0)] = float(AT_ROOT)

    # Text-derived: proxy using kw_root as partial signal for cmdline_priv_tokens;
    # touches_sensitive and is_suid are 0 (no text available)
    touches_sensitive = np.zeros(n)
    is_suid           = np.zeros(n)
    cmdline_priv      = np.clip(kw_root + kw_priv, 0, 5)   # coarse proxy
    process_depth     = np.zeros(n)

    X_norm = np.column_stack([
        rule_level / 15.0,
        mitre_tactic_id,
        is_auth_failure,
        is_web_attack,
        agent_criticality,
        col("alert_rate_1min"),
        col("failed_login_5min"),
        col("unique_src_ip_10min"),
        col("high_sev_ratio_20"),
        col("rule_diversity_10min"),
        col("time_since_last_high"),
        col("scan_preceded"),
        col("brute_preceded"),
        col("kill_chain_stage"),
        event_cat,
        event_type,
        event_out,
        actor,
        touches_sensitive,
        is_suid,
        cmdline_priv,
        process_depth,
    ])
    return X_norm.astype(np.float64)


# ---------------------------------------------------------------------------
# Coverage report — what fraction of alerts map "cleanly" vs fall to defaults
# ---------------------------------------------------------------------------

def coverage_report(alerts_iter, platform: str = "unknown") -> dict:
    """
    Compute mapping coverage over an iterable of raw Wazuh alert dicts.

    "Clean" = rule_id has an explicit _RULE_OVERRIDES entry OR at least one
    group matches a _GROUP_RULES trigger (not the final default).
    "Other"  = fell through to the default (EC_CONFIGURATION / ET_INFO / ...).

    Returns dict with: platform, total, clean, other, clean_pct, top_unmapped_rules
    """
    from collections import Counter
    total = clean = 0
    unmapped_rules: Counter = Counter()

    for alert in alerts_iter:
        rule    = alert.get("rule", {})
        rule_id = str(rule.get("id", "") or "")
        groups  = rule.get("groups", []) or []
        total  += 1

        if rule_id in _RULE_OVERRIDES:
            clean += 1
            continue

        groups_lower = {g.lower() for g in groups}
        matched = False
        for triggers, _ in _GROUP_RULES:
            if any(t in g for t in triggers for g in groups_lower):
                matched = True
                break
        if matched:
            clean += 1
        else:
            unmapped_rules[rule_id] += 1

    other = total - clean
    return {
        "platform":           platform,
        "total":              total,
        "clean":              clean,
        "other":              other,
        "clean_pct":          round(100 * clean / total, 1) if total else 0.0,
        "top_unmapped_rules": unmapped_rules.most_common(10),
    }


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import json, sys, os

    ROOT = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, ROOT)

    print("=== normalize_schema.py self-test ===")
    print(f"FEATURE_COLS_NORM ({NUM_FEATURES_NORM} features):")
    for i, c in enumerate(FEATURE_COLS_NORM):
        print(f"  {i:2d}. {c}")

    # Test on a handful of lnx-dmz alerts
    sample_alerts = []
    with open(os.path.join(ROOT, "lnx_dmz_ai_detections.json")) as fh:
        for i, line in enumerate(fh):
            if i >= 200: break
            line = line.strip()
            if line:
                try: sample_alerts.append(json.loads(line).get("original_alert", {}))
                except: pass

    # Coverage report — Linux
    cov_lnx = coverage_report(sample_alerts, platform="linux-sample")
    print(f"\nLinux sample coverage: {cov_lnx['clean']}/{cov_lnx['total']} "
          f"= {cov_lnx['clean_pct']}% clean")
    print("  Top unmapped rules:", cov_lnx["top_unmapped_rules"][:5])

    # Coverage report — Windows
    win_alerts = []
    for fname in ["ossec-alerts-23.json", "ossec-alerts-24.json"]:
        fpath = os.path.join(ROOT, "testAlerts", "Alerts", fname)
        with open(fpath) as fh:
            for line in fh:
                if win_alerts and len(win_alerts) >= 300: break
                line = line.strip()
                if line:
                    try: win_alerts.append(json.loads(line))
                    except: pass

    cov_win = coverage_report(win_alerts, platform="windows-sample")
    print(f"\nWindows sample coverage: {cov_win['clean']}/{cov_win['total']} "
          f"= {cov_win['clean_pct']}% clean")
    print("  Top unmapped rules:", cov_win["top_unmapped_rules"][:5])

    # Quick feature extraction test
    from shared_constants import MITRE_TACTIC_MAP  # noqa
    dummy_hfeat = {k: 0.0 for k in [
        "alert_rate_1min", "failed_login_5min", "unique_src_ip_10min",
        "high_sev_ratio_20", "rule_diversity_10min", "time_since_last_high",
        "scan_preceded", "brute_preceded", "kill_chain_stage",
    ]}
    dummy_hfeat["time_since_last_high"] = 999.0

    test_alert = {
        "rule": {"id": "5402", "level": 3, "description": "Successful sudo to ROOT executed",
                 "groups": ["syslog", "sudo"]},
        "full_log": "sudo: ubuntu : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash",
    }
    feats = extract_normalized(test_alert, dummy_hfeat)
    assert len(feats) == NUM_FEATURES_NORM, f"expected {NUM_FEATURES_NORM}, got {len(feats)}"
    print(f"\nSudo-to-root alert normalized ({len(feats)} features):")
    for name, val in zip(FEATURE_COLS_NORM, feats):
        if val != 0.0:
            print(f"  {name}: {val}")
    print("\nSelf-test PASSED.")
