"""
shared_constants.py
===================
Central definition of every constant used across the SOC alert-triage v2 pipeline
(XGBoost + MemAE + RL threshold adaptation + CORAL transfer learning).

Import with:  from shared_constants import *
"""

# ----------------------------------------------------------------------------
# Keyword feature vocabulary (order matters -> maps to kw_* feature columns)
# ----------------------------------------------------------------------------
KEYWORDS = ["scan", "brute", "password", "denied", "root", "privilege",
            "sql", "shell", "trojan", "virus"]

# ----------------------------------------------------------------------------
# Feature column definitions
# ----------------------------------------------------------------------------
FEATURE_COLS_V1 = ["desc_len", "rule_level", "kw_scan", "kw_brute", "kw_password",
                   "kw_denied", "kw_root", "kw_privilege", "kw_sql", "kw_shell",
                   "kw_trojan", "kw_virus"]

FEATURE_COLS_V2 = FEATURE_COLS_V1 + [
    "mitre_tactic_id",
    "is_auth_failure",
    "is_web_attack",
    "rule_id_encoded",
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
]

NUM_FEATURES_V1 = 12
NUM_FEATURES_V2 = 26
SEED = 42

# ----------------------------------------------------------------------------
# MITRE tactic -> keyword injection. Adds attack-relevant keywords to the
# combined text so the kw_* features fire even when the raw log is terse.
# ----------------------------------------------------------------------------
MITRE_INJECT = {
    "credential access":    "password brute",
    "privilege escalation": "privilege root",
    "execution":            "shell",
    "discovery":            "scan",
    "lateral movement":     "scan shell",
    "command and control":  "shell trojan",
    "defense evasion":      "root",
    "persistence":          "root",
}

# ----------------------------------------------------------------------------
# MITRE tactic -> integer id (feature mitre_tactic_id)
# ----------------------------------------------------------------------------
MITRE_TACTIC_MAP = {
    "reconnaissance": 0, "resource development": 1,
    "initial access": 2, "execution": 3,
    "persistence": 4, "privilege escalation": 5,
    "defense evasion": 6, "credential access": 7,
    "discovery": 8, "lateral movement": 9,
    "collection": 10, "command and control": 11,
    "exfiltration": 12, "impact": 13,
}

# ----------------------------------------------------------------------------
# Agent name substring -> criticality weight (feature agent_criticality)
# ----------------------------------------------------------------------------
AGENT_CRITICALITY_MAP = {
    "win-dc": 3, "win_dc": 3, "windc": 3,
    "win-cli": 2, "win_cli": 2, "wincli": 2,
    "lnx-dmz": 1, "lnx_dmz": 1,
}

# ----------------------------------------------------------------------------
# Cost model: a false negative is FN_FP_COST_RATIO times worse than a false
# positive (missed attack vs. analyst nuisance).
# ----------------------------------------------------------------------------
FN_FP_COST_RATIO = 10

# ----------------------------------------------------------------------------
# Ground-truth attack windows for the live lnx-dmz Atomic-Red-Team experiment.
# (technique, phase, start_iso, end_iso). Times are UTC (Z).
# ----------------------------------------------------------------------------
ATTACK_WINDOWS_LNX = [
    ("T1595.003", "AIT-ADS", "2026-05-25T13:33:39Z", "2026-05-25T13:36:15Z"),
    ("T1046",     "AIT-ADS", "2026-05-25T13:39:15Z", "2026-05-25T13:43:16Z"),
    ("T1110.001", "AIT-ADS", "2026-05-25T13:46:16Z", "2026-05-25T13:48:22Z"),
    ("T1595.002", "AIT-ADS", "2026-05-25T13:51:22Z", "2026-05-25T13:53:23Z"),
    ("T1489",     "AIT-ADS", "2026-05-25T13:56:23Z", "2026-05-25T13:59:29Z"),
    ("T1048.003", "AIT-ADS", "2026-05-25T14:02:29Z", "2026-05-25T14:04:40Z"),
    ("T1053.003", "NOVEL",   "2026-05-25T14:17:40Z", "2026-05-25T14:19:41Z"),
    ("T1136.001", "NOVEL",   "2026-05-25T14:22:41Z", "2026-05-25T14:24:41Z"),
    ("T1070.003", "NOVEL",   "2026-05-25T14:27:41Z", "2026-05-25T14:29:42Z"),
    ("T1003.008", "NOVEL",   "2026-05-25T18:04:00Z", "2026-05-25T18:06:03Z"),
    ("T1548.001", "NOVEL",   "2026-05-25T18:09:03Z", "2026-05-25T18:11:10Z"),
    ("T1105",     "NOVEL",   "2026-05-25T18:14:39Z", "2026-05-25T18:16:45Z"),
    ("T1074.001", "NOVEL",   "2026-05-25T18:19:45Z", "2026-05-25T18:21:46Z"),
]

EXPERIMENT_START = "2026-05-25T13:32:39Z"
EXPERIMENT_END   = "2026-05-25T18:22:46Z"

# ----------------------------------------------------------------------------
# Windows cross-platform attack windows (target domain for transfer learning).
# (start_iso, end_iso). Times are UTC (Z).
# ----------------------------------------------------------------------------
WINDOWS_ATTACK_WINDOWS = [
    ("2025-11-23T16:15:00Z", "2025-11-23T19:45:00Z"),
    ("2025-11-24T16:00:00Z", "2025-11-24T23:59:59Z"),
]
