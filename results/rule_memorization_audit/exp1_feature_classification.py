import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import os as _os
REPO_ROOT = _os.path.dirname(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
"""
Experiment 1 — Feature inventory and classification.
Enumerates all 26 features from shared_features.py and classifies each into
RULE-IDENTITY, RULE-CORRELATED, or BEHAVIORAL.
"""
import csv, sys, os
sys.path.insert(0, REPO_ROOT)
from shared_constants import FEATURE_COLS_V2

OUT = REPO_ROOT + "/results/rule_memorization_audit/exp1_feature_classification.csv"

# -----------------------------------------------------------------------
# Manual classification — justified feature-by-feature
# -----------------------------------------------------------------------
CLASSIFICATIONS = [
    # (feature_name, bucket, justification)

    # ---- RULE-IDENTITY -------------------------------------------------
    ("desc_len",
     "RULE-IDENTITY",
     "Length of rule.description string. Each Wazuh rule has a fixed, unique "
     "description, so desc_len acts as a noisy-but-informative proxy for rule.id. "
     "In practice, dirb rules (31101) have short descriptions; auth rules have longer ones."),

    ("rule_level",
     "RULE-IDENTITY",
     "Wazuh rule severity level (integer 0-15) is set in the rule XML definition and is "
     "constant per rule. It does not vary with the actual event payload."),

    # ---- RULE-CORRELATED (keyword features) ----------------------------
    ("kw_scan",
     "RULE-CORRELATED",
     "Keyword 'scan' present in build_combined_text(), which combines rule.description "
     "(fixed per rule) + full_log + commandLine + MITRE keyword injections. "
     "In AIT-ADS the rule description and MITRE inject dominate; 'scan' fires reliably "
     "for T1046/T1595 rules regardless of payload content."),

    ("kw_brute",
     "RULE-CORRELATED",
     "Keyword 'brute' from combined text — dominated by rule description for cracking/auth rules "
     "(e.g., rule 5710 'Multiple authentication failures') and by MITRE inject for tactic "
     "'credential access' (injected string: 'password brute')."),

    ("kw_password",
     "RULE-CORRELATED",
     "Keyword 'password' — fired by MITRE inject for 'credential access' tactic, "
     "which is a rule-level annotation. Also present in descriptions of auth-failure rules."),

    ("kw_denied",
     "RULE-CORRELATED",
     "Keyword 'denied' appears in the description of Apache/web rules (31101: "
     "'Access to a potentially harmful file denied'). Nearly constant per-rule."),

    ("kw_root",
     "RULE-CORRELATED",
     "Keyword 'root' fired by MITRE inject for 'privilege escalation' and 'defense evasion' "
     "tactics, and by rule descriptions for sudo/su rules (5401/5402). Rule-derived."),

    ("kw_privilege",
     "RULE-CORRELATED",
     "Keyword 'privilege' — injected via MITRE inject string 'privilege root' for tactic "
     "'privilege escalation'. Deterministically set by the rule's MITRE annotation."),

    ("kw_sql",
     "RULE-CORRELATED",
     "Keyword 'sql' present in descriptions of SQL-injection detection rules and web-attack "
     "rule groups. Rarely fires on genuine log content in this dataset."),

    ("kw_shell",
     "RULE-CORRELATED",
     "Keyword 'shell' — MITRE inject adds 'shell' for tactics 'execution', 'lateral movement', "
     "'command and control'. Also in rule descriptions for reverse-shell rules (e.g., 86601)."),

    ("kw_trojan",
     "RULE-CORRELATED",
     "Keyword 'trojan' from rule descriptions (antivirus/malware rules). Essentially a rule-type flag."),

    ("kw_virus",
     "RULE-CORRELATED",
     "Keyword 'virus' from rule descriptions (AV/malware rules). Same category as kw_trojan."),

    # ---- RULE-CORRELATED (semantic / structured rule metadata) ---------
    ("mitre_tactic_id",
     "RULE-CORRELATED",
     "Integer encoding of rule.mitre.tactic from MITRE_TACTIC_MAP. This field is populated "
     "by the Wazuh rule definition, not by the event payload — it is a rule annotation. "
     "Constant per rule."),

    ("is_auth_failure",
     "RULE-CORRELATED",
     "1 if rule.groups intersects _AUTH_FAIL_GROUPS. Rule groups are rule-definition metadata; "
     "the same rule fires this flag every time regardless of what happened."),

    ("is_web_attack",
     "RULE-CORRELATED",
     "1 if rule.groups intersects _WEB_ATTACK_TOKENS, or rule description contains web-attack "
     "phrases. Both sources are fixed per rule. Effectively a rule-type indicator."),

    ("rule_id_encoded",
     "RULE-IDENTITY",
     "Direct numeric encoding of rule.id (float(int(rule.id))). The clearest possible "
     "rule-identity feature — the model can learn a per-rule lookup table through this column."),

    ("agent_criticality",
     "RULE-CORRELATED",
     "Weight derived from agent.name substring matching (e.g., 'win-dc'→3, 'lnx-dmz'→1). "
     "Encodes WHICH monitoring agent sent the alert, not what happened. Per the project notes, "
     "agent name is classified as rule-correlated (log source / deployment artifact)."),

    # ---- RULE-CORRELATED (behavioral aggregates over rule-derived signals)
    ("alert_rate_1min",
     "BEHAVIORAL",
     "Raw count of alerts in the past 60 s for this agent, regardless of which rules fired. "
     "The only purely count-based, rule-agnostic temporal rate feature."),

    ("failed_login_5min",
     "RULE-CORRELATED",
     "Count of alerts where is_auth_failure=1 in the past 5 min. The 'failure' classification "
     "comes from rule groups (rule metadata), making this an aggregated rule-group count, "
     "not an independent observation of auth state."),

    ("unique_src_ip_10min",
     "BEHAVIORAL",
     "Count of distinct srcip values in the past 10 min. Source IP is an observed network "
     "field drawn from the raw log, not rule metadata. Captures scanning/spray behavior "
     "from actual packet headers."),

    ("high_sev_ratio_20",
     "RULE-CORRELATED",
     "Fraction of last 20 alerts with rule.level >= 8. Rule level is a rule-definition "
     "property (constant per rule), so this aggregates rule severity metadata over a window, "
     "not an independent behavioral signal."),

    ("rule_diversity_10min",
     "RULE-CORRELATED",
     "Count of distinct rule.id values in the past 10 min. Directly counts distinct rule "
     "identifiers — an aggregation of rule-identity values over time, not of semantic behaviors."),

    ("time_since_last_high",
     "BEHAVIORAL",
     "Seconds since the last alert with rule.level >= 10 (or 999 if none). While 'high' is "
     "defined by rule level (metadata), the TIME ELAPSED is a genuinely temporal behavioral "
     "pattern — attack bursts cluster level-10 alerts together. Borderline but placed here "
     "as the temporal gap carries independent signal beyond rule identity."),

    ("scan_preceded",
     "RULE-CORRELATED",
     "1 if any alert in the past 10 min had kw_scan=1. kw_scan is itself RULE-CORRELATED "
     "(dominated by rule description and MITRE inject), so scan_preceded inherits that "
     "correlation — it measures whether a scan-type rule fired recently."),

    ("brute_preceded",
     "RULE-CORRELATED",
     "1 if any alert in the past 10 min had kw_brute=1. Same reasoning as scan_preceded: "
     "kw_brute is rule-description/MITRE-derived, so brute_preceded is an aggregated "
     "rule-correlated flag."),

    ("kill_chain_stage",
     "RULE-CORRELATED",
     "0-4 integer derived deterministically from mitre_tactic_id via _kill_chain_stage(). "
     "Because mitre_tactic_id is itself rule-correlated, kill_chain_stage is a coarsening "
     "of that rule-derived feature. Constant per rule."),
]

assert len(CLASSIFICATIONS) == 26, f"Expected 26 rows, got {len(CLASSIFICATIONS)}"
# Verify all canonical feature names are covered
listed = {r[0] for r in CLASSIFICATIONS}
missing = set(FEATURE_COLS_V2) - listed
extra   = listed - set(FEATURE_COLS_V2)
assert not missing, f"Missing features: {missing}"
assert not extra,   f"Extra features: {extra}"

# -----------------------------------------------------------------------
# Write CSV (preserving canonical feature order)
# -----------------------------------------------------------------------
feature_order = {f: i for i, f in enumerate(FEATURE_COLS_V2)}
rows_sorted = sorted(CLASSIFICATIONS, key=lambda r: feature_order[r[0]])

with open(OUT, "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=["col_idx", "feature", "bucket", "justification"])
    w.writeheader()
    for i, (feat, bucket, just) in enumerate(rows_sorted):
        w.writerow({"col_idx": i+1, "feature": feat, "bucket": bucket, "justification": just})

print(f"Wrote {len(rows_sorted)} rows → {OUT}")

# -----------------------------------------------------------------------
# Summary table (print to stdout)
# -----------------------------------------------------------------------
from collections import Counter
bucket_counts = Counter(r[1] for r in CLASSIFICATIONS)
n_total = len(CLASSIFICATIONS)

print("\n### Experiment 1 — Feature Classification Summary")
print(f"\n{'#':>4}  {'Feature':<25} {'Bucket'}")
print("-" * 60)
for i, (feat, bucket, _) in enumerate(rows_sorted):
    marker = ""
    print(f"  {i+1:>2}.  {feat:<25} {bucket} {marker}")

print("\n### Bucket Totals")
for bucket in ["RULE-IDENTITY", "RULE-CORRELATED", "BEHAVIORAL"]:
    n = bucket_counts[bucket]
    pct = 100 * n / n_total
    print(f"  {bucket:<20}: {n:>2} / {n_total}  ({pct:.1f}%)")

id_corr = bucket_counts["RULE-IDENTITY"] + bucket_counts["RULE-CORRELATED"]
print(f"\n  RULE-IDENTITY + RULE-CORRELATED: {id_corr} / {n_total} ({100*id_corr/n_total:.1f}%)")
print(f"  BEHAVIORAL only               : {bucket_counts['BEHAVIORAL']} / {n_total} "
      f"({100*bucket_counts['BEHAVIORAL']/n_total:.1f}%)")
