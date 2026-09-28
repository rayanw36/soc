"""v8_write_outputs.py -- consolidate Tasks 0-4 into the final v8 deliverables."""
import json
import os
import sys

import pandas as pd

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(_PROJECT_ROOT)

calib = pd.read_csv("analysis/v8_task1_calibration.csv")
task2 = pd.read_csv("analysis/v8_task2_comparison.csv")
same_space = pd.read_csv("analysis/v8_task3_same_space.csv")
tradeoff = pd.read_csv("analysis/v8_task3_tradeoff.csv")
task4 = pd.read_csv("analysis/v8_task4_l1_routing.csv")

# ---------------------------------------------------------------------------
# thresholds_v8.json
# ---------------------------------------------------------------------------
thresholds = {
    "_meta": {
        "generated_by": "newCol/v8_task1_train.py, v8_task2_eval.py, v8_task3_lnx_regression.py, v8_task4_l1_routing.py",
        "recommendation": "platform-routed: keep the 26-feat v5-defer pipeline for Linux "
                           "(unchanged); route Windows to L2-only C2 (ocsvm_xplatform_v7.pkl, "
                           "unretrained) at its calibrated threshold; bypass L1 on Windows entirely.",
    },
    "windows": {
        "calibration_set": {
            "source": "testAlerts/Alerts/ossec-alerts-{23,24}.json, high-confidence benign "
                       "(>=60min outside WINDOWS_ATTACK_WINDOWS), 70/30 split seed=42",
            "session": "2025-11-23/24 (cross-session vs. the 2026-07-08 attack collection -- flagged per Guard 1)",
            "n": 3398,
            "role": "calibration only -- never used to fit any model",
        },
        "evaluation_set": {
            "source": "data/testbed_collection/collection_benign_win_alerts.json",
            "session": "2026-07-12 (fresh, matched testbed/agent WIN-CL1, dedicated single session)",
            "n": 201,
            "role": "held-out FPR evaluation only -- untouched by training or calibration",
        },
        "l2_thresholds": {
            row["candidate"]: {
                "theta_calibrated": row["theta_calibrated"],
                "percentile_used": int(row["percentile_used"]),
                "fpr_at_calibrated_on_calibration": row["fpr_at_calibrated"],
                "theta_sign": row["theta_sign"],
                "fpr_at_sign_on_calibration": row["fpr_at_sign"],
            }
            for _, row in calib.iterrows()
        },
        "l1_theta_recalibrated": 0.99286,
        "l1_routing_recommendation": "bypass -- L1 fires on zero alerts (attack or benign) "
                                      "on fresh evaluation data at this threshold; fully inert",
    },
    "linux": {
        "reference_threshold": {
            "model": "models_v2/ocsvm_normalized.pkl",
            "theta_ocsvm_norm": -0.0004195287152697347,
            "derivation": "phase3_normalized_v7 method: 90th percentile of AIT-ADS test-split "
                           "benign scores (ait_split.npz) -- unchanged from prior work",
            "caveat": "This same threshold produces 100% FPR on the FRESH matched Linux benign "
                      "(n=267, 2026-07-12) -- REF is saturated on any data outside its original "
                      "AIT-ADS training distribution, not just cross-platform. Not a reliable "
                      "floor for the same-space regression comparison.",
        },
        "frozen_v5_production_reference": {
            "pipeline": "26-feat xgb_model.pkl + ocsvm_nu05.pkl (v5) + rule_confound_fixes_v5.json defer",
            "novel_recall": 0.8431, "fpr": 0.1086, "f1": 0.8702,
            "note": "cross-pipeline reference, not same feature space as the 22-feat models above",
        },
    },
}
with open("models_v2/thresholds_v8.json", "w") as f:
    json.dump(thresholds, f, indent=2)
print("wrote models_v2/thresholds_v8.json")

# ---------------------------------------------------------------------------
# windows_recalibration_v8.csv -- all tables, tagged by task
# ---------------------------------------------------------------------------
calib.insert(0, "task", "1_calibration")
task2.insert(0, "task", "2_windows_headline")
same_space.insert(0, "task", "3a_linux_same_space")
tradeoff.insert(0, "task", "3_tradeoff")
task4.insert(0, "task", "4_l1_routing")

all_rows = pd.concat([calib, task2, same_space, tradeoff, task4], ignore_index=True, sort=False)
all_rows.to_csv("results_v2/windows_recalibration_v8.csv", index=False)
print("wrote results_v2/windows_recalibration_v8.csv")
