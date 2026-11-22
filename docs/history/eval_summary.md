# Phase 4 -- v6 model evaluation on genuinely-labeled re-collection
_All scoring reuses the validated v6 artifacts; nothing was retrained. Feature construction matches the deployed pipeline (per-agent history)._
**Deployed thresholds** (thresholds_production_v3.json): theta_xgb=0.07538, theta_ocsvm=-0.33500. L2 = v6_retrained_31151_5710.
## Task 1 -- Known attacks (31101/31151), Layer 1
| alerts | TP | FN | recall | FNR | F1 | FPR |
|--:|--:|--:|--:|--:|--:|--:|
| 22,250 | 22,241 | 9 | 99.96% | 0.04% | n/a | n/a |
_F1 and FPR require a benign class; none was collected (idle baselines). FNR = 1 - recall is computable and reported._
## Task 2 -- Novel attacks per technique (discriminative alerts only)
Every rule here is absent from training, so L1 recall = generalization (not memorization); L2 recall = genuine anomaly detection.
| technique | n | L1 recall | L2 recall | either | note |
|---|--:|--:|--:|--:|---|
| T1053.003 | 6 | 33.3% | 100.0% | 100.0% | L2 anomaly-driven |
| T1098.004 | 6 | 0.0% | 100.0% | 100.0% | L2 anomaly-driven |
| T1110.001 | 119 | 96.6% | 22.7% | 100.0% | L1 generalizes (rule unseen) |
| T1136.001 | 163 | 37.4% | 74.2% | 79.8% | L2 anomaly-driven |
| T1543.002 | 6 | 50.0% | 100.0% | 100.0% | L2 anomaly-driven |
| T1546.004 | 6 | 83.3% | 50.0% | 83.3% | L1 generalizes (rule unseen) |

_Incidental alerts (sudo/PAM/process-noise), reported separately, never merged: n=213, L1=48.4%, L2=79.8%._
## Task 1c/2c -- FPR
**Not computable — no benign class collected.** The 19 'benign' Linux alerts are attack-script side effects (PAM/sudo during teardown), not background traffic; the 90s baselines were idle.
## Task 3 -- Cross-platform (Windows), first genuinely-labeled result
Normalized 22-feature model; thresholds re-derived from ait_split.npz (theta_xgb_norm=0.0740, theta_ocsvm_norm=-0.0004; AIT-ADS reproduction F1=0.969, PASS). process_depth=0 (as in training), though a real Sysmon tree exists.
Discriminative alerts only (same rule as Linux); incidental reported separately.

| technique | n | L1 recall | L2 recall | either |
|---|--:|--:|--:|--:|
| T1110.001 | 241 | 55.2% | 100.0% | 100.0% |
| T1136.001 | 8 | 62.5% | 100.0% | 100.0% |

_Windows incidental (logon-success/process-noise), separate: n=56, L1=94.6%, L2=100.0%._

_Windows FPR not computable: benign class = 3 alerts._
