# Data

Three kinds of data are involved: the public AIT-ADS benchmark (downloaded separately), files derived
from it that this repository ships, and this project's own testbed collection.

## AIT-ADS (not included; download separately)

**Licence.** The AIT Alert Data Set (AIT-ADS) is published on Zenodo, DOI
[10.5281/zenodo.8263181](https://doi.org/10.5281/zenodo.8263181), under **Creative Commons Attribution 4.0
International (CC BY 4.0)**. This repository does not include the raw alert files; it downloads them from
Zenodo on request (below), because they are large (2.9 GB unpacked).

**Required citations** (from the Zenodo record; cite both if you use AIT-ADS):

> Max Landauer, Florian Skopik, Markus Wurzenberger. "Introducing a New Alert Data Set for Multi-Step Attack
> Analysis." *Proceedings of the 17th Cyber Security Experimentation and Test Workshop* (CSET '24), 2024.
> DOI: [10.1145/3675741.3675748](https://doi.org/10.1145/3675741.3675748). Also on arXiv:
> [2308.12627](https://arxiv.org/abs/2308.12627).

> Max Landauer, Florian Skopik, Maximilian Frank, Wolfgang Hotwagner, Markus Wurzenberger, Andreas Rauber.
> "Maintainable Log Datasets for Evaluation of Intrusion Detection Systems." *IEEE Transactions on Dependable
> and Secure Computing*, vol. 20, no. 4, pp. 3466-3482, 2023.

**Getting the data.**

```bash
python data/download_ait_ads.py --download     # about 96 MB download, verified by md5, 2.9 GB unpacked
python data/download_ait_ads.py --check --full # verify all 17 files again (sizes and md5)
```

This places the 16 alert files at `data/ait_ads/raw/<scenario>_{wazuh,aminer}.json` (scenarios `fox`, `harrison`,
`russellmitchell`, `santos`, `shaw`, `wardbeck`, `wheeler`, `wilson`) and the attack-phase intervals at
`data/ait_ads/labels.csv`. The folder `data/ait_ads/` is git-ignored. `python data/download_ait_ads.py --check`
without `--full` only checks that the 17 files exist with the expected sizes. The downloader reads the archive and
`labels.csv` from the Zenodo record and checks them against the checksums published there (archive md5
`43db6b1f0996e0024befd617706c50e9`, `labels.csv` md5 `60ff33796c77fd2136c4d1a4bc841bd9`).

**Files in this repository derived from AIT-ADS.** They are redistributed under CC BY 4.0 with attribution to
Landauer, Skopik and Wurzenberger. Changes: the Wazuh alerts were reduced to 26 numeric features and a label, or to
per-alert rule, scenario and time metadata; nothing else is kept. No raw alert text is shipped.

| file | what it holds |
|---|---|
| `models_v2/ait_split.npz` | 2,600,263 Wazuh/Suricata alerts as 26 features plus label, split 80/20 into train and test |
| `analysis/xdet_wazuh_recovered_split.npz` | for the same alerts: row index of the split, label, rule id, rule description, scenario, epoch |
| `analysis/xdet_aminer_split.npz` | the same for the 55,558 AMiner alerts (name, scenario, epoch, split) |
| `models_v2/xgb_model.pkl`, `xgb_normalized.pkl` and the scalers | models and preprocessing fitted on that data |
| aggregate tables: `results/rule_memorization_audit/*.csv`, `results_v2/ait_ads_rule_breakdown.csv`, `analysis/rev_dataset_characterisation.csv`, `analysis/xdet_*.json`, `ait_ads_seen_*.txt` | counts and metrics computed from AIT-ADS |

`analysis/xdet_aminer_signature_check.py` writes a file of raw AMiner log lines
(`analysis/xdet_aminer_dominant_sig_records.csv`) when the raw data is present. It is git-ignored and is not
shipped: AIT-ADS was generated from the AIT Log Data Set V2.0, which is licensed CC BY-NC-SA 4.0, and this
repository does not redistribute log lines taken from it.

Scripts that read `data/ait_ads/raw/` are skipped, not failed, by `reproduce.sh` when it is absent. The steps that
use only the shipped `.npz` files above (the lookup/ablation audit, temporal split, multiseed and cross-detector
lookup) run without it.

## Testbed collection (`testbed_collection/`) and other data we produced

This project's own Atomic Red Team collection: a Linux host (`lnx-dmz`) and a Windows host (`win-cl1`), each with an
attack round and a separate benign-only round. Licensed CC BY 4.0 (`LICENSE-DATA`).

| file | what it is |
|---|---|
| `collection_lnx_alerts.{json,csv}`, `collection_win_alerts.{json,csv}` | raw Wazuh/Sysmon alert stream, attack round |
| `labeled_lnx.csv`, `labeled_win.csv` | the same, after labelling (see `labelling/`) |
| `collection_benign_lnx_alerts.{json,csv}`, `collection_benign_win_alerts.{json,csv}` | the benign-only rounds (Linux n=267, Windows n=201) |
| `audit_lnxdmz.log` | raw Linux auditd log (partial: rotation lost about 79% of the collection window, which is why Linux labelling does not use a process tree; see `labelling/label_lnx_timeonly.py`) |
| `sysmon_eid1.csv`, `sysmon_artifacts.csv` | parsed Sysmon process-creation records used to build the Windows process tree (`labelling/build_sysmon_tree.py`) |
| `collect_markers_{lnx,win}.txt` | timestamped `>>> ... START/END` markers delimiting each attack technique window |

Other data we produced, outside this folder:

- `lnx_dmz_ai_detections.json`: alerts from the same Linux host collected between 2025-12-02 and 2026-05-25
  (the source of the OC-SVM training set; see `build_clean_benign_baseline.py`).
- `attack_log.txt`: start/end markers of the 2026-05-25 attack run.
- `results_v2/benign_baseline_clean.csv`: the cleaned benign baseline (26 features per alert) built from it.

**`sysmon_wincl1.evtx`** (the 59 MB raw Sysmon export that `sysmon_eid1.csv` was parsed from) is not included; it
adds nothing beyond the two CSV files for this repository's scripts.

**Privacy.** The Windows event text contained a shared lab account email address. It was replaced by the placeholder
`lab-user-1` in every file; no email address remains in the data. Lab account and path names that remain
(`C:\Users\coe55...`, `C:\Users\Administrator`, `/home/lnx-dmz`, `/home/coluser`) belong to the lab virtual machines.
All IP addresses are private (`192.168.x.x`, `10.x.x.x`) or loopback (`127.0.0.1`), except the placeholder
`1.2.3.4` used as the attacker address in `lnx_dmz_ai_detections.json`.

**Strings in the raw data that look like secrets but are not.** The attack scripts, logged verbatim by Windows
script-block logging, create a throwaway test account `coluser` with the password `P@ssw0rd123!` and delete it
afterwards (`collection_win_alerts.json`, `labeled_win.csv`); the Linux file-integrity alerts contain fake SSH key
lines such as `ssh-rsa AAAAB3COLLECTNOVEL colkey`. None is a real credential.
