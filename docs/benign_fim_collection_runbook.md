# Benign-FIM Collection Runbook (Sessions A + B)

Prepared to close the Task 0 STOP finding: v5's actual training benign has 1
syscheck alert out of 4,257; the fresh matched benign has 9 out of 267, all in
one path class ("other"). Every f27 persistence-path category (cron, systemd,
shell-rc, ssh-key, account-mgmt) currently has **zero** benign examples anywhere.

**Naming correction:** no `collect_lnx.sh` exists anywhere in this repo. The
actual wrapper used for the July 12 benign collection (`newCol/benign_markers_lnx.txt`)
is `./extract_agent.sh <agent_id> <START-UTC> <END-UTC> <tag>`, run against
SOC-Wazuh after the session, agent 003 for lnx-dmz. This runbook uses that
script name; if a differently-named wrapper exists on the current testbed,
substitute it — the marker format and window discipline are what matter.

## Path-monitoring status (empirical, not from ossec.conf — none is in this repo)

Checked every `syscheck.path` that has ever actually fired across both the July
2026 attack and benign collections:

| path prefix | status | evidence |
|---|---|---|
| `/etc/cron.d/*` | **CONFIRMED** | fired in attack collection (T1053.003) |
| `/etc/systemd/system/*` | **CONFIRMED** | fired in attack collection (T1543.002) |
| `/etc/profile.d/*` | **CONFIRMED** | fired in attack collection (T1546.004) |
| `/root/.ssh/*` | **CONFIRMED** | fired in attack collection (T1098.004) |
| `/home/<user>/.ssh/*` | **CONFIRMED** | fired organically in benign collection (`known_hosts`) |
| `/etc/passwd*`, `/etc/shadow*`, `/etc/group*`, `/etc/gshadow*`, `/etc/subuid*`, `/etc/subgid*` | **CONFIRMED** | fired extensively as useradd/usermod side effects |
| `/etc/*` generally | **CONFIRMED broad** | `/etc/cups/subscriptions.conf` fired from routine, non-scripted CUPS activity — the watch is not an allowlist of testbed-specific files |
| bare `/home/<user>/.bashrc` (outside `.ssh/`) | **UNCONFIRMED** | never observed firing; home directories may only be watched under `.ssh/` |
| `/var/spool/cron/crontabs/<user>` (user crontab via `crontab -e`) | **UNCONFIRMED** | never observed; only `/etc/cron.d/` has fired |

**Runbook design consequence:** the shell-rc activity uses only
`/etc/profile.d/` (confirmed). The `.bashrc` variant is included as an
**optional, flagged** extra — run it if you want the extra path diversity, but
verify live first (see the smoke-test line in that block) since it may produce
zero alerts, and don't spend collection time on it if it doesn't fire. Same
treatment for `crontab -e`. The cron activity itself uses `/etc/cron.d/`
exclusively (both edit and add), which is fully confirmed.

---

## Session tags and window discipline (same convention as all prior newCol collections)

- Session A: tag `benign_fim_A` — training-benign supplement.
- Session B: tag `benign_fim_B` — **held-out evaluation only, run on a
  different day than A.** Same activities, different filenames/account names
  (noted per block below) so B is not a byte-for-byte replay of A.
- Marker format: `>>> <UTC-ISO> <LABEL> | <detail>`, matching
  `benign_markers_lnx.txt`'s convention exactly.
- Dedicated benign-only window: nothing attack-shaped runs before, during, or
  after. No `dirb`/`nmap`/`hydra`/brute-force activity in the same window.
- Archive raw `audit.log` at session end, same as every prior collection:
  `sudo cp /var/log/audit/audit.log ~/collection_$(date +%F)/audit_fim_<A|B>.log`

---

## Command checklist

Run in this order. Each block: marker line(s), the command(s), expected rule
ID(s), and the f27 class it targets. Wait for each activity's alert to appear
in `tail -f /var/ossec/logs/alerts/alerts.json` (or equivalent) before moving
to the next block — this is a live smoke-test as you go, not just a
post-session check.

### Block 0 — session start

```bash
echo ">>> $(date -u +%Y-%m-%dT%H:%M:%SZ) BENIGN_FIM_START tag=benign_fim_A" >> ~/benign_fim_markers.txt
echo ">>> $(date -u +%Y-%m-%dT%H:%M:%SZ) EXPORT_FROM | note_this_time_minus_30min_for_export" >> ~/benign_fim_markers.txt
```
(Session B: same block, `tag=benign_fim_B`.)

### Block 1 — package/conffile update touching `/etc` (f27: other, benign content baseline)

Offline-safe choice (no network dependency) — reconfigure tzdata to its
current value, a genuinely routine sysadmin action that rewrites `/etc/timezone`
and `/etc/localtime`:

```bash
echo ">>> $(date -u +%Y-%m-%dT%H:%M:%SZ) START | benign_conffile_update" >> ~/benign_fim_markers.txt
sudo dpkg-reconfigure tzdata   # accept the current timezone value unchanged
echo ">>> $(date -u +%Y-%m-%dT%H:%M:%SZ) END | benign_conffile_update" >> ~/benign_fim_markers.txt
```
Expected: rule 550 (modified) on `/etc/timezone` and/or `/etc/localtime`.
If connectivity is available and you prefer the apt route instead:
`sudo apt-get install --reinstall --force-confnew logrotate` also works and
touches `/etc/logrotate.conf`. Session B: use the apt route (or a different
low-risk package) if session A used tzdata, for variation.

### Block 2a — edit an existing `/etc/cron.d/` entry (f27: cron)

```bash
echo ">>> $(date -u +%Y-%m-%dT%H:%M:%SZ) START | benign_cron_edit_existing" >> ~/benign_fim_markers.txt
sudo sed -i '$ a # benign fim collection marker A' /etc/cron.d/e2scrub_all   # or any existing entry present
echo ">>> $(date -u +%Y-%m-%dT%H:%M:%SZ) END | benign_cron_edit_existing" >> ~/benign_fim_markers.txt
```
Expected: rule 550 (modified). Verify `/etc/cron.d/e2scrub_all` (or substitute
whichever pre-existing file is actually present — `ls /etc/cron.d/` first)
exists before running. Session B: append a differently-worded comment to a
different existing entry if more than one is present.

### Block 2b — add a new file under `/etc/cron.d/` (f27: cron)

```bash
echo ">>> $(date -u +%Y-%m-%dT%H:%M:%SZ) START | benign_cron_add_new" >> ~/benign_fim_markers.txt
echo '*/15 * * * * root /bin/true # fim-benign-test-A' | sudo tee /etc/cron.d/fim-benign-test-A
echo ">>> $(date -u +%Y-%m-%dT%H:%M:%SZ) END | benign_cron_add_new" >> ~/benign_fim_markers.txt
# cleanup after the alert has fired:
sudo rm /etc/cron.d/fim-benign-test-A
```
Expected: rule 554 (added), then rule 553 (deleted) on cleanup — both useful,
both benign. Session B filename: `fim-benign-test-B`.

### Block 3 — SSH key append via `ssh-copy-id` (f27: ssh-key — highest priority, f31)

Run **from an authorized admin workstation**, not on lnx-dmz itself:

```bash
echo ">>> $(date -u +%Y-%m-%dT%H:%M:%SZ) START | benign_ssh_key_append" >> ~/benign_fim_markers.txt  # run this line on lnx-dmz just before
ssh-copy-id -i ~/.ssh/id_ed25519_benigntest_A.pub lnx-dmz-admin@<lnx-dmz-ip>   # from the workstation
echo ">>> $(date -u +%Y-%m-%dT%H:%M:%SZ) END | benign_ssh_key_append" >> ~/benign_fim_markers.txt  # back on lnx-dmz
```
Use a **freshly generated, dedicated test keypair** (`ssh-keygen -t ed25519 -f
~/.ssh/id_ed25519_benigntest_A -N ""`) — do not reuse a real admin's actual
key. Append to a regular user's `authorized_keys` (not `/root/.ssh/`) if
policy prefers not to touch root's key file for a test; both paths are
confirmed monitored. Expected: rule 550 (modified, if the file already
exists) or rule 554 (added, if it doesn't yet). This is the single
highest-priority block — it's the only source of a genuine benign f31=0
(key added, not tampered) example. Session B: generate and append a
different dedicated test keypair (`_benigntest_B`).

### Block 4 — systemd unit edit/add + daemon-reload (f27: systemd)

```bash
echo ">>> $(date -u +%Y-%m-%dT%H:%M:%SZ) START | benign_systemd_add" >> ~/benign_fim_markers.txt
sudo tee /etc/systemd/system/fim-benign-test-A.service <<'EOF'
[Unit]
Description=FIM benign collection test unit A (inert)

[Service]
Type=oneshot
ExecStart=/bin/true

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
echo ">>> $(date -u +%Y-%m-%dT%H:%M:%SZ) END | benign_systemd_add" >> ~/benign_fim_markers.txt
# cleanup after the alert has fired:
sudo rm /etc/systemd/system/fim-benign-test-A.service && sudo systemctl daemon-reload
```
Expected: rule 554 (added), then rule 553 (deleted) on cleanup. Do not
`enable`/`start` the unit — creation + daemon-reload is enough to fire FIM;
no need to actually run it. Session B filename:
`fim-benign-test-B.service`.

### Block 5 — legitimate line in `/etc/profile.d/` (f27: shell-rc)

```bash
echo ">>> $(date -u +%Y-%m-%dT%H:%M:%SZ) START | benign_profile_d_add" >> ~/benign_fim_markers.txt
echo "# fim-benign-test-A: alias ll='"'"'ls -la'"'"'" | sudo tee /etc/profile.d/fim-benign-test-A.sh
echo ">>> $(date -u +%Y-%m-%dT%H:%M:%SZ) END | benign_profile_d_add" >> ~/benign_fim_markers.txt
# cleanup after the alert has fired:
sudo rm /etc/profile.d/fim-benign-test-A.sh
```
Expected: rule 554 (added), then rule 553 (deleted) on cleanup.

**Optional, unconfirmed — verify live before relying on it:**
```bash
echo "# fim-benign-test-A" >> ~/.bashrc
```
If this does NOT produce an alert within ~60s, skip it — it means home
directories outside `.ssh/` aren't watched, and no amount of retrying will
change that; note it as a coverage gap for f27's shell-rc class rather than a
collection failure.

### Block 6 — legitimate useradd/usermod (f27: account-mgmt, the v9 amendment class)

```bash
echo ">>> $(date -u +%Y-%m-%dT%H:%M:%SZ) START | benign_useradd" >> ~/benign_fim_markers.txt
sudo useradd -m benigntest_fim_a
sudo usermod -aG users benigntest_fim_a
echo ">>> $(date -u +%Y-%m-%dT%H:%M:%SZ) END | benign_useradd" >> ~/benign_fim_markers.txt
# cleanup after alerts have fired:
sudo userdel -r benigntest_fim_a
```
Expected: rule 5901 and/or 5902 (group/user added), plus rule 550/553/554 on
`/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/gshadow`, `/etc/subuid`,
`/etc/subgid` and their `-`/`.lock` variants — this is exactly the incidental
side-effect pattern already confirmed in the attack data, now captured as
genuinely benign. Session B account name: `benigntest_fim_b`.

### Session end

```bash
echo ">>> $(date -u +%Y-%m-%dT%H:%M:%SZ) EXPORT_TO | note_this_time_plus_30min_for_export" >> ~/benign_fim_markers.txt
echo ">>> $(date -u +%Y-%m-%dT%H:%M:%SZ) BENIGN_FIM_DONE tag=benign_fim_A" >> ~/benign_fim_markers.txt
sudo cp /var/log/audit/audit.log ~/collection_$(date +%F)/audit_fim_A.log
```

Then on SOC-Wazuh: `./extract_agent.sh 003 <START-UTC> <END-UTC> benign_fim_A`
(substitute the actual wrapper name if different; window = block-0 EXPORT_FROM
time minus nothing extra needed beyond the marker timestamps themselves, since
this is a manual live session, not a scripted replay — just use the literal
BENIGN_FIM_START/DONE timestamps ±5 min margin for the export window).

---

## Post-session verification (run immediately after export, before sending me the files)

```bash
# 1. Marker presence and count
grep -c '^>>>' ~/benign_fim_markers.txt   # expect 20+ lines (6 activities x ~2-3 markers + start/end)

# 2. Expected minimum alert counts per rule (adjust jq path to your export format)
jq -r '.rule.id' benign_fim_A_alerts.json | sort | uniq -c | sort -rn
# Expect at minimum: 550 >= 4, 554 >= 3, 553 >= 3, 5901/5902 >= 1 each, plus the
# passwd/shadow/group family from block 6 (6-10+ alerts)

# 3. All alert timestamps fall inside [BENIGN_FIM_START, BENIGN_FIM_DONE]
jq -r '.timestamp' benign_fim_A_alerts.json | sort | head -1   # >= START marker
jq -r '.timestamp' benign_fim_A_alerts.json | sort | tail -1   # <= END marker (+ ~80s ingestion lag)

# 4. UTC-offset / mtime_after sanity check (the timezone-bug class flagged in
#    verify_labels_lnx.py section 2.5 -- re-check here, do not assume it stays fixed)
#    For each syscheck alert, compare alert.timestamp to syscheck.mtime_after:
jq -r 'select(.syscheck.mtime_after != null) | "\(.timestamp)  \(.syscheck.mtime_after)  \(.syscheck.path)"' benign_fim_A_alerts.json
#    The two times should be within ~0-80s of each other (normal ingestion lag).
#    A CONSTANT offset of exactly 1, 2, or 3 hours across every row is the known
#    local-vs-UTC bug -- report it, do not silently adjust.

# 5. Marker-to-alert correlation spot check (pick 2-3 activities)
#    For block 3 (ssh-copy-id), confirm an alert with syscheck.path containing
#    "authorized_keys" appears within ~80s of the block's START/END markers.
```

Report back: the marker file, the raw alert export (JSON), the raw
`audit_fim_A.log`, and the output of the five verification commands above.
I'll run Phase 2's ingestion and coverage re-check on what you send.
