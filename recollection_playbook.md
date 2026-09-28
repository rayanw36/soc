# Re-collection Playbook — SOC Triage Provenance Labeling

**Purpose:** Specify exactly what must be enabled and logged before the next
Atomic Red Team run so that `provenance_label.py` can produce HIGH-confidence
labels (process-tree anchored), Phase 2 can be completed, and Phase 3 validation
can be re-run on trustworthy ground truth.

Estimated effort to implement: 2–3 hours of testbed setup before the next run.

---

## 1. Linux host (lnx-dmz)

### 1a. Enable raw auditd logging for process + network provenance

Add the following rules to `/etc/audit/rules.d/atomictest.rules` before the run:

```bash
# Capture all process execution (EXECVE syscall + arg list)
-a always,exit -F arch=b64 -S execve -k atomictest_exec
-a always,exit -F arch=b32 -S execve -k atomictest_exec

# Capture socket connects (network provenance, replaces SOCKADDR guess)
-a always,exit -F arch=b64 -S connect -k atomictest_net
-a always,exit -F arch=b32 -S connect -k atomictest_net

# Capture file opens to sensitive paths
-a always,exit -F arch=b64 -S open,openat -F path=/etc/shadow -k sensitive_path
-a always,exit -F arch=b64 -S open,openat -F path=/etc/passwd -k sensitive_path
-a always,exit -F arch=b64 -S open,openat -F path=/etc/sudoers -k sensitive_path

# Reload: augenrules --load && systemctl restart auditd
```

### 1b. Archive raw auditd logs, NOT just Wazuh output

```bash
# Before the run: start a secondary capture to a dedicated file
auditd -f -l >> /var/log/atomictest_auditd.log &
# OR: copy /var/log/audit/audit.log after the run completes.
# The critical thing: preserve the raw audit.log, not just Wazuh-processed output.
# Wazuh processes auditd events into Wazuh alerts but drops pid/ppid/SOCKADDR.
```

### 1c. Record the pwsh/bash root PID at each test launch

Modify the Atomic Red Team invocation wrapper to emit the root PID:

```bash
# In your run script, for each technique:
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) START ${TECHNIQUE} ${NAME} root_pid=$$" >> attack_log.txt
pwsh -Command "Invoke-AtomicTest ${TECHNIQUE} -ExecutionLogPath /tmp/atomic_${TECHNIQUE}.log" &
ROOT_PID=$!
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) ROOT_PID ${TECHNIQUE} pid=${ROOT_PID}" >> attack_log.txt
wait $ROOT_PID
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) END ${TECHNIQUE} ${NAME}" >> attack_log.txt
```

### 1d. Capture tool source ports

```bash
# For each tool that opens a network connection, record the source port:
# Example for SSH brute force (T1110.001) with Hydra:
ss -tnp 'sport > 1024' > /tmp/tool_ports_${TECHNIQUE}.txt
# Or: strace -e trace=connect -p $ROOT_PID 2>&1 | grep -oP 'sin_port=\K\d+'
```

---

## 2. Windows host (WIN-CL1)

### 2a. Keep Sysmon running (already enabled — do not change)

Sysmon EID-1 (process creation) with ProcessGuid/ParentProcessGuid is already
configured and working. **Do not disable it.** Ensure the Sysmon configuration
captures: EID 1, EID 3 (network), EID 11 (file create), EID 13 (registry).

### 2b. Write attack_log.txt with START/END technique markers

Mirror the Linux `attack_log.txt` format exactly:

```powershell
# In the PowerShell run wrapper:
$utc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
Add-Content attack_log_win.txt "$utc START $TechniqueId $TechniqueName"
$proc = Start-Process pwsh -ArgumentList "-Command `"Invoke-AtomicTest $TechniqueId`"" -PassThru
Add-Content attack_log_win.txt "$utc ROOT_GUID ???"  # fill in below
Wait-Process -Id $proc.Id
$utc2 = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
Add-Content attack_log_win.txt "$utc2 END $TechniqueId $TechniqueName"
```

### 2c. Record the pwsh root ProcessGuid per technique

```powershell
# Immediately after spawning the pwsh process, query Sysmon for its GUID.
# Wait ~200ms for Sysmon to log EID 1, then query the Sysmon operational log:
Start-Sleep -Milliseconds 200
$guid = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
    Where-Object { $_.Id -eq 1 } |
    Select-Object -First 1 |
    ForEach-Object { ([xml]$_.ToXml()).Event.EventData.Data |
        Where-Object { $_.Name -eq 'ProcessGuid' } | Select-Object -Exp '#text' }
Add-Content attack_log_win.txt "$(date -u ...) ROOT_GUID $TechniqueId guid=$guid"
```

### 2d. Capture tool source ports

```powershell
# For each tool: netstat -n immediately after launch
Get-NetTCPConnection -State Established |
    Where-Object { $_.OwningProcess -eq $proc.Id -or $proc.Id -in (
        Get-WmiObject Win32_Process | Where-Object { $_.ParentProcessId -eq $proc.Id }
    ).ProcessId } |
    Select-Object LocalPort, RemoteAddress, RemotePort |
    Export-Csv tool_ports_$TechniqueId.csv
```

---

## 3. Both platforms — export alignment fix

The single largest data quality problem from Phase 0 is that the exported Wazuh
alert files cover different time ranges than the defined attack windows.

### Fix the Wazuh alert export window

```bash
# WRONG (what happened in 2025-11-23 run):
#   exported ossec-alerts-23.json covers 19:05–23:58
#   WINDOWS_ATTACK_WINDOWS window 1 is 16:15–19:45
#   → only 40 min of 90-min window has alert data

# CORRECT:
#   Export should START at least 30 min BEFORE the first technique starts
#   and END at least 30 min AFTER the last technique ends.
#
# For Linux (attack_log.txt covers 13:27–18:22 UTC):
#   Export window: 2026-05-25T13:00:00Z to 2026-05-25T19:00:00Z
#
# For Windows (next run):
#   Export window: start - 30m to end + 30m
#
# Wazuh export command:
wazuh-logtest -T -j -q \
  -f /var/ossec/logs/alerts/alerts.log \
  --from "2026-05-25T13:00:00" --to "2026-05-25T19:00:00" \
  > ossec-alerts-attack-day.json
```

---

## 4. Technique selection — deliberately include novel-rule techniques

Phase 1 showed that T1548.001, T1548.003, and T1003.008 all fire Wazuh rules
(5401/5402/5501/5502) that ALSO appear in AIT-ADS privilege_escalation training
windows. The model can detect these but it's ambiguous whether this is genuine
novelty or training-rule memorization.

For the next run, **add at least two techniques whose Wazuh rules are ABSENT from
AIT-ADS entirely** — rule IDs that never appear in the dirb/wpscan/cracking/etc.
windows:

| Technique | Expected Wazuh rules | AIT-ADS presence |
|-----------|----------------------|------------------|
| T1053.003 | 2832 (cron changed)  | ABSENT ← keep this |
| T1136.001 | 5902 (new user added) | ABSENT ← currently empty window |
| T1070.003 | audit/history clear   | ABSENT ← currently empty window |
| T1059.004 | 5xxx (reverse shell)  | Some via AIT-ADS reverse_shell |

**Ensure the following currently-empty windows fire at least 1 alert:**
- T1136.001 (create local user): verify `useradd` triggers rule 5902
- T1070.003 (clear bash history): verify `history -c` triggers an auditd alert
- T1059.004 (reverse shell): check which Wazuh rules fire on Linux; add to attack_log.txt

### Running T1136.001 / T1070.003 diagnostic before the run

```bash
# Quick smoke test on the live lnx-dmz to verify Wazuh coverage:
useradd testuser_atomiccheck && sleep 5 && userdel testuser_atomiccheck
# Check: tail -n 20 /var/ossec/logs/alerts/alerts.json | grep -E '"rule"'
# Expected: rule 5902 (new user added) should appear

history -c && sleep 5
# Check: rule 2850 or similar audit alert for history clear
```

---

## 5. Checklist before the next run

- [ ] auditd rules loaded (`augenrules --load`; verify `auditctl -l` shows execve + connect)
- [ ] Raw `audit.log` backup target confirmed (`/var/log/atomictest_auditd.log`)
- [ ] Wazuh export start time set to (first-technique-start − 30 min)
- [ ] `attack_log.txt` wrapper logs `root_pid` for each technique (Linux)
- [ ] `attack_log_win.txt` wrapper logs `ROOT_GUID` for each technique (Windows)
- [ ] Tool source ports captured per technique (`tool_ports_${TECH}.csv`)
- [ ] T1136.001 and T1070.003 smoke-tested to produce Wazuh alerts
- [ ] Export alignment verified: `ossec-alerts-attack-day.json` covers full attack window ± 30 min
- [ ] Wazuh alert files do NOT truncate mid-session (check log rotation during the run)

---

*Generated by `provenance_label.py` / Phase 2C — to be executed before testbed re-activation (~1 month).*
