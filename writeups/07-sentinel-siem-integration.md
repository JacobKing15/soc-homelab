# SIEM Integration: Forwarding Wazuh to Microsoft Sentinel + First Analytics Rule
**Date:** 2026-08-14 to 2026-08-25
**Category:** SIEM Integration / Detection Engineering
**Lab:** Wazuh manager (192.168.1.95) → Azure Monitor Agent → Microsoft Sentinel (sentinel-lab-workspace)
**MITRE ATT&CK:** T1110 (Brute Force) — for the analytics rule built at the end

---

## Goal

Forward real Wazuh alerts from the home lab into Microsoft Sentinel so they're queryable with KQL, then build an actual Sentinel analytics rule that recreates the Sim 1 brute-force detection — turning a one-off manual investigation into a standing, auto-firing detection.

This wasn't a tutorial follow-along. Every non-trivial step below came from debugging a real failure with real evidence, not copy-pasting a guide.

---

## Environment

| Component | Role |
|---|---|
| Wazuh manager (192.168.1.95) | Alert source, formats output as CEF |
| rsyslog | Local listener on the Wazuh VM, receives CEF over UDP/TCP 514 |
| Azure Monitor Agent (AMA) | Relays received syslog to Azure over port 28330 |
| Azure Arc | Registers the Wazuh VM as a managed Azure resource (`wazuh-server`) |
| Entra ID service principal (`arc-onboarding-sp`) | Non-human identity used to authenticate the Arc onboarding, scoped only to `sentinel-lab-rg` |
| Microsoft Sentinel (`sentinel-lab-workspace`) | Destination — CEF via AMA connector, Data Collection Rule, `CommonSecurityLog` table |

---

## Phase 1: Onboarding the Wazuh VM to Azure Arc

Sentinel's "CEF via AMA" connector requires non-Azure machines to be Arc-enabled before it will accept them as a data collection target. Ran the standard onboarding script via `azcmagent connect` using an interactive login.

**Failure:** Every attempt returned "You don't have access to this — your sign-in was successful but you don't have permission to access this resource," Error Code 530035.

Two dead-end theories were ruled out with real evidence before finding the actual cause:
- Checked `Microsoft.HybridCompute` resource provider registration — it was un-registered, registered it, re-tested. Same error.
- Retried in a clean incognito browser session to rule out a cached-account conflict. Same error.

**Root cause, found via Entra ID → Sign-in logs:** the failed sign-in event showed `Original transfer method: Device code flow` and a Conditional Access policy detail with `Result: Failure`, `Grant Controls: Block`. Azure's **Security Defaults** — a baseline enabled automatically on personal/free tenants — explicitly blocks device code flow authentication. This is deliberate hardening against device-code phishing, not a bug or misconfiguration.

**Fix:** azcmagent's own documented pattern for headless Linux servers is service principal authentication instead of interactive login — this is the *recommended* method, not a workaround.
1. Created an Entra ID App Registration (`arc-onboarding-sp`)
2. Generated a client secret
3. Assigned it the **Azure Connected Machine Onboarding** role, scoped only to the `sentinel-lab-rg` resource group (least privilege — this identity can't touch anything else)
4. Re-ran onboarding with `azcmagent connect --service-principal-id ... --service-principal-secret ...`

Hit one more real error along the way — `AADSTS7000215: Invalid client secret provided`, from copying the Secret ID instead of the Secret Value on the first attempt. Regenerated the secret, copied the correct field, connect succeeded: `"Connected machine to Azure"`.

<!-- Screenshot: Entra sign-in log showing Conditional Access block on device code flow -->
<!-- Screenshot: successful azcmagent connect output -->

---

## Phase 2: Building the Data Collection Rule

With the VM Arc-connected, built the CEF via AMA Data Collection Rule (`wazuh-cef-dcr`) targeting `wazuh-server`, collecting Linux syslog. No "collect everything" shortcut existed in the wizard, so each of the ~15 syslog facility rows was individually set to minimum level "Debug" to avoid silently dropping data before Wazuh's actual output facility was even configured.

Portal confirmed all three pieces succeeded: CefAma extension installed, DCR created, association linked.

---

## Phase 3: Wazuh CEF Output — the rsyslog Gap

Added the actual output config to `/var/ossec/etc/ossec.conf`:

```xml
<syslog_output>
  <server>127.0.0.1</server>
  <port>514</port>
  <format>cef</format>
</syslog_output>
```

Restarted `wazuh-manager`. Immediately started seeing repeated errors in `ossec.log`:

```
wazuh-csyslogd: ERROR: (5302): Error sending message to '127.0.0.1'.
```

**Investigation, not guessing:**
1. `sudo ss -tulnp | grep ":514 "` — nothing listening on port 514 at all.
2. Confirmed AMA itself was running (`systemctl status azuremonitoragent` — active) and confirmed rsyslog was running too — both healthy independently.
3. Found `/etc/rsyslog.d/10-azuremonitoragent-omfwd.conf` — AMA's installer had correctly configured the *forward to mdsd on 127.0.0.1:28330* half of the pipeline.
4. `grep -A2 "imudp\|imtcp" /etc/rsyslog.conf` — found the actual gap: `$ModLoad imudp`, `$UDPServerRun 514`, `$ModLoad imtcp`, `$InputTCPServerRun 514` were all commented out in rsyslog's main config.

**Root cause:** rsyslog ships with network listening disabled by default, for security reasons (a distro shouldn't silently open a network port just because a package installed). AMA's installer sets up the outbound forwarding side automatically but can't safely assume every machine should also accept inbound network syslog — that's left as a deliberate manual step.

**Fix:** uncommented the four lines, restarted rsyslog, confirmed via `ss -tulnp` that rsyslogd was now bound to UDP+TCP 514. Wazuh's send errors stopped immediately and stayed stopped.

**Verification, not assumption:** ran `CommonSecurityLog | take 10` in Sentinel Logs. Real rows came back — `DeviceVendor: Wazuh Inc.`, `DeviceProduct: Wazuh v4.10.2`, real activity (Windows Logon Success/Logoff, PAM session events, sudo execution) — confirmed the full chain end to end, not just "no more errors."

<!-- Screenshot: ossec.conf syslog_output block -->
<!-- Screenshot: ss -tulnp showing rsyslogd bound to :514 before/after -->
<!-- Screenshot: CommonSecurityLog | take 10 showing real Wazuh rows -->

---

## Phase 4: Live-Fire Test — Attack to Detection, End to End

Re-ran the Sim 1 brute-force attack against Win10-Victim (`jsmith` account) specifically to generate real data and validate the pipeline under real conditions, not synthetic test rows.

Hydra's `smb` module failed immediately with `[ERROR] invalid reply from target` — a known compatibility issue between Hydra's older SMB module and modern SMBv2/3, not a target-side problem. Switched to CrackMapExec, which handled it cleanly:

```bash
crackmapexec smb 192.168.1.101 -u jsmith -p /usr/share/wordlists/rockyou.txt
```

**Confirmed in Sentinel within ~15 minutes:**
- Real `CommonSecurityLog` entries, Windows **Event ID 4625** (failed logon)
- `DeviceCustomString1: (Win10-Victim)` — correct source host
- **Wazuh's own correlation rule fired**: `Activity: "Multiple Windows Logon Failures"`, `LogSeverity: 10` — not just raw individual events, a real correlated detection reached Sentinel
- Tagged with real compliance-framework metadata generated automatically by Wazuh (PCI-DSS 10.2.4/10.2.5, HIPAA 164.312.b, NIST 800-53 AC.7/AC.9)

<!-- Screenshot: CommonSecurityLog query showing the live Event 4625 / Multiple Windows Logon Failures hit -->

---

## Phase 5: Building the Analytics Rule

Recreated the detection as an actual saved Microsoft Sentinel Scheduled Query Rule — the difference between "I can investigate this if I remember to check" and "Sentinel watches for this automatically and opens an incident on its own."

**Rule: "SMB Brute Force - Multiple Failed Logons"**
- MITRE ATT&CK: Credential Access / **T1110**
- Severity: Medium
- Query:
  ```kql
  CommonSecurityLog
  | where Activity has "Logon" and Activity contains "Fail"
  | summarize count() by Activity, bin(TimeGenerated, 1h)
  ```
- Schedule: runs every 1 hour, looks back 1 hour
- Threshold: alert if results > 0
- Event grouping: alert per event, incidents grouped by matching entities within a 5-hour window (prevents one ongoing attack from spawning multiple separate incidents)

**Two real KQL gotchas hit while building this, not obvious from the syntax alone:**
1. First version of the query used `Activity has "Fail"` and returned **zero results**, even though the real event definitely existed (confirmed live in Phase 4). `has` matches whole terms only — the real value is "**Failures**," and "Fail" is not a complete term inside it, so it silently didn't match. Fixed by switching to `contains`, which does true substring matching. Rule of thumb: `has` for exact whole words, `contains` for partial matches.
2. Widening the query's `bin(TimeGenerated, 1h)` grouping did nothing to surface older data during testing. The actual constraint was the rule wizard's own **"Lookup data from the last"** scheduling field (initially 5 hours) — `bin()` only groups whatever data is already in scope, it doesn't extend the time range. Temporarily widened the lookback to 7 days to validate the query against Phase 4's historical data, confirmed it worked, then set it back to a sane 1-hour production window before saving.

Validated with Sentinel's "Test with current data" simulator before saving — confirmed a real match against the Phase 4 attack data. Saved and confirmed live in the portal: **1 Active rule, Enabled.**

<!-- Screenshot: Analytics rule wizard - Review + create summary -->
<!-- Screenshot: Analytics rules list showing "1 Active rules", Enabled, T1110 -->

---

## Errors & Fixes

| Problem | Root Cause | Fix |
|---|---|---|
| Arc onboarding: Error 530035, "you don't have access" | Security Defaults blocking device code flow auth | Switched to service principal auth (also the documented best-practice for headless servers) |
| `AADSTS7000215: Invalid client secret` | Copied the Secret ID instead of the Secret Value | Regenerated secret, copied the correct field |
| `wazuh-csyslogd: Error sending message to 127.0.0.1` | rsyslog's `imudp`/`imtcp` listener modules disabled by default | Uncommented the 4 listener lines in `rsyslog.conf`, restarted rsyslog |
| Hydra SMB: "invalid reply from target" | Hydra's `smb` module doesn't handle modern SMBv2/v3 | Switched to CrackMapExec |
| KQL `has "Fail"` returned 0 results | `has` requires a whole-term match; "Fail" isn't a complete term inside "Failures" | Used `contains` instead for substring matching |
| Historical attack data missing from rule test | Confused `bin()` (groups data) with a time filter — the wizard's "Lookup data from the last" field was the real constraint | Temporarily widened the lookback to validate, reset to 1h for production |

---

## Key Takeaways

1. **A working SIEM connector is a multi-layer chain, and every layer can fail independently.** Source format, local network listener, forwarding agent, cloud-side routing, and authentication are five separate things that all have to be right — this pipeline broke at two of them (auth, and the local listener), and both had a real, findable root cause rather than a random fix.

2. **Debug with evidence, not guesses.** Every fix in this writeup came from checking logs, port bindings, or sign-in records directly (`ss -tulnp`, Entra sign-in logs, `ossec.log`) — not from trial-and-error changes made hopefully.

3. **KQL syntax has real, non-obvious gotchas that silently produce wrong (not error) results.** `has` vs `contains`, and `bin()` vs an actual time filter, both looked like they "worked" (no error message) while quietly returning the wrong answer. Worth testing a query's actual output against known-good data before trusting it in a saved rule.

4. **A detection isn't done until it's a standing rule, not a query you have to remember to run.** The whole point of a SIEM is that it watches continuously — this project didn't end at "I can query for this," it ended at "Sentinel will tell me if this happens again, without me checking."

---

## What an Analyst Would Do Next

1. Add entity mapping to the rule so incidents show structured host/account info instead of raw text fields
2. Recreate additional Sim 1-4 detections (pass-the-hash, persistence, C2 beacon) as their own Sentinel analytics rules
3. Build a KQL query specifically isolating the compliance-framework tags (PCI-DSS/HIPAA/NIST) Wazuh already generates, for audit-reporting use cases
4. Attach an automated response (Logic App playbook) to the rule — e.g., auto-notify on incident creation — once the rule's been observed running cleanly for a while
