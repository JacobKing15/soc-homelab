# Sentinel Analytics Rules Part 2: Recreating Sim 2 & Sim 4 as Live Detections
**Date:** 2026-09-04 to 2026-09-07
**Category:** Detection Engineering
**Lab:** Builds directly on the Wazuh to Sentinel pipeline from the [SIEM Integration writeup](07-sentinel-siem-integration.md). No new infrastructure needed, same `CommonSecurityLog` data source.
**MITRE ATT&CK:** T1550.002 (Pass-the-Hash), T1021.002 (Remote Services: SMB/Windows Admin Shares)

---

## Goal

The last writeup got the pipeline working and recreated one detection (Sim 1, brute force). This one closes out the rest of the sims I already had built: two more Sentinel analytics rules, each covering a different attack technique. End state I was going for: 3 live rules, 3 different MITRE techniques, one detection pipeline doing real work.

---

## Phase 1: Rule 2, NTLM Pass-the-Hash

Sim 2 (pass-the-hash lateral movement) originally ran back in April, months before the Sentinel pipeline even existed. That meant there was no historical data sitting in `CommonSecurityLog` waiting for me. I had to re-run the attack fresh with CrackMapExec against Win10-Victim to get real, current data flowing.

Query, and I deliberately filtered by Wazuh's own rule ID instead of matching text:
```kql
CommonSecurityLog
| where DeviceVendor == "Wazuh Inc." and DeviceEventClassID == "92652"
```
Filtering on `DeviceEventClassID` instead of the `Activity` text field sidesteps the whole `has` vs `contains` substring-matching bug I ran into on rule 1. A numeric rule ID either matches or it doesn't, no partial-term ambiguity to worry about.

**Rule: "NTLM Pass-the-Hash - Successful Remote Logon"**
- MITRE: T1550.002 (Use Alternate Authentication Material: Pass the Hash)
- Severity: High
- Schedule: 1h run / 1h lookback, threshold >0, per-event alerting, 5h entity-match incident grouping (same pattern as rule 1)

**Gotcha:** "Test with current data" showed 0 results even though the query returned real matches when I ran it directly in Logs. Took me a minute to figure out why. Turns out the results simulator only evaluates *completed* hourly evaluation windows, and my attack had happened just minutes earlier, still inside the current, still-in-progress hour. There was no finished evaluation cycle yet that included it. Fixed by temporarily widening "Lookup data from the last" to confirm the query matched historical data, then setting it back to 1h for production. This is related to the `bin()` lesson from the last writeup but not the same thing. That one was about the query's own time grouping, this one is about the wizard's separate scheduling field.

---

## Phase 2: Rule 3, SMB Admin Shares + Service Execution (C2 Lateral Movement)

Sim 4 (C2 beacon via impacket-psexec into Meterpreter) also predated the pipeline, so it needed a fresh replay too. This one did not go smoothly.

**Failure, same every time:** `impacket-psexec` would upload its service stub, start the service, then immediately error out with `Error performing the uninstallation, cleaning up`. No interactive shell ever showed up.

I checked Defender status directly on Win10-Victim (via the console, not through the dead psexec channel, since that gave me nothing to work with):
```powershell
Get-MpComputerStatus | Select RealTimeProtectionEnabled, AntivirusEnabled
Get-MpThreatDetection
```
`AntivirusEnabled: True`. And `Get-MpThreatDetection` returned two real quarantine entries, filenames and timestamps matching my failed attempts exactly:
- `adFMKwqe.exe` / service `LDSo`, detected 12:23:22 AM, cleaned by 12:23:35 AM (13 seconds)
- `cAAFKioC.exe` / service `tLct`, an earlier attempt, same pattern

That confirmed it with hard evidence instead of a guess: Windows Defender's real-time protection was intercepting and quarantining impacket's uploaded service stub within seconds, every single time, before a shell could ever get established.

Fix, and I want to be clear this is lab-appropriate, not production-appropriate:
```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
```
Ran that as admin on Win10-Victim, which is a controlled lab box, not a production host. A hardened real target would need actual AV evasion, which is a different exercise than this one.

Once real-time protection was off, the whole chain worked end to end: `msfvenom`-generated `beacon.exe` served from a local HTTP server, `impacket-psexec` got me a real Windows shell, a PowerShell one-liner from inside that shell downloaded and executed `beacon.exe`, and the Meterpreter session opened successfully on my `multi/handler`.

Query:
```kql
CommonSecurityLog
| where DeviceVendor == "Wazuh Inc." and DeviceEventClassID == "92650"
```

**Rule: "SMB Admin Shares + Service Execution (C2 Lateral Movement)"**
- MITRE: T1021.002 (Remote Services: SMB/Windows Admin Shares)
- Severity: High
- Schedule: 1h / 1h, threshold >0, per-event alerting, 5h entity-match grouping

---

## Errors & Fixes

| Problem | Root Cause | Fix |
|---|---|---|
| `impacket-psexec` uninstall error, zero shell, every attempt | Windows Defender real-time protection quarantining the uploaded service stub in about 13 seconds (confirmed via `Get-MpThreatDetection`, filenames/timestamps matched exactly) | `Set-MpPreference -DisableRealtimeMonitoring $true` on the lab VM |
| Rule 2's "Test with current data" showed 0 results despite real matching data existing | Results simulation only evaluates completed hourly windows; my attack landed inside the still-in-progress current hour | Temporarily widened "Lookup data from the last," confirmed the match, reset to 1h for production |

---

## Key Takeaways

1. **A working pipeline doesn't backfill history.** Data only exists from the moment the pipeline went live. Recreating an older sim as a Sentinel detection means replaying the attack fresh, not querying for old data that was never captured in the first place.
2. **Endpoint protection is part of the story, not just an obstacle.** Defender catching the payload before Wazuh or Sentinel ever saw anything, with a measured 13-second detection-to-quarantine window, is a real finding worth writing down, not just a lab annoyance I disabled and moved past.
3. **Filter by the source SIEM's own rule ID, not free text.** `DeviceEventClassID` is exact match. `Activity` text matching inherits a whole class of substring bugs (`has` vs `contains`) for free. Once bitten, I'm reaching for the numeric identifier from now on.
4. **A "0 results" test doesn't always mean a broken query.** The Analytics Rule wizard's simulator has its own scheduling quirks, separate from whether the underlying KQL is actually correct. Worth verifying against older, settled data before trusting a zero.

---

## What I'd Do Next

1. Add entity mapping to rules 2 and 3 (still optional, same as rule 1)
2. Go back to the still-open Sim 3 persistence-detection gap (scheduled task creation and registry Run key mods never made it into Wazuh's alert stream in the first place). Would need native Windows Security Event auditing (4698/4657) to supplement Wazuh's alert-only CEF forwarding
3. Build a KQL query pulling Wazuh's own auto-generated compliance-framework tags (PCI-DSS/HIPAA/NIST) across all 3 rules, good practice for audit reporting
4. Attach an automated response (Logic App playbook) once all 3 rules have been running cleanly for a while

---

**Result: 3 live Sentinel analytics rules, 3 different MITRE techniques (T1110, T1550.002, T1021.002), one real detection pipeline.**
