# Sim 3 — Remote Persistence via Pass-the-Hash
**Date:** 2026-05-21
**MITRE ATT&CK:** T1053.005 (Scheduled Task/Job) + T1547.001 (Registry Run Keys)
**Tools:** CrackMapExec, Kali Linux, Wazuh SIEM

---

## What I Was Trying to Do

Following Sims 1 and 2, the attacker has valid credentials and domain access. The goal of this simulation was to establish persistence — mechanisms that survive a reboot and maintain access without re-exploiting the initial foothold.

Two techniques were used:
- A scheduled task disguised as a Windows update helper
- A registry run key under the current user's hive

Both were planted remotely from Kali using a stolen NTLM hash, without ever opening an interactive session on the target.

---

## Attack

**Environment:**
- Attacker: Kali Linux (192.168.1.102)
- Target: Win10-Victim (192.168.1.101) — domain-joined, lab.local
- Credential: jsmith NTLM hash from Sim 2 (7facdc498ed...a8c04f)

**Plant scheduled task:**
<img width="1280" height="529" alt="crackmapexec2" src="https://github.com/user-attachments/assets/d6f178a2-6bec-4334-a5af-3b70f6405640" />

**Plant registry run key:**
<img width="1280" height="868" alt="pers1" src="https://github.com/user-attachments/assets/c144354e-8174-4cd5-8ff7-5774b6d289e7" />

---

## Verify Persistence (Post-Reboot)

Win10-Victim was rebooted. Both mechanisms were queried remotely from Kali — no interactive login required.

<img width="1280" height="877" alt="persistance3" src="https://github.com/user-attachments/assets/723dccf5-e693-4c6c-b787-a65fb34f9d33" />

Both survived the reboot. Persistence confirmed.

---

## Detection — What Wazuh Saw

**Baseline (before attack):**
<img width="1280" height="605" alt="baseline" src="https://github.com/user-attachments/assets/e9564871-c51e-4305-8817-9c8b5c520014" />

**During attack:**
<img width="1280" height="532" alt="pers2" src="https://github.com/user-attachments/assets/d5639c49-d492-4b4e-bba3-d1a02232a6a9" />

**Alert detail:**
<img width="959" height="861" alt="wazuhinvest" src="https://github.com/user-attachments/assets/44e937f5-ceb1-45b8-9465-7bb0090ea714" />

Wazuh fired **Rule 92652** — "Successful Remote Logon Detected - User:jsmith - NTLM authentication, possible pass-the-hash attack" — for every CME execution, including the verification queries after reboot.

**Detection gap:** Wazuh caught the PTH authentication pattern but did not generate a specific alert for the scheduled task creation (Event ID 4698) or the registry modification. The attack method was flagged; the payload was not.

---

## What a SOC Analyst Would Do

Seeing Rule 92652 with source IP 192.168.1.102 (a workstation) authenticating to another workstation over SMB via NTLM is a high-priority finding. Steps:

1. Isolate Win10-Victim immediately
2. Check for scheduled tasks and registry run keys under all user hives
3. Pull process tree from EDR — look for cmd.exe spawned by task scheduler
4. Review all logons from 192.168.1.102 across the environment
5. Assume lateral movement has occurred — scope the full incident

---

## What This Teaches Defenders

- PTH-based authentication generates NTLM Type 3 logons that Wazuh detects out of the box
- Scheduled tasks and registry run keys are common persistence mechanisms — enable Sysmon Event ID 4698 logging and audit registry changes to detect them
- Detection of the authentication is not the same as detection of what the attacker did with that access
