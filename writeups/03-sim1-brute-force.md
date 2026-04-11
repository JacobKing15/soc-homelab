# Sim 1: SMB Brute Force Attack & Detection
**Date:** 2026-04-10  
**Category:** Attack Simulation  
**Lab:** Proxmox — Kali (192.168.1.102) → Win10-Victim (192.168.1.101)  
**MITRE ATT&CK:** T1046 (Network Service Discovery), T1110.001 (Brute Force: Password Guessing)

---

## Goal

Simulate a credential brute force attack over SMB from Kali Linux against a domain-joined Windows 10 machine, then verify detection and investigate the alerts in Wazuh SIEM.

---

## Environment

| Machine | Role | IP |
|---------|------|----|
| Kali Linux (VM 103) | Attacker | 192.168.1.102 |
| Win10-Victim (VM 102) | Target | 192.168.1.101 |
| Wazuh SIEM (VM 100) | Detection | 192.168.1.95 |
| DC01 / lab.local | Domain Controller | 192.168.1.100 |

Target account: `LAB\jsmith` (intentionally weak password — lab environment)

---

## Phase 1: Reconnaissance

Started with an Nmap scan to identify open ports on the target.

```bash
nmap -sV 192.168.1.101
```

**Initial result:** Only port 135 open. Ports 445 (SMB) and 3389 (RDP) were blocked.

**Fix:** Windows Firewall was enabled. Disabled it on Win10-Victim via PowerShell:

```powershell
Set-NetFirewallProfile -Profile Domain,Private -Enabled False
```

Re-ran Nmap — ports 135, 139, and 445 now open.

![445](https://github.com/user-attachments/assets/4eef0d38-61a9-4d02-b03a-51b731601164)


---

## Phase 2: Brute Force Attack

**Tool: Metasploit — smb_login module**

First attempt with Hydra failed — Hydra doesn't handle modern SMBv2/v3. Switched to Metasploit.

```bash
msfconsole -q
use auxiliary/scanner/smb/smb_login
set RHOSTS 192.168.1.101
set SMBUser jsmith
set PASS_FILE /usr/share/wordlists/rockyou.txt
set VERBOSE false
run
```

Metasploit iterated through rockyou.txt, attempting each password via SMB authentication against the target.

<img width="1458" height="330" alt="Screenshot 2026-04-10 002554" src="https://github.com/user-attachments/assets/2fd657f8-7c1c-48d1-8c9d-7a2112e5e25d" />

---

## Phase 3: Wazuh Detection — Real Time

Switched to the Wazuh Threat Hunting dashboard filtered to Win10-Victim (agent 002) while the attack ran.

**What Wazuh caught:**
- Authentication failure count spiked in real time
- Final count: **6,236 failed logon attempts (Event ID 4625)**
- Wazuh correlation rule fired: **"Multiple Windows Logon Failures" — Rule ID 60204, Severity Level 10**

![authfail](https://github.com/user-attachments/assets/8a652d2a-1b54-479c-a70f-027936e606ea)

---

## Phase 4: Forensic Investigation

Pivoted to the Events tab, filtered on `data.win.system.eventID: 4625`.

Key fields inside individual event details:

| Field | Value | Meaning |
|-------|-------|---------|
| `data.win.eventdata.ipAddress` | 192.168.1.102 | Attacker IP (Kali) |
| `data.win.eventdata.targetUserName` | jsmith | Account being attacked |
| `data.win.eventdata.logonType` | 3 | Network logon (SMB) |
| `data.win.eventdata.authenticationPackageName` | NTLM | Auth protocol used |
| `data.win.eventdata.targetDomainName` | LAB | Domain targeted |

<img width="1045" height="894" alt="Screenshot 2026-04-10 084127" src="https://github.com/user-attachments/assets/d117ab7a-f0db-4824-997e-4dd93df3af25" />

### Confirming Successful Logon

Ran a direct authentication test to confirm the password was found:

```bash
crackmapexec smb 192.168.1.101 -u jsmith -p 'Password1!'
```

Wazuh logged a **successful logon — Event ID 4624, Logon Type 3** from the same source IP.

<img width="956" height="855" alt="4264 success" src="https://github.com/user-attachments/assets/5ff177dd-7e3b-47dc-9216-eb7253f1f57e" />

---

## Errors & Fixes

| Problem | Root Cause | Fix |
|---------|-----------|-----|
| Nmap only showed port 135 | Windows Firewall blocking SMB/RDP | Disabled via PowerShell |
| Hydra SMB failed with "invalid reply" | Hydra doesn't support SMBv2/v3 | Switched to Metasploit smb_login |
| CrackMapExec treated wordlist path as literal password | Used lowercase `-p` (single password) instead of `-P` (file) | Switched to Metasploit instead |

---

## MITRE ATT&CK Mapping

| Technique | ID | What Happened |
|-----------|----|---------------|
| Network Service Discovery | T1046 | Nmap scan to identify open ports before attack |
| Brute Force: Password Guessing | T1110.001 | Metasploit smb_login iterating rockyou.txt against jsmith |

---

## Key Takeaways

1. **Windows Firewall matters.** Port 445 wasn't reachable until the firewall was disabled — a good reminder that reducing attack surface starts with keeping unnecessary ports closed.

2. **SIEMs detect patterns, not just events.** Individual 4625 events are low severity. It's the correlation rule ("Multiple Windows Logon Failures" — 6,236 in a short window) that fires the high-severity alert. That's what a real analyst would action.

3. **Forensic pivoting tells the full story.** The Wazuh dashboard shows you something happened. The event detail tells you exactly who, from where, using what method — attacker IP, target account, auth protocol, logon type. That's the difference between knowing there was an incident and being able to respond to it.

---

## What an Analyst Would Do Next

1. Block source IP (192.168.1.102) at the firewall
2. Disable or reset the `jsmith` account immediately
3. Check for Event ID 4624 from the same source — did the brute force succeed? (It did)
4. If successful logon confirmed: begin incident response — what did the attacker do after logging in?
5. Document findings, escalate per severity![445](https://github.com/user-attachments/assets/1d4894f1-76d4-4aa3-95d7-c2d828d287e7)
