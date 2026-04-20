# Sim 2: Pass-the-Hash / Lateral Movement

**Date:** 2026-04-18
**Attacker:** Kali Linux (192.168.1.102)
**Targets:** Win10-victim (192.168.1.101) → DC01 (192.168.1.100)
**MITRE ATT&CK:** T1021.002 · T1003.002 · T1003.003 · T1550.002

---

## Goal

Starting from valid domain credentials (jsmith / Password1!) obtained in [Sim 1](03-sim1-brute-force.md), the goal was to:

1. Get a shell on Win10-victim
2. Dump NTLM hashes from DC01
3. Authenticate to DC01 using only the hash — no password required

This simulates an attacker who has stolen credentials and wants to move laterally through a domain without ever cracking a password.

---

## Environment

| Machine | IP | Role |
|---|---|---|
| Kali Linux | 192.168.1.102 | Attacker |
| Win10-victim | 192.168.1.101 | Initial target, domain-joined (lab.local) |
| DC01 | 192.168.1.100 | Domain Controller — ultimate target |

---

## What I Tried First (and Why It Failed)

### Attempt 1: Metasploit psexec

The plan was to use Metasploit's `exploit/windows/smb/psexec` to get a reverse shell on Win10-victim.

**Problem 1 — STATUS_LOGON_FAILURE**
jsmith wasn't in the local Administrators group on Win10-victim. Fix: added jsmith to local Administrators via DC01.

**Problem 2 — ACCESS_DENIED on service start**
Even as a local admin, psexec was blocked by UAC token filtering. Remote connections from domain accounts don't get a full admin token by default. Fix: set `LocalAccountTokenFilterPolicy = 1` in the registry and rebooted.

```cmd
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
```

<img width="1280" height="893" alt="psexecerror1" src="https://github.com/user-attachments/assets/ca49648c-b78f-4613-be62-fc631481180a" />



**Problem 3 — STATUS_VIRUS_INFECTED**
After fixing UAC, Metasploit's psexec uploads a payload exe to the target. Windows Defender caught it immediately, even with "real-time protection" turned off in settings. The reason: turning off real-time protection isn't the same as disabling tamper protection. Tamper protection must be explicitly disabled first (Windows Security → Virus & threat protection settings).

<img width="1280" height="868" alt="STATUSVIRUS" src="https://github.com/user-attachments/assets/70abeae1-273b-46cc-bcc9-c0ffcc12f715" />


**Decision:** psexec was too noisy and required too many pre-conditions. Switched tools.

---

### Attempt 2: LSASS Memory Dump (comsvcs.dll method)

LSASS (Local Security Authority Subsystem Service) holds live NTLM hashes in memory for currently logged-in users. The plan was to dump it using a built-in Windows DLL:

```cmd
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <LSASS_PID> C:\Windows\Temp\lsass.dmp full
```

The file was never created. Defender tamper protection blocked the LSASS read entirely.

<img width="1280" height="823" alt="LSASSscreenshot" src="https://github.com/user-attachments/assets/c39381df-1822-4a81-be69-d324fe2cd453" />


**Key lesson:** Tamper protection ≠ real-time protection. Two separate settings. This is intentional — Microsoft hardened LSASS access specifically because credential dumping is so common.

---

### Attempt 3: secretsdump on Win10-victim

Ran Impacket's secretsdump remotely against Win10-victim to pull SAM hashes:

```bash
impacket-secretsdump 'lab.local/jsmith:Password1!@192.168.1.101'
```

Got SAM hashes back — but jsmith's credential showed up as:

```
LAB.LOCAL/jsmith:$DCC2$10240#jsmith#bf61dccadc3f1e237d7b4fce651de0ad:::
```

That's **DCC2 — Domain Cached Credentials**, not NTLM. Windows caches domain logon credentials locally so users can log in when the DC is unreachable. DCC2 is a completely different format and **cannot be used for Pass-the-Hash**. It requires offline cracking to recover the plaintext password.

<img width="1280" height="849" alt="DCC2dump" src="https://github.com/user-attachments/assets/aef84efa-cbed-49b0-9663-038311c04656" />


**Key lesson:** secretsdump on a workstation gives you cached credentials, not live NTLM. For Pass-the-Hash you need NTLM — which lives in LSASS memory or NTDS.dit on the DC.

---

## What Actually Worked

### Step 1 — Initial Shell via WMI

Switched to `impacket-wmiexec` — executes commands through Windows Management Instrumentation instead of creating a service like psexec. No exe upload, no reverse connection, Defender doesn't catch it.

```bash
impacket-wmiexec 'lab.local/jsmith:Password1!@192.168.1.101'
```

Result: semi-interactive shell as `lab\jsmith`.

<img width="1280" height="756" alt="impacket-wmiexec" src="https://github.com/user-attachments/assets/7e44e69f-2721-49d2-b294-4a82bd9cfdde" />


**Why this works when psexec doesn't:** psexec works by creating a Windows service on the target (noisy, requires service start rights, uploads an exe that AV can catch). WMI executes through the Windows management interface — it looks like legitimate admin activity. No service created, no exe on disk.

---

### Step 2 — Escalate jsmith to Domain Admin

From RDP on DC01 (logged in as Administrator):

```cmd
net user Administrator NewPassword1!
net group "Domain Admins" jsmith /add
net group "Domain Admins"
```

<img width="881" height="468" alt="image" src="https://github.com/user-attachments/assets/101e9782-34c1-4bf3-ae10-ccc55efa8baf" />


Output confirmed: `Administrator, jsmith` are both Domain Admins.

*(In a real engagement this step would be unnecessary — the goal would be to find a domain admin account through credential access. In this lab, jsmith started as a regular user so escalation was set up manually to simulate already having DA access.)*

---

### Step 3 — Dump NTDS.dit from DC01

With jsmith as domain admin, ran secretsdump against the domain controller:

```bash
impacket-secretsdump 'lab.local/jsmith:Password1!@192.168.1.100'
```

This dumps **NTDS.dit** — the Active Directory database stored on every domain controller. It contains NTLM hashes for every domain account.

Got every domain account's hash, including:

```
lab.local\jsmith:1104:aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f:::
```

The hash after the third colon (`7facdc498ed1680c4fd1448319a8c04f`) is jsmith's NTLM hash.

<img width="1410" height="643" alt="Screenshot 2026-04-18 001124" src="https://github.com/user-attachments/assets/c6c868a1-b072-4a02-a814-e5bd7a09022d" />


---

### Step 4 — Pass-the-Hash Confirmed

Used CrackMapExec to authenticate to DC01 using only the hash — no password:

```bash
crackmapexec smb 192.168.1.100 -u jsmith -H 7facdc498ed1680c4fd1448319a8c04f -d lab.local
```

Output:

```
SMB  192.168.1.100  445  DC01  [+] lab.local\jsmith:7facdc498ed1680c4fd1448319a8c04f (Pwn3d!)
```

<img width="1550" height="189" alt="Screenshot 2026-04-18 001239" src="https://github.com/user-attachments/assets/48559b95-93e3-4be8-b004-edd8c8bc006f" />


**Domain controller compromised.**

---

## Troubleshooting Reference

| Problem | Cause | Fix |
|---|---|---|
| psexec STATUS_LOGON_FAILURE | jsmith not in local Admins | Added jsmith to local Administrators on Win10 via DC01 |
| psexec ACCESS_DENIED (service start) | UAC token filtering | Set LocalAccountTokenFilterPolicy = 1, rebooted |
| psexec STATUS_VIRUS_INFECTED | Defender caught payload exe | Switched to wmiexec (no exe upload) |
| LSASS dump file never created | Defender tamper protection | Would need tamper protection explicitly disabled; pivoted to DC dump instead |
| jsmith returned DCC2, not NTLM | Workstation stores cached creds in DCC2 format | Dumped NTDS.dit from DC01 for raw NTLM |
---

## MITRE ATT&CK Mapping

| Technique | ID | What we did |
|---|---|---|
| SMB/Windows Admin Shares | T1021.002 | Used SMB for lateral movement |
| OS Credential Dumping: SAM | T1003.002 | secretsdump against Win10-victim |
| OS Credential Dumping: NTDS | T1003.003 | secretsdump against DC01 NTDS.dit |
| Pass the Hash | T1550.002 | Authenticated to DC01 using NTLM hash |

---

## Key Takeaways

**1. Valid credentials beat endpoint security.**
wmiexec, secretsdump, and crackmapexec are all legitimate tools used by sysadmins every day. When you have valid credentials, you're not "hacking" — you're using the network the way it was designed. Defenders have a hard time distinguishing this from normal activity.

**2. DCC2 ≠ NTLM.**
Workstation secretsdump returns cached credentials (DCC2), not live NTLM. Pass-the-Hash requires raw NTLM, which lives in LSASS memory or NTDS.dit. Know which format you have before trying to use it.

**3. The DC is the real target.**
Everything is harder on a hardened endpoint. The domain controller — which holds every account's credentials — is often less protected because it's "inside the firewall." Once you have domain admin access, NTDS.dit gives you the entire domain.

**4. What would have stopped this attack:**
- MFA on domain admin accounts (PTH fails if MFA is required)
- LAPS (randomizes local admin passwords — no reusable hashes from workstation SAM)
- Network segmentation (Kali shouldn't be able to reach DC01 on port 445 directly)
- Tiered admin model (jsmith as a regular user should never be elevatable to Domain Admin)

---

*Part of the [SOC Home Lab](https://github.com/JacobKing15/soc-homelab) series.*
*Previous: [Sim 1 — Brute Force](03-sim1-brute-force.md)*
*Next: Sim 3 — Persistence (Scheduled Task + Registry)*
