# Lab Build #1: Proxmox + Wazuh SIEM Setup

**Date:** March 2026  
**Goal:** Get a Wazuh SIEM running on a Proxmox hypervisor on my home network

---

## What I Was Trying to Do

Set up a cybersecurity home lab on an old desktop PC. The plan: run Proxmox as a Type 1 hypervisor, then deploy a Wazuh SIEM as a VM so I can practice log analysis, detection, and incident response in a real environment.

---

## What I Did

**Hardware:** i5-6600K, 16GB RAM, 1TB Firecuda SSHD — repurposed desktop, nothing special.

Proxmox was already installed from a previous session. This session was about getting Wazuh running.

**Steps:**
1. Downloaded the Wazuh 4.10.2 OVA directly onto the Proxmox host
2. Extracted the OVA (it's a tar archive containing a VMDK disk image)
3. Converted the VMDK to qcow2 format using `qemu-img convert` (Proxmox's native format)
4. Created a VM with `qm create`, imported the disk with `qm importdisk`, set boot order
5. Started the VM, confirmed Wazuh booted, found its IP, accessed the dashboard

---

## What Went Wrong

**The network wasn't working on Proxmox at all.**

Wazuh wouldn't download. `ping 8.8.8.8` showed 100% packet loss. Even `ping 192.168.1.1` (the router) failed. The network config looked correct — right IP, right gateway, bridge interface up. Nothing made sense.

I checked `ip addr show` and `ip route show`. Everything looked fine on paper.

Then I logged into the router's admin page and found it: a TV was using the same IP address (192.168.1.50) as Proxmox. The router's ARP table pointed .50 to the TV's MAC address, so all of Proxmox's outbound traffic was being dropped — the router thought it already knew where .50 was, and it wasn't Proxmox.

**Fix:** Changed Proxmox's static IP to 192.168.1.150 (editing `/etc/network/interfaces` and `/etc/hosts`), restarted networking. Internet worked immediately.

---

## What I Learned

**Duplicate IPs are one of the sneakiest network problems.** Everything looks correct in your config, but the conflict is invisible until you check what else is on the network. Key symptom: can reach the device FROM the network but the device can't reach OUT.

**ARP is the layer that breaks.** The router's ARP table maps IPs to MAC addresses. When two devices claim the same IP, ARP entries flip back and forth unpredictably. That instability can affect other devices on the same network too — not just the conflicting IP.

**Commands used:**
- `ip addr show` / `ip route show` — verify interface config and routing table
- `ping 192.168.1.1` — test gateway reachability
- `/etc/network/interfaces` — where Proxmox stores static IP config
- `qemu-img convert -f vmdk -O qcow2` — convert VM disk formats
- `qm create / importdisk / set` — Proxmox CLI for VM management

---

## Why It Matters for Defense

IP conflicts show up in real environments too — rogue devices, misconfigured static IPs, or DHCP scope exhaustion. A SOC analyst investigating "host can't reach the internet" would go through the same diagnostic steps: check the config, check routing, check ARP, check the upstream device.

The Wazuh SIEM is now running at 192.168.1.95. Next step: deploy the Windows agent on my laptop and start seeing real alerts.
```

---
