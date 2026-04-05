# Week 2: Active Directory and Kali Attacker VM Setup

## What I Built
- DC01 (Windows Server 2022) — Active Directory domain controller, domain: lab.local
- Win10-victim — domain-joined target machine, jsmith domain user
- Kali Linux — attacker VM with xrdp for RDP access

## Key Lessons

**VirtIO drivers:** Windows VMs in Proxmox need a separate VirtIO driver ISO attached during install. Without it the disk isn't visible. Load from vioscsi → w10 → amd64 during setup.

**xrdp on Kali:** Xorg session conflicts with the console session. Fix: select "Xvnc" in the session dropdown at the xrdp login screen instead of Xorg.

**Static IP:** /etc/network/interfaces is ignored by NetworkManager on Kali. Used DHCP reservation on the router instead (MAC → 192.168.1.102).

**THM VPN:** Downloaded .ovpn file → renamed to thm.ovpn (filename had special chars that broke the command) → sudo openvpn ~/Downloads/thm.ovpn. tun0 interface confirmed.

## Next
First attack simulation: Kali → win10-victim (jsmith), monitoring with Wazuh.
