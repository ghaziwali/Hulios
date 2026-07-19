# Hulios Project Roadmap

This document outlines the development lifecycle, current milestones, and future feature plans for the Hulios eBPF transparent Tor VPN gateway.

---

## 🚀 Milestones

### 📍 Milestone 1: Version 2.0.0-rc.1 (Current Release Candidate)
*Focus: Core Security, eBPF routing engine, and Zero-Leak guarantees.*
- [x] **eBPF Socket Marking:** Automatic `fwmark` tagging for all system TCP/UDP sockets inside cgroups.
- [x] **Transparent TCP Hijacking:** Standard routing rule redirection to the Arti-based Tor tunnel.
- [x] **Hickory DNS Overrides:** Hijacking DNS UDP/TCP queries to a local DNS resolver resolved natively over Tor.
- [x] **LSM Raw Socket Blocker:** Blocking `AF_PACKET` socket creation to prevent L2/L3 bypass leaks.
- [x] **Fail-Secure Kill-Switch:** Default blackhole routing preventing leaks during crashes or TUN interface drops.
- [x] **Muted Diagnostics & Graceful Recovery:** In-depth CLI system status diagnostics and complete system recovery resets.

---

### 📅 Milestone 2: Version 2.1.0 (Short-Term Enhancements)
*Focus: Restoring advanced user-space network convenience features.*
- [ ] **LAN Bypass (`--lan-bypass`):** Allow local network routing (printers, local admin panels, local servers) directly bypassing Tor.
- [ ] **Portal Escape (`--portal-escape`):** Temporary captive portal authentication bypass to login to public WiFi hotspots before locking down the network.
- [ ] **Cgroup & User Exclusions:** Bypassing specific systemd services, users (UIDs), or slices from transparent routing.

---

### 📅 Milestone 3: Version 2.2.0 (Network Roaming)
*Focus: Seamless WiFi roaming and sleep/wake compatibility.*
- [ ] **TC (Traffic Control) Egress Hook Shift:** Transition from LSM-based socket blocking to TC egress filtering on physical interfaces. This allows link-local protocols (DHCP, EAPOL, ARP) to egress during sleep/wake re-negotiations while maintaining the zero-leak guarantee for all other traffic.
- [ ] **Netlink Interface Monitor:** Dynamically attaching TC filters to interfaces as they are created or modified (e.g. WiFi toggles, Ethernet plugs).

---

### 📅 Milestone 4: Version 2.3.0+ (Anti-Censorship & Relays)
*Focus: Native anti-censorship support and path exclusions.*
- [ ] **In-Process Pluggable Bridges:** Integrating native pure-Rust implementations of obfs4, Snowflake, and WebTunnel directly into the Arti runtime.
- [ ] **Zero-Fork Execution:** Executing bridge transports in-memory without spawning subprocesses, ensuring complete compatibility with Hulios's strict `seccomp` sandboxes.
- [ ] **Node Exclusions:** Exclude specific countries or relay paths from Tor circuits via CLI/config settings (pending upstream `onionmasq` support).
