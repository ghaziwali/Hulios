# Security Policy

We take the security and privacy of Hulios seriously. If you believe you have found a security vulnerability, please report it privately using the guidelines below.

---

## Supported Versions

Only the active release branch and stable versions receive security updates:

| Version | Supported |
| :--- | :--- |
| 2.0.0-rc.x | :white_check_mark: Yes |
| < 2.0.0 (Legacy) | :x: No |

---

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

To report a vulnerability (e.g., DNS leaks, WebRTC leaks, routing bypasses, or sandbox escapes):
1.  Go to the [GitHub Security Advisories Page](https://github.com/ghaziwali/Hulios/security/advisories/new).
2.  Fill out the advisory details privately (this allows maintenance coordination without disclosing details prematurely).
3.  We will acknowledge your report within 48 hours and coordinate a fix.

---

## Scope of Security

### 🎯 In-Scope Vulnerabilities
We actively patch and track:
*   **Leak Vulnerabilities:** Any scenario where cleartext IP or DNS traffic bypasses the Tor routing rules and escapes onto the physical interface.
*   **Privilege Escalations:** Escapes from the unprivileged `nobody` sandbox or the `seccomp` filters of the worker process.
*   **Buffer Overflows & Memory Corruption:** Security issues inside the supervisor socket parser or custom DNS resolver.

### 🚫 Out-of-Scope Vulnerabilities
The following are external dependencies or design constraints and are out of scope:
*   **Host Compromise:** If an attacker already has root privileges on your machine, they can modify kernel routing tables or unload eBPF programs. Hulios cannot defend against a compromised host.
*   **Tor Network Limitations:** Global traffic correlation attacks or compromised exit nodes run by hostile entities.
*   **Application-Level Tracking:** Web browser cookies, Canvas fingerprinting, or user-agent tracking.
