---
name: Bug Report
about: Create a report to help us improve Hulios.
title: "[BUG] "
labels: bug
assignees: ''
---

**Describe the bug**
A clear description of what the bug is.

**Environment Telemetry (Required):**
- **Linux Distribution / OS:**
- **Kernel Version (`uname -r`):**
- **eBPF Support (`zcat /proc/config.gz | grep BPF_LSM` or similar):**
- **Init System:** [systemd / openrc / runit / other]
- **Network Management:** [NetworkManager / systemd-networkd / dhcpcd / other]

**To Reproduce**
Steps to reproduce the behavior (e.g., `sudo hulios start --ipv6 tor`).

**Diagnostics Output**
Please run the diagnostics tool and paste the output:
```bash
sudo hulios diagnose
```
<paste output here>

**Daemon Logs**
Provide the system/daemon log output during the failure:
```bash
# If using systemd
journalctl -u hulios -n 100 --no-pager

# Otherwise, paste console logs
```
