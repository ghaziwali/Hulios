# Hulios

> Hardened Universal Linux Invisibility and Onion System

Hulios is an eBPF-powered, transparent Tor VPN gateway for Linux. It secures outbound network traffic by redirecting TCP sockets and DNS queries through an embedded **Arti** (Tor client) instance and a localized **Hickory-based DNS resolver**. By operating at the kernel socket level via cgroup hooks and policy routing, Hulios implements robust leak-resistant boundaries without modifying runtime resolv.conf configurations or relying on external firewall daemons.

![Kernel](https://img.shields.io/badge/Kernel-5.10%2B-blue?logo=linux)
![Technology](https://img.shields.io/badge/Tech-eBPF%20%2F%20rtnetlink-orange)
![Rust](https://img.shields.io/badge/Rust-Nightly-red?logo=rust)
![Platform](https://img.shields.io/badge/Platform-Linux-green?logo=linux)

---

## 🔒 Security Architecture

Hulios implements a strict privilege-separated runtime model:

*   **Privilege Separation:** The entry point supervisor runs with host root privileges to hook eBPF programs and build policy routing tables, then immediately spawns an unprivileged worker child.
*   **Sandbox Isolation:** The worker process drops privileges to `nobody` and is isolated using a restrictive `seccomp` system call filter.
*   **Fail-Secure Kill-Switch:** Output traffic routing is locked using kernel policy tables (`table 100`) and default blackholes. In the event of a daemon crash or forced shutdown (`SIGKILL`), the blackholes remain active, blocking outgoing traffic to prevent IP leaks until a manual recovery is initiated.
*   **Raw Socket Blocker:** An LSM eBPF hook blocks raw `AF_PACKET` socket creation globally to prevent applications from bypassing standard IP routing rules.

---

## 📋 Requirements

*   **Linux Kernel:** Version 5.10 or higher.
*   **Kernel Configs:** `CONFIG_BPF_SYSCALL`, `CONFIG_BPF_LSM`, and `CONFIG_CGROUPS_V2` must be enabled.
*   **Build Dependencies:** `clang` and `libelf` (required for compile-time eBPF compilation).

### Verified Platforms
Tested and verified on **Arch Linux** and **Debian 13 (Bookworm)**.

---

## ⚙️ Build and Installation

### 1. Install Build Dependencies
*   **Arch Linux:**
    ```bash
    sudo pacman -S clang libelf
    ```
*   **Debian/Ubuntu:**
    ```bash
    sudo apt install -y clang libelf-dev
    ```

### 2. Compile from Source
Ensure you have the Rust compiler installed (toolchain selection and target requirements are automatically managed by `rust-toolchain.toml`):
```bash
git clone https://github.com/ghaziwali/Hulios.git
cd Hulios
cargo build --release
```
The compiled binary will be located at `target/release/hulios`.

---

## 🚀 Usage Guide

All commands that interact with kernel interfaces or policy routing require elevated privileges:

```bash
# View global help and available commands
./target/release/hulios --help

# View help for a specific command (e.g. start)
./target/release/hulios start --help

# Start Hulios in foreground TUI mode
sudo ./target/release/hulios start

# Check current running state and Tor bootstrap progress
./target/release/hulios status

# Verify network namespace integrity and check for leaks
sudo ./target/release/hulios diagnose

# Revert system network settings and recover from unclean shutdowns
sudo ./target/release/hulios recover

# Stop Hulios and restore standard internet routing
sudo ./target/release/hulios stop
```

---

## ⚙️ Configuration

Hulios automatically generates a default, self-documenting template file at **/etc/hulios/config.toml** on its first run if one is not already present. Open the generated file to customize variables (such as preferred Tor exit nodes, DNS redirects, custom SOCKS ports, or strict lockdown mode).

---

## 💖 Donate

If you find Hulios useful and would like to support its ongoing security development and research, donations are greatly appreciated:

*   **Bitcoin (BTC):** `bc1q0gllvd7fe2y48emjd4shf42ul3cl4pgda5zpqz`
*   **USDT (TRON / TRC20):** `TQWUmTATa8sDntobTNGkLmbgmHVS9iWCRx`
*   **USDC (Ethereum / ERC20):** `0x16aFd1De7889071194A026D79393eb3CE659181e`

---

## ⚠️ Disclaimer

Hulios securing the network transport layer (Layer 3) does not guarantee total anonymity. 

*   **No Liability / Misuse:** THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED. THE DEVELOPER ASSUMES NO LIABILITY OR RESPONSIBILITY FOR ANY DATA LEAKS, PRIVACY COMPROMISES, LEGAL CONSEQUENCES, SYSTEM INSTABILITY, OR DAMAGES ARISING FROM THE USE, MISUSE, OR ILLEGAL APPLICATION OF HULIOS.
*   **Application Fingerprinting:** Hulios does not strip application-level trackers, cookies, or browser fingerprinting configurations. For web browsing, it is highly recommended to use the official Tor Browser configured to route through the Hulios SOCKS interface.
*   **Host Compromise:** Hulios cannot protect your system if an adversary obtains root access, as they can unload eBPF programs and alter routing tables.
*   **Tor Network Limitations:** Your traffic is subject to the security of the Tor network, including potential correlation attacks by entities controlling both entry and exit nodes.
