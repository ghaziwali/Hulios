<h1 align="center">HULIOS 🛡️ </h1>

**H**ardened **U**niversal **L**inux **I**nvisibility and **O**nion **S**ystem

The name *HULIOS* is inspired by both **Rust**, the programming language, and **Helios**, the Greek god of the sun. It reflects the project's goals of robustness, clarity, and pervasive reach in Linux systems.

A Rust-based transparent Tor proxy that routes **all system traffic** through the Tor network enhanced security, proper DNS isolation, and modern Linux compatibility.

<p align="center">
  <img src="https://img.shields.io/badge/Rust-1.70+-orange?logo=rust" alt="Rust">
  <img src="https://img.shields.io/badge/License-MIT-blue" alt="License">
  <img src="https://img.shields.io/badge/Platform-Linux-green?logo=linux" alt="Platform">
</p>

## Features

-  **Complete Traffic Anonymization** - All TCP traffic routed through Tor
-  **DNS Leak Prevention** - System resolver neutralized, DNS forced through Tor
-  **Default-Deny Firewall** - Only Tor user can access the internet
-  **IPv6 Blocked** - Prevents bypass via IPv6
-  **Tor Crash Monitoring** - Alerts if Tor dies unexpectedly
-  **Aggressive Resolver Handling** - Masks systemd-resolved to prevent resurrection

## Security Model

HULIOS implements a strict security model:

1. **Default-Deny Policy** - OUTPUT chain policy is DROP
2. **Tor-Only Internet Access** - Only the `tor` user can reach external networks
3. **DNS Ownership** - `/etc/resolv.conf` points to localhost, made immutable
4. **No Private Network Bypasses** - Router/LAN DNS cannot leak
5. **Encrypted DNS Blocked** - DoT (853) and QUIC (443/UDP) dropped
6. **IPv6 Killed** - All IPv6 traffic blocked at kernel level

## Requirements

- Linux (only tested on Arch)
- Rust 1.70+
- Tor
- iptables (nftables compatible)
- Root privileges

## Installation

### From AUR (Arch Linux)

If you are using an AUR helper like paru or yay, you can install HULIOS directly:

```bash
# Using paru
paru -S hulios-git

# Using yay
yay -S hulios-git
```

### From Source

```bash
# Clone the repository
git clone https://github.com/ghaziwali/hulios.git
cd hulios

# Build
cargo build --release

# Install (optional)
sudo cp target/release/hulios /usr/local/bin/
```

### Dependencies (Arch Linux)

```bash
sudo pacman -S tor iptables resolvectl
```

### Dependencies (Debian/Ubuntu)

```bash
sudo apt install tor iptables resolvectl
```

## Usage

```bash
# Start HULIOS (routes all traffic through Tor)
sudo hulios start

# Check status and current IP
hulios status

# Restart (get new Tor circuit)
sudo hulios restart

# Stop and restore normal networking
sudo hulios stop

# Flush firewall rules only
sudo hulios flush
```

## How It Works

### Traffic Flow

```
┌─────────────────────────────────────────────────────────────┐
│                        Your System                          │
├─────────────────────────────────────────────────────────────┤
│  Application (curl, browser, etc.)                          │
│          │                                                  │
│          ▼                                                  │
│  ┌─────────────────┐                                        │
│  │  System Resolver │ ──→ /etc/resolv.conf = 127.0.0.1      │
│  └─────────────────┘                                        │
│          │                                                  │
│          ▼                                                  │
│  ┌─────────────────────────────────────────┐                │
│  │           iptables NAT                  │                │
│  │  DNS (port 53) → REDIRECT → 127.0.0.1:9061 (Tor DNS)     │
│  │  TCP           → REDIRECT → 127.0.0.1:9051 (Tor Trans)   │
│  └─────────────────────────────────────────┘                │
│          │                                                  │
│          ▼                                                  │
│  ┌─────────────────────────────────────────┐                │
│  │           iptables FILTER               │                │
│  │  Policy: DROP (deny-all)                │                │
│  │  ACCEPT: loopback, tor user, established│                │
│  │  DROP: everything else                  │                │
│  └─────────────────────────────────────────┘                │
│          │                                                  │
│          ▼                                                  │
│  ┌─────────────────┐                                        │
│  │   Tor Process   │ ──→ Tor Network ──→ Internet           │
│  │  (user: tor)    │                                        │
│  └─────────────────┘                                        │
└─────────────────────────────────────────────────────────────┘
```

### Key Components

| Port | Service | Purpose |
|------|---------|---------|
| 9050 | SOCKSPort | SOCKS5 proxy (optional direct use) |
| 9051 | TransPort | Transparent TCP proxy |
| 9061 | DNSPort | DNS resolution via Tor |

## Verification

### Check Your IP

```bash
hulios status
# Output:
# [+] Status: true
# [+] Ip: 185.220.101.xxx (Tor exit node)
```

### Verify No DNS Leaks

```bash
# Terminal 1: Monitor external interface
sudo tcpdump -i wlan0 port 53 -n
# Should show: 0 packets captured

# Terminal 2: Monitor Tor DNS port
sudo tcpdump -i lo port 9061 -n
# Should show: UDP traffic to 127.0.0.1:9061
```

### Online Leak Tests

- [check.torproject.org](https://check.torproject.org)
- [bash.ws/dnsleak](https://bash.ws/dnsleak)
- [ipleak.net](https://ipleak.net)

## Configuration

HULIOS uses a temporary Tor configuration at `/tmp/hulios_torrc`:

```
RunAsDaemon 1
User tor
DataDirectory /tmp/hulios_tor_data
SOCKSPort 9050
TransPort 9051
DNSPort 9061
VirtualAddrNetwork 10.66.0.0/255.255.0.0
AutomapHostsOnResolve 1
```

## Notifications

HULIOS sends desktop notifications for:

| Event | Notification |
|-------|-------------|
| Start | "HULIOS Started - All traffic now routed through Tor " |
| Restart | "HULIOS Restarted - Tor connection refreshed " |
| Stop | "HULIOS Stopped - Normal network restored" |
| Tor Crash | "⚠️ HULIOS CRITICAL - Tor process crashed!" |

Works on both X11 and Wayland (Hyprland, Sway, GNOME, KDE...).

## Troubleshooting

### DNS Not Working

```bash
# Check if Tor is running
ps aux | grep tor

# Check if DNSPort is listening
sudo ss -tulpn | grep 9061

# Check Tor logs
cat /tmp/tor_debug.log
```

### Tor Fails to Bootstrap

Wait longer (some networks are slow) or check if Tor is blocked:

```bash
# View bootstrap progress
tail -f /tmp/tor_debug.log
```



## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## License

MIT License - See [LICENSE](LICENSE) for details.

## Disclaimer

This tool is for **educational and legitimate privacy purposes only**. The authors are not responsible for misuse. Always comply with local laws and terms of service.

## Credits

- [Tor Project](https://www.torproject.org/) for the Tor network
- [NIPE](https://github.com/htrgouvea/nipe) as an inspiration
