use anyhow::{Result, Context};
use std::process::Command;
use std::fs;
use std::thread;
use std::time::Duration;
use crate::iptables; 
use users::get_current_uid;

const TOR_USER: &str = "tor";
const RESOLV_BACKUP: &str = "/tmp/hulios_resolv.conf.backup";
const RESOLV_PATH: &str = "/etc/resolv.conf";
const TOR_PID_FILE: &str = "/tmp/hulios_tor.pid";

// =============================================================================
// Main Commands
// =============================================================================

pub fn start() -> Result<()> {
    if get_current_uid() != 0 {
        anyhow::bail!("HULIOS must be run as root.");
    }

    // Stop any existing tor and system resolver
    stop_tor_service()?;
    neutralize_system_resolver()?;
    
    // Enable route_localnet for DNS redirection
    enable_route_localnet()?;
    
    // Prepare Tor data directory
    let data_dir = "/tmp/hulios_tor_data";
    let _ = fs::remove_dir_all(data_dir);
    fs::create_dir_all(data_dir).context("Failed to create data dir")?;
    
    Command::new("chown")
        .args(["-R", "tor:tor", data_dir])
        .status()
        .context("Failed to chown data dir")?;

    // Write torrc
    let torrc_content = format!(r#"RunAsDaemon 1
User tor
DataDirectory {}
Log notice file /tmp/tor_debug.log
SOCKSPort 9050
TransPort 9051
DNSPort 9061
VirtualAddrNetwork 10.66.0.0/255.255.0.0
AutomapHostsOnResolve 1
"#, data_dir);
    
    fs::write("/tmp/hulios_torrc", &torrc_content)?;

    // Start Tor
    let tor_child = Command::new("tor")
        .args(["-f", "/tmp/hulios_torrc"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("Failed to start tor process")?;
    
    let tor_pid = tor_child.id();
    fs::write(TOR_PID_FILE, tor_pid.to_string())?;
    println!("[*] Tor starting (PID: {})...", tor_pid);

    // Wait for Tor to bootstrap
    thread::sleep(Duration::from_secs(10));
    
    // Verify Tor is still running
    if !is_tor_running() {
        send_notification("HULIOS Error", "Tor failed to start! Check /tmp/tor_debug.log", "critical");
        anyhow::bail!("Tor process died during startup");
    }

    // Apply iptables rules
    iptables::apply_rules(TOR_USER)?;
    
    // Force DNS to point to localhost
    take_dns_ownership()?;

    // Send success notification
    send_notification("HULIOS Started", "All traffic now routed through Tor 🧅", "normal");
    println!("[+] HULIOS started successfully.");
    
    // Spawn background Tor monitor
    spawn_tor_monitor();
    
    Ok(())
}

pub fn stop() -> Result<()> {
    if get_current_uid() != 0 {
        anyhow::bail!("HULIOS must be run as root.");
    }

    // Restore firewall
    iptables::flush_rules()?;
    
    // Stop tor
    stop_tor_service()?;
    
    // Restore DNS
    restore_dns()?;
    
    // Restore system resolver
    restore_system_resolver()?;

    // Send notification
    send_notification("HULIOS Stopped", "Normal network restored", "normal");
    println!("[+] HULIOS stopped.");
    Ok(())
}

pub fn restart() -> Result<()> {
    println!("[+] Restarting HULIOS...");
    
    // Quiet stop (no notification)
    if get_current_uid() != 0 {
        anyhow::bail!("HULIOS must be run as root.");
    }
    iptables::flush_rules()?;
    stop_tor_service()?;
    restore_dns()?;
    
    thread::sleep(Duration::from_secs(2));
    
    // Start (will send its own notification)
    start()?;
    
    // Override with restart-specific notification
    send_notification("HULIOS Restarted", "Tor connection refreshed 🔄", "normal");
    println!("[+] HULIOS restarted.");
    Ok(())
}

pub fn flush() -> Result<()> {
    if get_current_uid() != 0 {
        anyhow::bail!("HULIOS must be run as root.");
    }
    iptables::flush_rules()?;
    restore_dns()?;
    restore_system_resolver()?;
    send_notification("HULIOS Flushed", "Firewall rules cleared", "normal");
    println!("[+] Firewall rules flushed and DNS restored.");
    Ok(())
}

// =============================================================================
// Tor Monitoring
// =============================================================================

/// Check if Tor process is running
fn is_tor_running() -> bool {
    if let Ok(pid_str) = fs::read_to_string(TOR_PID_FILE) {
        if let Ok(pid) = pid_str.trim().parse::<i32>() {
            let status = Command::new("kill")
                .args(["-0", &pid.to_string()])
                .status();
            return status.map(|s| s.success()).unwrap_or(false);
        }
    }
    
    // Fallback: check by name
    let status = Command::new("pgrep")
        .args(["-x", "tor"])
        .status();
    status.map(|s| s.success()).unwrap_or(false)
}

/// Spawn a background thread to monitor Tor
fn spawn_tor_monitor() {
    thread::spawn(|| {
        thread::sleep(Duration::from_secs(30));
        
        loop {
            thread::sleep(Duration::from_secs(10));
            
            if !is_tor_running() {
                send_notification(
                    "⚠️ HULIOS CRITICAL", 
                    "Tor process crashed! Network may be leaking. Run: sudo hulios restart",
                    "critical"
                );
                eprintln!("[!] CRITICAL: Tor process died!");
                break;
            }
        }
    });
}

// =============================================================================
// Notifications - Works on both X11 and Wayland (Hyprland, Sway, etc.)
// =============================================================================

/// Send desktop notification using notify-send
/// Works on both X11 and Wayland by detecting the environment
fn send_notification(title: &str, body: &str, urgency: &str) {
    // Get the original user (before sudo)
    let sudo_user = std::env::var("SUDO_USER").unwrap_or_default();
    if sudo_user.is_empty() {
        // Running as root directly without sudo, try anyway
        let _ = Command::new("notify-send")
            .args(["-u", urgency, "-a", "HULIOS", title, body])
            .status();
        return;
    }
    
    // Get the user's UID for XDG_RUNTIME_DIR
    let uid = get_user_uid(&sudo_user).unwrap_or(1000);
    let xdg_runtime = format!("/run/user/{}", uid);
    
    // Try to detect Wayland first (common for Hyprland/Sway)
    let wayland_display = find_wayland_display(&xdg_runtime);
    
    // Also get X11 display if available
    let x11_display = std::env::var("DISPLAY").unwrap_or_else(|_| ":0".to_string());
    
    // Build environment for the notification command
    let mut env_vars = vec![
        ("XDG_RUNTIME_DIR", xdg_runtime.clone()),
        ("HOME", format!("/home/{}", sudo_user)),
    ];
    
    // Add Wayland-specific vars if detected
    if let Some(ref wd) = wayland_display {
        env_vars.push(("WAYLAND_DISPLAY", wd.clone()));
        // Hyprland instance signature (if available)
        if let Ok(his) = std::env::var("HYPRLAND_INSTANCE_SIGNATURE") {
            env_vars.push(("HYPRLAND_INSTANCE_SIGNATURE", his));
        }
    }
    
    // Always add DISPLAY for X11 fallback
    env_vars.push(("DISPLAY", x11_display.clone()));
    
    // Also need DBUS for notifications on most systems
    let dbus_addr = format!("unix:path={}/bus", xdg_runtime);
    env_vars.push(("DBUS_SESSION_BUS_ADDRESS", dbus_addr));
    
    // Run notify-send as the original user with proper environment
    let mut cmd = Command::new("sudo");
    cmd.arg("-u").arg(&sudo_user);
    
    // Set environment variables
    for (key, val) in &env_vars {
        cmd.arg(format!("{}={}", key, val));
    }
    
    cmd.arg("notify-send")
        .args(["-u", urgency, "-a", "HULIOS", "-i", "network-vpn", title, body]);
    
    let _ = cmd.status();
}

/// Get the UID of a user by name
fn get_user_uid(username: &str) -> Option<u32> {
    let output = Command::new("id")
        .args(["-u", username])
        .output()
        .ok()?;
    
    String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .ok()
}

/// Find the Wayland display socket in XDG_RUNTIME_DIR
fn find_wayland_display(xdg_runtime: &str) -> Option<String> {
    // Check for common Wayland socket names
    let candidates = ["wayland-0", "wayland-1", "wayland-2"];
    
    for candidate in candidates {
        let path = format!("{}/{}", xdg_runtime, candidate);
        if std::path::Path::new(&path).exists() {
            return Some(candidate.to_string());
        }
    }
    
    // Also check WAYLAND_DISPLAY from current environment
    std::env::var("WAYLAND_DISPLAY").ok()
}

// =============================================================================
// DNS Ownership Functions
// =============================================================================

/// Aggressively neutralize system resolver - treat as hostile
fn neutralize_system_resolver() -> Result<()> {
    println!("[*] Neutralizing system resolver (treating as hostile)...");
    
    // MASK the service (stronger than disable)
    let _ = Command::new("systemctl")
        .args(["mask", "systemd-resolved"])
        .status();
    
    let _ = Command::new("systemctl")
        .args(["stop", "systemd-resolved"])
        .status();
    
    let _ = Command::new("killall")
        .args(["systemd-resolved"])
        .status();
    
    let _ = Command::new("systemctl")
        .args(["stop", "NetworkManager-dispatcher"])
        .status();
    
    let _ = Command::new("systemctl")
        .args(["stop", "dnsmasq"])
        .status();
    
    let _ = Command::new("systemctl")
        .args(["mask", "dnsmasq"])
        .status();
    
    Ok(())
}

/// Restore systemd-resolved
fn restore_system_resolver() -> Result<()> {
    println!("[*] Restoring system resolver...");
    
    let _ = Command::new("systemctl")
        .args(["unmask", "systemd-resolved"])
        .status();
    
    let _ = Command::new("systemctl")
        .args(["unmask", "dnsmasq"])
        .status();
    
    let _ = Command::new("systemctl")
        .args(["start", "systemd-resolved"])
        .status();
    
    let _ = Command::new("systemctl")
        .args(["start", "NetworkManager-dispatcher"])
        .status();
    
    Ok(())
}

/// Take ownership of DNS by replacing /etc/resolv.conf
fn take_dns_ownership() -> Result<()> {
    println!("[*] Taking DNS ownership...");
    
    let _ = Command::new("chattr")
        .args(["-i", RESOLV_PATH])
        .status();
    
    if fs::metadata(RESOLV_BACKUP).is_err() {
        let sources = [
            "/run/systemd/resolve/resolv.conf",
            "/run/NetworkManager/resolv.conf",
            RESOLV_PATH,
        ];
        
        for src in sources {
            if fs::metadata(src).is_ok() {
                let _ = Command::new("cp")
                    .args(["-L", src, RESOLV_BACKUP])
                    .status();
                break;
            }
        }
    }
    
    let _ = fs::remove_file(RESOLV_PATH);
    
    let resolv_content = r#"# HULIOS - Tor DNS
# DO NOT MODIFY - This file is managed by HULIOS
# All DNS queries are routed through Tor
nameserver 127.0.0.1
options edns0 trust-ad ndots:0
"#;
    
    fs::write(RESOLV_PATH, resolv_content)
        .context("Failed to write resolv.conf")?;
    
    let _ = Command::new("chattr")
        .args(["+i", RESOLV_PATH])
        .status();
    
    println!("[+] DNS now points to localhost (Tor DNSPort)");
    Ok(())
}

/// Restore original DNS configuration
fn restore_dns() -> Result<()> {
    println!("[*] Restoring DNS configuration...");
    
    let _ = Command::new("chattr")
        .args(["-i", RESOLV_PATH])
        .status();
    
    if fs::metadata(RESOLV_BACKUP).is_ok() {
        let _ = fs::remove_file(RESOLV_PATH);
        let _ = fs::copy(RESOLV_BACKUP, RESOLV_PATH);
        let _ = fs::remove_file(RESOLV_BACKUP);
    } else {
        let _ = fs::remove_file(RESOLV_PATH);
        let _ = Command::new("ln")
            .args(["-sf", "/run/systemd/resolve/stub-resolv.conf", RESOLV_PATH])
            .status();
    }
    
    let _ = fs::remove_file(TOR_PID_FILE);
    
    Ok(())
}

// =============================================================================
// Helper Functions
// =============================================================================

fn stop_tor_service() -> Result<()> {
    let _ = Command::new("systemctl").args(["stop", "tor"]).status();
    let _ = Command::new("killall").args(["tor"]).status();
    let _ = fs::remove_file(TOR_PID_FILE);
    Ok(())
}

fn enable_route_localnet() -> Result<()> {
    let _ = Command::new("sysctl")
        .args(["-w", "net.ipv4.conf.all.route_localnet=1"])
        .stdout(std::process::Stdio::null())
        .status();
    Ok(())
}
