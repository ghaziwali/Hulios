use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::types::*;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DiagnoseCheckResult {
    pub name: String,
    pub description: String,
    pub passed: bool,
    pub message: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DiagnoseReport {
    pub checks: Vec<DiagnoseCheckResult>,
    pub passed_count: usize,
    pub total_count: usize,
}

pub async fn check_routing_rules(fwmark: u32) -> Result<()> {
    hulios_tun::check_routing_rules(fwmark).await
}

pub async fn check_table_100(tun_name: &str) -> Result<()> {
    hulios_tun::check_table_100(tun_name).await
}

pub async fn check_udev_shield() -> Result<()> {
    let path = crate::types::get_udev_rules_path();
    if !path.exists() {
        anyhow::bail!(
            "Udev NetworkManager unmanaged rules file does not exist at {:?}",
            path
        );
    }
    Ok(())
}

pub async fn check_dns_resolution(ipv6_mode: Option<hulios_cli::Ipv6Mode>) -> Result<()> {
    if std::env::var("HULIOS_MOCK_DNS_RESOLUTION").is_ok() {
        if std::env::var("HULIOS_MOCK_DNS_RESOLUTION").unwrap() == "fail" {
            anyhow::bail!("DNS query failed");
        }
        return Ok(());
    }
    use hickory_resolver::config::{NameServerConfig, ResolverConfig, ResolverOpts};
    use hickory_resolver::net::runtime::TokioRuntimeProvider;
    use hickory_resolver::TokioResolver;
    use std::net::SocketAddr;
    use std::time::Duration;

    let port = std::env::var("HULIOS_MOCK_DNS_PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(53);

    // Read /proc/net/tcp and /proc/net/udp to find where Hickory is currently listening.
    // In our new approach, the daemon is already running and bound to port 53.
    // If 127.0.0.1:53 is listening, that's our target.
    // If not, we fall back to 127.0.0.2, or finally check hickory_bind_ip().
    let is_127_0_0_1_listening = {
        let mut found = false;
        let target = "0100007F:0035";
        for path in &["/proc/net/tcp", "/proc/net/udp"] {
            if let Ok(content) = std::fs::read_to_string(path) {
                for line in content.lines().skip(1) {
                    let cols: Vec<&str> = line.split_whitespace().collect();
                    if cols.len() >= 2 && cols[1].eq_ignore_ascii_case(target) {
                        found = true;
                        break;
                    }
                }
            }
        }
        found
    };

    let ip_str = if is_127_0_0_1_listening {
        "127.0.0.1"
    } else {
        let is_127_0_0_2_listening = {
            let mut found = false;
            let target = "0200007F:0035";
            for path in &["/proc/net/tcp", "/proc/net/udp"] {
                if let Ok(content) = std::fs::read_to_string(path) {
                    for line in content.lines().skip(1) {
                        let cols: Vec<&str> = line.split_whitespace().collect();
                        if cols.len() >= 2 && cols[1].eq_ignore_ascii_case(target) {
                            found = true;
                            break;
                        }
                    }
                }
            }
            found
        };
        if is_127_0_0_2_listening {
            "127.0.0.2"
        } else {
            hulios_dns::detect::hickory_bind_ip()
        }
    };

    let ip: std::net::IpAddr = ip_str
        .parse()
        .context(format!("Failed to parse Hickory bind IP: {}", ip_str))?;

    let ns_addr = SocketAddr::from((ip, port));
    let mut config = ResolverConfig::from_parts(None, vec![], vec![]);
    config.add_name_server(NameServerConfig::udp(ns_addr.ip()));
    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_secs(1);
    opts.attempts = 1;

    let resolver =
        TokioResolver::builder_with_config(config, TokioRuntimeProvider::default()).build()?;
    let _lookup = resolver
        .lookup_ip("example.com.")
        .await
        .context(format!("DNS query to {}:53 for example.com failed", ip))?;

    if ipv6_mode == Some(hulios_cli::Ipv6Mode::Tor) {
        let ip_ipv6: std::net::IpAddr = "fdbe::53".parse().unwrap();
        let ns_addr_ipv6 = SocketAddr::from((ip_ipv6, port));
        let mut config_ipv6 = ResolverConfig::from_parts(None, vec![], vec![]);
        config_ipv6.add_name_server(NameServerConfig::udp(ns_addr_ipv6.ip()));
        let resolver_ipv6 =
            TokioResolver::builder_with_config(config_ipv6, TokioRuntimeProvider::default())
                .build()?;
        let _lookup_ipv6 = resolver_ipv6
            .lookup_ip("example.com.")
            .await
            .context(format!(
                "DNS query to [fdbe::53]:{} for example.com failed",
                port
            ))?;
    }

    Ok(())
}

pub fn check_ebpf_programs() -> Result<()> {
    // Check if we hold active program links in memory (active daemon context)
    let has_bpf_in_memory = {
        if let Some(ref active) = *crate::get_active_handles().lock().unwrap() {
            active.ebpf_handles.sock_mark_link.is_some()
        } else {
            false
        }
    };
    if has_bpf_in_memory {
        return Ok(());
    }

    if std::env::var("HULIOS_MOCK_EBPF").is_ok() || std::env::var("HULIOS_MOCK_RECOVERY").is_ok() {
        if std::env::var("HULIOS_MOCK_EBPF").ok().as_deref() == Some("fail") {
            anyhow::bail!("eBPF program 'mark_hulios_socket' not found in loaded programs");
        }
        return Ok(());
    }

    // 1. Check pinned path in BPF filesystem
    let pin_dir = get_bpf_pin_dir_path();
    let lsm_pin_path = pin_dir.join("block_af_packet");
    let mark_pin_path = pin_dir.join("mark_hulios_socket");

    if lsm_pin_path.exists() && mark_pin_path.exists() {
        return Ok(());
    }

    // 2. Fallback: Query kernel for active/loaded programs via BPF programmatic query
    let mut has_mark = false;
    let mut has_block = false;

    for p in aya::programs::loaded_programs().flatten() {
        let name_bytes = p.name();
        let name = String::from_utf8_lossy(name_bytes);
        if name.contains("mark_hulios") {
            has_mark = true;
        }
        if name.contains("block_af_packet") || name.contains("block_af_pack") {
            has_block = true;
        }
    }
    if !has_mark {
        anyhow::bail!(
            "eBPF program 'mark_hulios_socket' not found in loaded programs or pin directory"
        );
    }
    if !has_block {
        anyhow::bail!(
            "eBPF program 'block_af_packet' not found in loaded programs or pin directory"
        );
    }
    Ok(())
}

pub async fn check_ipv4_udp_leak(tun_name: &str) -> Result<()> {
    if std::env::var("HULIOS_MOCK_LEAK_TEST").is_ok() {
        let mode = std::env::var("HULIOS_MOCK_LEAK_TEST").unwrap();
        if mode == "fail_ipv4" || mode == "fail_all" {
            anyhow::bail!("Leak detected: IPv4 UDP packet was sent successfully");
        }
        return Ok(());
    }

    let output = tokio::process::Command::new("ip")
        .args(["route", "get", "8.8.8.8"])
        .output()
        .await
        .context("Failed to run ip route get 8.8.8.8")?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    if !stdout.contains(&format!("dev {}", tun_name)) {
        anyhow::bail!(
            "IPv4 route for 8.8.8.8 does not resolve to the TUN interface {}",
            tun_name
        );
    }
    Ok(())
}

pub async fn check_ipv6_udp_leak(ipv6_mode: hulios_cli::Ipv6Mode) -> Result<()> {
    if std::env::var("HULIOS_MOCK_LEAK_TEST").is_ok() {
        let mode = std::env::var("HULIOS_MOCK_LEAK_TEST").unwrap();
        if mode == "fail_ipv6" || mode == "fail_all" {
            anyhow::bail!("Leak detected: IPv6 UDP check failed");
        }
        return Ok(());
    }

    use std::time::Duration;
    use tokio::net::UdpSocket;
    use tokio::time::timeout;

    match ipv6_mode {
        hulios_cli::Ipv6Mode::Disable => {
            let output = tokio::process::Command::new("ip")
                .args(["-6", "route", "get", "2001:4860:4860::8888"])
                .output()
                .await;

            match output {
                Ok(out) => {
                    if out.status.success() {
                        let stdout = String::from_utf8_lossy(&out.stdout);
                        let phys_iface = crate::detect_phys_iface();
                        if !phys_iface.is_empty() && stdout.contains(&format!("dev {}", phys_iface))
                        {
                            anyhow::bail!(
                                "IPv6 leak detected: route resolves to physical interface {}",
                                phys_iface
                            );
                        }
                        Ok(())
                    } else {
                        let stderr = String::from_utf8_lossy(&out.stderr);
                        if stderr.contains("unreachable") || stderr.contains("Unreachable") {
                            Ok(())
                        } else {
                            anyhow::bail!("IPv6 route check failed: {}", stderr.trim());
                        }
                    }
                }
                Err(e) => {
                    anyhow::bail!("Failed to execute ip -6 route get: {}", e);
                }
            }
        }
        hulios_cli::Ipv6Mode::Tor => {
            let socket = UdpSocket::bind("[::]:0")
                .await
                .context("Failed to bind IPv6 UDP socket in tor mode")?;
            if let Err(e) = socket.connect("[2001:4860:4860::8888]:12345").await {
                let err_code = e.raw_os_error();
                if err_code == Some(libc::ENETUNREACH) || err_code == Some(libc::EADDRNOTAVAIL) {
                    return Ok(());
                }
                return Err(anyhow::anyhow!(
                    "Failed to connect IPv6 UDP socket in tor mode: {}",
                    e
                ));
            }
            let packet = [0u8; 10];
            let _ = socket
                .send(&packet)
                .await
                .context("Failed to send IPv6 UDP packet in tor mode")?;

            let mut buf = [0u8; 10];
            match timeout(Duration::from_secs(1), socket.recv(&mut buf)).await {
                Ok(Err(e)) => {
                    let err_code = e.raw_os_error();
                    if err_code == Some(libc::ECONNREFUSED) || err_code == Some(libc::ENETUNREACH) {
                        Ok(())
                    } else {
                        anyhow::bail!(
                            "IPv6 UDP leak test in tor mode failed with unexpected error: {}",
                            e
                        );
                    }
                }
                Ok(Ok(_)) => {
                    anyhow::bail!("IPv6 UDP leak test in tor mode failed: packet sent successfully without expected block");
                }
                Err(_) => Ok(()),
            }
        }
    }
}

pub async fn check_daemon_responsive() -> Result<()> {
    let sock_path = get_control_sock_path();
    if !sock_path.exists() {
        anyhow::bail!("Control socket does not exist");
    }

    use std::time::Duration;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixStream;
    use tokio::time::timeout;

    let connect_fut = UnixStream::connect(&sock_path);
    let mut stream = timeout(Duration::from_secs(1), connect_fut).await??;

    let req = StatusRequest {
        cmd: "status".to_string(),
    };
    let req_str = format!("{}\n", serde_json::to_string(&req)?);

    stream.write_all(req_str.as_bytes()).await?;
    let mut reader = BufReader::new(stream);
    let mut response_line = String::new();
    timeout(Duration::from_secs(1), reader.read_line(&mut response_line)).await??;

    let _response: serde_json::Value = serde_json::from_str(&response_line)?;
    Ok(())
}

pub async fn run_diagnose(json: bool) -> Result<String> {
    if check_daemon_responsive().await.is_err() {
        let dirty_report = crate::detect_dirty_state().await;
        if !dirty_report.is_dirty() {
            return Ok(
                "Hulios is cleanly stopped (no stale rules or routes detected).".to_string(),
            );
        }
    }

    let file_cfg = hulios_cli::load_config_file().ok();
    let state_path = get_state_toml_path();
    let mut state_ipv6 = None;
    let (fwmark, tun_name) = if state_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&state_path) {
            if let Ok(state) = toml::from_str::<RunningState>(&content) {
                state_ipv6 = state.ipv6;
                (state.fwmark, state.tun_name)
            } else {
                (42, "hulios0".to_string())
            }
        } else {
            (42, "hulios0".to_string())
        }
    } else if let Some(ref cfg) = file_cfg {
        (cfg.fwmark, cfg.tun_name.clone())
    } else {
        (42, "hulios0".to_string())
    };

    let ipv6_mode = state_ipv6.unwrap_or_else(|| {
        file_cfg
            .as_ref()
            .map(|cfg| cfg.ipv6)
            .unwrap_or(hulios_cli::Ipv6Mode::Disable)
    });

    let mut checks = Vec::new();

    // Check 1: Routing rules
    let (passed, message) = match check_routing_rules(fwmark).await {
        Ok(_) => (true, "Routing rules verified successfully".to_string()),
        Err(e) => (false, e.to_string()),
    };
    checks.push(DiagnoseCheckResult {
        name: "Routing rules".to_string(),
        description: "Verify ip rule show has fwmark and table-100 entries".to_string(),
        passed,
        message,
    });

    // Check 2: Table 100
    let (passed, message) = match check_table_100(&tun_name).await {
        Ok(_) => (true, "Table 100 route verified successfully".to_string()),
        Err(e) => (false, e.to_string()),
    };
    checks.push(DiagnoseCheckResult {
        name: "Table 100".to_string(),
        description: format!(
            "Verify ip route show table 100 has default dev {}",
            tun_name
        ),
        passed,
        message,
    });

    // Check 3: Udev network shield
    let (passed, message) = match check_udev_shield().await {
        Ok(_) => (
            true,
            "Udev Network Shield verified successfully".to_string(),
        ),
        Err(e) => (false, e.to_string()),
    };
    checks.push(DiagnoseCheckResult {
        name: "Udev Network Shield".to_string(),
        description: format!(
            "Verify {} exists",
            crate::types::get_udev_rules_path().display()
        ),
        passed,
        message,
    });

    // Check 4: DNS resolution
    let (passed, message) = match check_dns_resolution(Some(ipv6_mode)).await {
        Ok(_) => (true, "DNS resolution verified successfully".to_string()),
        Err(e) => (false, e.to_string()),
    };
    checks.push(DiagnoseCheckResult {
        name: "DNS resolution".to_string(),
        description: "Send a DNS query for example.com to Hickory DNS resolver (127.0.0.1 or 127.0.0.2) and verify response".to_string(),
        passed,
        message,
    });

    // Check 5: eBPF programs
    let (passed, message) = match check_ebpf_programs() {
        Ok(_) => (true, "eBPF programs verified successfully".to_string()),
        Err(e) => (false, e.to_string()),
    };
    checks.push(DiagnoseCheckResult {
        name: "eBPF programs".to_string(),
        description:
            "Verify both eBPF programs (mark_hulios_socket and block_af_packet) are loaded"
                .to_string(),
        passed,
        message,
    });

    // Check 6: IPv4 UDP leak test
    let (passed, message) = match check_ipv4_udp_leak(&tun_name).await {
        Ok(_) => (true, "IPv4 UDP leak test verified successfully".to_string()),
        Err(e) => (false, e.to_string()),
    };
    checks.push(DiagnoseCheckResult {
        name: "IPv4 UDP leak test".to_string(),
        description: "Verify IPv4 UDP leaks are blocked".to_string(),
        passed,
        message,
    });

    // Check 7: IPv6 UDP leak test
    let (passed, message) = if ipv6_mode == hulios_cli::Ipv6Mode::Disable {
        (true, "SKIP (IPv6 is disabled)".to_string())
    } else {
        match check_ipv6_udp_leak(ipv6_mode).await {
            Ok(_) => (true, "IPv6 UDP leak test verified successfully".to_string()),
            Err(e) => (false, e.to_string()),
        }
    };
    checks.push(DiagnoseCheckResult {
        name: "IPv6 UDP leak test".to_string(),
        description: "Verify IPv6 UDP leaks are blocked".to_string(),
        passed,
        message,
    });

    // Check 8: Daemon responsive
    let (passed, message) = match check_daemon_responsive().await {
        Ok(_) => (true, "Daemon responsive".to_string()),
        Err(e) => (false, e.to_string()),
    };
    checks.push(DiagnoseCheckResult {
        name: "Daemon responsive".to_string(),
        description: "Ping control socket".to_string(),
        passed,
        message,
    });

    let mut passed_count = 0;
    let mut skipped_count = 0;
    for check in &checks {
        let is_skipped = check.message.starts_with("SKIP") || check.message.contains("disabled");
        if is_skipped {
            skipped_count += 1;
        } else if check.passed {
            passed_count += 1;
        }
    }
    let total_count = checks.len();
    let all_passed = checks.iter().all(|c| c.passed);

    let mut output = String::new();
    if json {
        let report = DiagnoseReport {
            checks,
            passed_count,
            total_count,
        };
        output = serde_json::to_string_pretty(&report)?;
    } else {
        output.push_str("Hulios Diagnostics:\n");
        for check in &checks {
            let is_skipped =
                check.message.starts_with("SKIP") || check.message.contains("disabled");
            let status = if is_skipped {
                "SKIP"
            } else if check.passed {
                "PASS"
            } else {
                "FAIL"
            };
            output.push_str(&format!(
                "  [{:<20}] {} ({})\n",
                check.name, status, check.message
            ));
        }
        output.push_str(&format!(
            "Summary: {}/{} checks passed ({} skipped)",
            passed_count, total_count, skipped_count
        ));
    }

    if all_passed {
        Ok(output)
    } else {
        Err(anyhow::anyhow!(
            "{}\nDiagnostics failed: {}/{} checks passed",
            output,
            passed_count,
            total_count
        ))
    }
}
