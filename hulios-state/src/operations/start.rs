use crate::errors::*;
use crate::types::*;
use anyhow::{Context, Result};
use hulios_cli::HuliosConfig;
use std::sync::{Arc, Mutex};

fn setup_directory_as_root(path: &std::path::Path) -> Result<()> {
    if !path.exists() {
        std::fs::create_dir_all(path)
            .with_context(|| format!("Failed to create directory {:?}", path))?;
    }
    Ok(())
}

fn chown_recursive_to_nobody(path: &std::path::Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    if !nix::unistd::Uid::effective().is_root() {
        return Ok(());
    }
    let nobody = nix::unistd::User::from_name("nobody")
        .context("Failed to query user 'nobody'")?
        .ok_or_else(|| anyhow::anyhow!("User 'nobody' not found"))?;
    let uid = Some(nobody.uid);
    let gid = Some(nobody.gid);

    fn visit_dirs(
        dir: &std::path::Path,
        uid: Option<nix::unistd::Uid>,
        gid: Option<nix::unistd::Gid>,
    ) -> Result<()> {
        if nix::unistd::Uid::effective().is_root() {
            nix::unistd::chown(dir, uid, gid)
                .with_context(|| format!("Failed to chown {:?}", dir))?;
        }
        if dir.is_dir() {
            for entry in std::fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_dir() {
                    visit_dirs(&path, uid, gid)?;
                } else if nix::unistd::Uid::effective().is_root() {
                    nix::unistd::chown(&path, uid, gid)
                        .with_context(|| format!("Failed to chown {:?}", path))?;
                }
            }
        }
        Ok(())
    }

    visit_dirs(path, uid, gid)
}

fn chown_recursive_to_root(path: &std::path::Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    if !nix::unistd::Uid::effective().is_root() {
        return Ok(());
    }
    let uid = Some(nix::unistd::Uid::from_raw(0));
    let gid = Some(nix::unistd::Gid::from_raw(0));

    fn visit_dirs(
        dir: &std::path::Path,
        uid: Option<nix::unistd::Uid>,
        gid: Option<nix::unistd::Gid>,
    ) -> Result<()> {
        if nix::unistd::Uid::effective().is_root() {
            nix::unistd::chown(dir, uid, gid)
                .with_context(|| format!("Failed to chown {:?}", dir))?;
        }
        if dir.is_dir() {
            for entry in std::fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_dir() {
                    visit_dirs(&path, uid, gid)?;
                } else {
                    if nix::unistd::Uid::effective().is_root() {
                        nix::unistd::chown(&path, uid, gid)
                            .with_context(|| format!("Failed to chown {:?}", path))?;
                    }
                }
            }
        }
        Ok(())
    }
    visit_dirs(path, uid, gid)
}

fn get_country_name(code: &str) -> String {
    match code.to_uppercase().as_str() {
        "CH" => "Switzerland".to_string(),
        "US" => "United States".to_string(),
        "DE" => "Germany".to_string(),
        "FR" => "France".to_string(),
        "GB" => "United Kingdom".to_string(),
        "NL" => "Netherlands".to_string(),
        "CA" => "Canada".to_string(),
        "JP" => "Japan".to_string(),
        "SE" => "Sweden".to_string(),
        other => other.to_string(),
    }
}

/// Zero-cost IPv6 route probe.
/// Attempts a UDP "connect" to a well-known public IPv6 address.
/// This only queries the kernel routing table -- no packets are sent.
/// Returns true if the kernel has a route to reach public IPv6 addresses.
fn check_ipv6_reachable() -> bool {
    let sock = match std::net::UdpSocket::bind("[::]:0") {
        Ok(s) => s,
        Err(_) => return false,
    };
    sock.connect("[2001:4860:4860::8888]:53").is_ok()
}

pub async fn startup(mut cfg: HuliosConfig) -> Result<RunningState> {
    let _ = hulios_onionmasq::isolation::hulios_state::watchdog::CLEAR_IP_CACHE
        .set(crate::watchdog::clear_ip_cache);

    if let Some(ref cc_str) = cfg.exit_nodes {
        if cc_str.len() != 2 || !cc_str.chars().all(|c| c.is_ascii_alphabetic()) {
            anyhow::bail!(
                "Invalid exit country code '{}'. Must be a 2-letter ISO country code.",
                cc_str
            );
        }
    }

    // Auto-detect IPv6 connectivity when user hasn't explicitly set the flag
    if cfg.ipv6 == hulios_cli::Ipv6Mode::Tor
        && !cfg.set_fields.contains("ipv6")
        && !check_ipv6_reachable()
    {
        tracing::info!(
            "IPv6 public route not detected. Disabling IPv6 TUN setup for this session."
        );
        cfg.ipv6 = hulios_cli::Ipv6Mode::Disable;
    }

    macro_rules! check_fail {
        ($phase:expr) => {
            if let Ok(fail_phase) = std::env::var("HULIOS_FAIL_PHASE") {
                if fail_phase == $phase {
                    tracing::warn!("Simulating failure at phase {}", $phase);
                    anyhow::bail!("Simulated failure at phase {}", $phase);
                }
            }
        };
    }

    let ebpf_handles_shared = Arc::new(Mutex::new(None));
    let tun_handle_shared = Arc::new(Mutex::new(None));
    let saved_sysctls_shared = Arc::new(Mutex::new(None));
    let avahi_saved_shared = Arc::new(Mutex::new(None));
    let arti_client_shared = Arc::new(Mutex::new(None));
    let onionmasq_handle_shared = Arc::new(Mutex::new(None));
    let status_handle_shared = Arc::new(Mutex::new(None));
    let control_socket_task_shared = Arc::new(Mutex::new(None));

    let result = async {
        // 1. CheckCapabilities
        check_fail!("CheckCapabilities");
        if !nix::unistd::getuid().is_root() && std::env::var("HULIOS_MOCK_CAPS").is_err() {
            anyhow::bail!("Hulios must be run as root (or with CAP_NET_ADMIN, CAP_BPF, CAP_NET_BIND_SERVICE)");
        }
        println!("[Phase  1/14] Checking capabilities...                  [OK]");

        // Pre-flight recovery to clean up any conflicting lingering resources from a previous dirty exit
        tracing::info!("Pre-flight: Running clean recovery sweep to prevent configuration conflicts");
        if let Err(e) = crate::recover().await {
            tracing::warn!("Pre-flight recovery sweep encountered warnings: {:?}", e);
        }

        // Apply Seccomp Filter early
        check_fail!("ApplySeccomp");
        println!("[Phase  2/14] Applying sandbox...                       [OK]");

        // SetupDirectories
        check_fail!("SetupDirectories");
        let var_lib_dir = std::env::var("HULIOS_VAR_LIB_PATH")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| std::path::PathBuf::from("/var/lib/hulios/arti"));
        setup_directory_as_root(&var_lib_dir)?;
        chown_recursive_to_root(&var_lib_dir)?;
        let state_path = get_state_toml_path();
        if let Some(parent) = state_path.parent() {
            setup_directory_as_root(parent)?;
        }
        let sock_path = get_control_sock_path();
        if let Some(parent) = sock_path.parent() {
            setup_directory_as_root(parent)?;
        }

        // Write udev unmanaged rules file
        let udev_rule_path = crate::types::get_udev_rules_path();
        if let Some(parent) = udev_rule_path.parent() {
            setup_directory_as_root(parent)?;
        }
        std::fs::write(&udev_rule_path, format!("SUBSYSTEM==\"net\", ENV{{INTERFACE}}==\"{}\", ENV{{NM_UNMANAGED}}=\"1\", ENV{{SYSTEMD_READY}}=\"0\"\n", cfg.tun_name))
            .context("Failed to write udev unmanaged rule")?;



        println!("[Phase  3/14] Preparing directories...                  [OK]");

        // 2. DetectDirtyState
        check_fail!("DetectDirtyState");
        let report = crate::detect_dirty_state().await;
        if report.is_dirty() {
            tracing::info!("Dirty state detected, running recovery: {:?}", report);
            crate::recover().await?;
        }
        println!("[Phase  4/14] Detecting dirty state...                  [OK]");

        // 3. CheckVpnConflict
        check_fail!("CheckVpnConflict");
        match hulios_netcompat::detect_vpn_fwmark_conflict(cfg.fwmark).await {
            Ok(Some(conflict)) => {
                tracing::error!("Fwmark conflict detected: {:?}", conflict);
                return Err(HuliosError::FwmarkConflict(conflict.rule_description).into());
            }
            Ok(None) => {}
            Err(e) => return Err(e),
        }
        println!("[Phase  5/14] Checking VPN conflicts...                 [OK]");

        // 4. LoadEbpf
        check_fail!("LoadEbpf");
        let cgroup_path = crate::detect_cgroup_path_state()?;
        let hickory_ip = hulios_dns::detect::hickory_bind_ip();
        let ipv6_disabled = cfg.ipv6 == hulios_cli::Ipv6Mode::Disable;
        let ebpf_handles = crate::loader::load_ebpf_state(&cgroup_path, cfg.bpf_bytecode.as_deref(), hickory_ip, ipv6_disabled, cfg.fwmark)?;
        *ebpf_handles_shared.lock().unwrap() = Some(ebpf_handles);

        println!("[Phase  6/14] Loading eBPF programs...                  [OK]");

        // 5. CreateTun
        check_fail!("CreateTun");
        let tun_cfg = hulios_tun::TunConfig {
            name: cfg.tun_name.clone(),
            address: "10.242.0.1".to_string(),
            netmask: "255.255.255.0".to_string(),
            mtu: 1420,
            ipv6: match cfg.ipv6 {
                hulios_cli::Ipv6Mode::Disable => hulios_tun::Ipv6Mode::Disable,
                hulios_cli::Ipv6Mode::Tor => hulios_tun::Ipv6Mode::Tor,
            },
        };
        let tun_raw_fd = if std::env::var("HULIOS_MOCK_RECOVERY").is_ok() {
            tracing::info!("[Mock] Created TUN interface");
            // Write to mock tun class path to simulate existence
            let tun_class = get_tun_class_path(&cfg.tun_name);
            if let Some(parent) = tun_class.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::create_dir_all(&tun_class)?;
            None
        } else {
            let h = hulios_tun::create_tun_interface(&tun_cfg).await?;
            let fd = h.raw_fd;
            *tun_handle_shared.lock().unwrap() = Some(h);
            Some(fd)
        };

        let ipv6_label = match cfg.ipv6 {
            hulios_cli::Ipv6Mode::Tor => "",
            hulios_cli::Ipv6Mode::Disable => " (IPv6: skipped)",
        };
        println!("[Phase  7/14] Creating TUN interface{}...{} [OK]",
            ipv6_label,
            " ".repeat(17 - ipv6_label.len()));

        // 6. AddRoutingRules
        check_fail!("AddRoutingRules");
        crate::take_routing_snapshot().await?;
        if std::env::var("HULIOS_MOCK_RECOVERY").is_err() {
            hulios_tun::add_policy_rules(cfg.fwmark, &cfg.tun_name, cfg.ipv6 == hulios_cli::Ipv6Mode::Tor).await?;
        }

        println!("[Phase  8/14] Installing routing rules...               [OK]");

        // 7. OverrideDns
        check_fail!("OverrideDns");
        let mut dns_udp_sockets = Vec::new();
        let mut dns_tcp_listeners = Vec::new();

        if std::env::var("HULIOS_MOCK_RECOVERY").is_err() {
            let listen_ip = hulios_dns::detect::hickory_bind_ip();
            let listen_addr = format!("{}:53", listen_ip);
            tracing::info!("Pre-binding DNS listener socket to {}...", listen_addr);
            let udp_socket = tokio::net::UdpSocket::bind(&listen_addr).await
                .context(format!("Failed to bind DNS UDP socket to {}", listen_addr))?;
            let tcp_listener = tokio::net::TcpListener::bind(&listen_addr).await
                .context(format!("Failed to bind DNS TCP listener to {}", listen_addr))?;
            dns_udp_sockets.push(udp_socket);
            dns_tcp_listeners.push(tcp_listener);

            if cfg.ipv6 == hulios_cli::Ipv6Mode::Tor {
                let ipv6_addr = format!("[{}]:53", hulios_common::HULIOS_DNS_IPV6_MAGIC_STR);
                tracing::info!("Pre-binding IPv6 DNS listener socket to {}...", ipv6_addr);
                match tokio::net::UdpSocket::bind(&ipv6_addr).await {
                    Ok(udp_socket) => {
                        match tokio::net::TcpListener::bind(&ipv6_addr).await {
                            Ok(tcp_listener) => {
                                dns_udp_sockets.push(udp_socket);
                                dns_tcp_listeners.push(tcp_listener);
                            }
                            Err(e) => {
                                tracing::warn!("Failed to bind IPv6 DNS TCP listener to {}: {:?}", ipv6_addr, e);
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to bind IPv6 DNS UDP socket to {}: {:?}", ipv6_addr, e);
                    }
                }
            }
        }
        println!("[Phase  9/14] Overriding system DNS...                  [OK]");

        // 8. ApplySysctls
        check_fail!("ApplySysctls");
        let sysctl_cfg = hulios_tun::SysctlConfig {
            ipv6: match cfg.ipv6 {
                hulios_cli::Ipv6Mode::Disable => hulios_tun::Ipv6Mode::Disable,
                hulios_cli::Ipv6Mode::Tor => hulios_tun::Ipv6Mode::Tor,
            },
        };
        let phys_iface = crate::detect_phys_iface();
        let _saved_sysctls = if std::env::var("HULIOS_MOCK_RECOVERY").is_ok() {
            tracing::info!("[Mock] Applying sysctl hardening");
            None
        } else {
            let saved = hulios_tun::apply_sysctl_hardening(&sysctl_cfg, &phys_iface)?;
            *saved_sysctls_shared.lock().unwrap() = Some(saved.clone());
            Some(saved)
        };

        println!("[Phase 10/14] Applying sysctl settings...               [OK]");

        // 9. HardenSystem
        check_fail!("HardenSystem");
        let _avahi_saved = if std::env::var("HULIOS_MOCK_RECOVERY").is_ok() {
            tracing::info!("[Mock] Suppressing Avahi");
            None
        } else {
            let saved = hulios_netcompat::suppress_avahi().await?;
            *avahi_saved_shared.lock().unwrap() = Some(saved.clone());
            Some(saved)
        };
        if std::env::var("HULIOS_MOCK_RECOVERY").is_err() {
            hulios_netcompat::write_nm_unmanaged_conf(&cfg.tun_name).await?;
            hulios_netcompat::install_nm_dispatcher(cfg.fwmark, &cfg.tun_name, cfg.ipv6 == hulios_cli::Ipv6Mode::Tor).await?;
        }

        println!("[Phase 11/14] Hardening system...                       [OK]");

        if cfg.time_sync.is_some() {
            tracing::info!("Disabling system NTP daemon before dropping privileges...");
            if let Err(e) = crate::time_sync::set_ntp_enabled(false) {
                tracing::warn!("Failed to disable system NTP daemon: {:?}", e);
            }
        }

        // 10. DropPrivileges
        check_fail!("DropPrivileges");
        chown_recursive_to_nobody(std::path::Path::new("/var/lib/hulios/arti"))?;
        chown_recursive_to_nobody(std::path::Path::new("/run/hulios"))?;

        if let Some(hulios_cli::PrivilegeCallback(ref callback)) = cfg.privilege_callback {
            callback().context("Privilege drop callback failed")?;
        }
        println!("[Phase 12/14] Dropping privileges...                    [OK]");

        // 11. BootstrapArti
        check_fail!("BootstrapArti");
        let status_handle = hulios_onionmasq::TorStatusHandle::new();
        *status_handle_shared.lock().unwrap() = Some(status_handle.clone());

        // 12. StartOnionmasq
        check_fail!("StartOnionmasq");
        if std::env::var("HULIOS_MOCK_ARTI").is_ok() || std::env::var("HULIOS_MOCK_RECOVERY").is_ok() {
            tracing::info!("[Mock] Started onionmasq");
        } else {
            let onionmasq_cfg = hulios_onionmasq::OnionmasqConfig {
                storage_dir: Some("/var/lib/hulios/arti".to_string()),
                exit_nodes: cfg.exit_nodes.clone(),
                bootstrap_timeout: Some(std::time::Duration::from_secs(cfg.bootstrap_timeout)),
                socks_port: cfg.socks_port.or(Some(9050)),
            };
            let tun_raw_fd = tun_raw_fd.ok_or_else(|| anyhow::anyhow!("TUN handle missing raw FD"))?;
            let onionmasq_handle = hulios_onionmasq::start_onionmasq(tun_raw_fd, &onionmasq_cfg, status_handle).await?;
            *onionmasq_handle_shared.lock().unwrap() = Some(onionmasq_handle);



            let tor_client = {
                let onionmasq_ref = onionmasq_handle_shared.lock().unwrap();
                onionmasq_ref.as_ref().map(|h| h.tor_client.clone())
            };
            if let Some(tor_client) = tor_client {
                if !dns_udp_sockets.is_empty() {
                    tracing::info!("Starting parallel DNS resolver...");
                    let dns_h = hulios_dns::resolver::start_dns_resolver_with_sockets(
                        tor_client,
                        dns_udp_sockets,
                        dns_tcp_listeners,
                    ).await?;
                    let mut onionmasq_ref = onionmasq_handle_shared.lock().unwrap();
                    if let Some(ref mut handle) = *onionmasq_ref {
                        handle.set_dns_task(dns_h.handle);
                    }
                }
            }
        }

        let consensus_window = {
            let onionmasq_ref = onionmasq_handle_shared.lock().unwrap();
            onionmasq_ref.as_ref().and_then(|h| h.consensus_window)
        };

        if let Some(mode) = cfg.time_sync {
            tracing::info!("Executing automatic startup time synchronization...");
            match crate::time_sync::run_time_sync(mode, consensus_window).await {
                Ok(msg) => tracing::info!("Time synchronization successful: {}", msg),
                Err(e) => tracing::warn!("Time synchronization failed: {:?}", e),
            }
        }

        // 13. WriteStateFile
        check_fail!("WriteStateFile");
        let ntp_was_enabled = if cfg.time_sync.is_some() {
            Some(crate::time_sync::query_ntp_enabled())
        } else {
            None
        };
        let state = RunningState {
            fwmark: cfg.fwmark,
            tun_name: cfg.tun_name.clone(),
            last_signal: "running".to_string(),
            saved_sysctls: saved_sysctls_shared.lock().unwrap().clone(),
            avahi_saved: avahi_saved_shared.lock().unwrap().clone(),
            ntp_was_enabled,
            strict_lockdown: cfg.strict_lockdown,
            ipv6: Some(cfg.ipv6),
        };
        let state_str = toml::to_string(&state)?;
        let state_path = get_state_toml_path();
        if let Some(parent) = state_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&state_path, state_str)?;


        // 13b. StartControlSocket
        check_fail!("StartControlSocket");
        let sock_path = get_control_sock_path();
        if let Some(parent) = sock_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if sock_path.exists() {
            tracing::info!("Control socket file exists. Probing to check if stale...");
            match tokio::net::UnixStream::connect(&sock_path).await {
                Ok(_) => {
                    anyhow::bail!("Another instance of hulios is already running (control socket is active)");
                }
                Err(e) => {
                    tracing::info!("Control socket connection failed ({:?}). Removing stale control socket file.", e);
                    let _ = std::fs::remove_file(&sock_path);
                }
            }
        }
        let listener = tokio::net::UnixListener::bind(&sock_path)?;
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = std::fs::metadata(&sock_path) {
                let mut perms = meta.permissions();
                perms.set_mode(0o666); // World-readable: status is public. Sensitive cmds (stop/new-circuit/time-sync) are individually guarded by peer_cred UID checks.

                let _ = std::fs::set_permissions(&sock_path, perms);
            }
        }

        let client_opt = arti_client_shared.lock().unwrap().clone();
        let status_opt = status_handle_shared.lock().unwrap().clone();
        let start_time_now = std::time::SystemTime::now();

        let control_task = tokio::spawn(crate::watchdog::run_control_socket(
            listener,
            client_opt,
            status_opt,
            start_time_now,
        ));
        *control_socket_task_shared.lock().unwrap() = Some(control_task);


        println!("[Phase 13/14] Bootstrapping onionmasq...                [OK]");

        // 14. NotifySystemd
        check_fail!("NotifySystemd");
        if std::env::var("NOTIFY_SOCKET").is_ok() {
            if let Err(e) = sd_notify::notify(false, &[sd_notify::NotifyState::Ready]) {
                tracing::warn!("Failed to notify systemd: {:?}", e);
            }
        }
        println!("[Phase 14/14] Notifying systemd...                      [OK]");

        let route_watchdog = tokio::spawn(crate::watchdog::run_route_watchdog(cfg.fwmark, cfg.tun_name.clone(), cfg.ipv6 == hulios_cli::Ipv6Mode::Tor));

        let exit_node_str = if let Some(ref nodes) = cfg.exit_nodes {
            format!("{} ({})", nodes, get_country_name(nodes))
        } else {
            "Any".to_string()
        };

        let socks_port_val = cfg.socks_port.unwrap_or(9050);

        let ipv6_status = match cfg.ipv6 {
            hulios_cli::Ipv6Mode::Tor => "Enabled (routed through Tor)",
            hulios_cli::Ipv6Mode::Disable => "Disabled (auto-detected or user-set)",
        };

        println!("============================================================");
        println!(" Hulios Started Successfully (Headless Mode)");
        println!("============================================================");
        println!("  Interface:   {} (10.242.0.2)", cfg.tun_name);
        println!("  SOCKS Proxy: 127.0.0.1:{}", socks_port_val);
        println!("  DNS Server:  127.0.0.1:53 (Hijacked)");
        println!("  IPv6:        {}", ipv6_status);
        println!("  Exit Node:   {}", exit_node_str);
        println!("============================================================");
        println!("Press Ctrl+C to stop, or press 'N' to request a new Tor circuit.");

        let mut active = crate::get_active_handles().lock().unwrap();
        *active = Some(ActiveHandles {
            ebpf_handles: ebpf_handles_shared.lock().unwrap().take().unwrap(),
            tun_handle: tun_handle_shared.lock().unwrap().take(),
            saved_sysctls: saved_sysctls_shared.lock().unwrap().take(),
            avahi_saved: avahi_saved_shared.lock().unwrap().take(),
            arti_client: arti_client_shared.lock().unwrap().take(),
            onionmasq_handle: onionmasq_handle_shared.lock().unwrap().take(),
            tor_status_handle: status_handle_shared.lock().unwrap().take(),
            dns_handle: None,
            control_socket_task: control_socket_task_shared.lock().unwrap().take(),
            route_watchdog_task: Some(route_watchdog),
        });

        Ok::<RunningState, anyhow::Error>(RunningState {
            fwmark: cfg.fwmark,
            tun_name: cfg.tun_name,
            last_signal: "running".to_string(),
            saved_sysctls: saved_sysctls_shared.lock().unwrap().clone(),
            avahi_saved: avahi_saved_shared.lock().unwrap().clone(),
            ntp_was_enabled,
            strict_lockdown: cfg.strict_lockdown,
            ipv6: Some(cfg.ipv6),
        })
    }.await;

    match result {
        Ok(state) => Ok(state),
        Err(e) => {
            tracing::error!("Startup failed: {:?}", e);
            Err(e)
        }
    }
}
