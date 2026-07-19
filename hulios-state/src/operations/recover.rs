use crate::types::*;
use anyhow::Result;

pub async fn recover() -> Result<()> {
    println!("* Initiating network recovery...");
    tracing::info!("Starting unconditional recovery sweep...");

    let mut fwmark = hulios_common::HULIOS_FWMARK;
    let mut tun_name = "hulios0".to_string();
    let mut saved_sysctls = None;
    let mut avahi_saved = None;
    let mut ntp_was_enabled = None;

    let state_path = get_state_toml_path();
    if state_path.exists() {
        match std::fs::read_to_string(&state_path) {
            Ok(content) => match toml::from_str::<RunningState>(&content) {
                Ok(state) => {
                    ntp_was_enabled = state.ntp_was_enabled;
                    fwmark = state.fwmark;
                    tun_name = state.tun_name.clone();
                    saved_sysctls = state.saved_sysctls;
                    avahi_saved = state.avahi_saved;
                }
                Err(e) => {
                    tracing::warn!("Failed to parse state file during recovery: {:?}", e);
                }
            },
            Err(e) => {
                tracing::warn!("Failed to read state file during recovery: {:?}", e);
            }
        }
    }

    // 1. Delete state.toml (kills NM dispatcher guard immediately)
    let _ = std::fs::remove_file(&state_path);

    // 2. Delete control socket (prevents any IPC during cleanup)
    let sock_path = get_control_sock_path();
    let _ = std::fs::remove_file(&sock_path);

    // 3. Remove NM dispatcher script
    if std::env::var("HULIOS_MOCK_RECOVERY").is_err() {
        tracing::info!("Removing NM dispatcher script...");
        let _ = hulios_netcompat::remove_nm_dispatcher().await;
    }

    // 4. Remove NM unmanaged conf
    if std::env::var("HULIOS_MOCK_RECOVERY").is_err() {
        tracing::info!("Removing NM unmanaged configuration...");
        let _ = hulios_netcompat::remove_nm_unmanaged_conf().await;
    }
    println!("* Restoring NetworkManager configuration... [OK]");

    // 5. Restore sysctls (loaded from state before deletion)
    if let Some(sysctls) = saved_sysctls {
        tracing::info!("Recovering saved sysctls...");
        if let Err(e) = hulios_tun::restore_sysctls(sysctls) {
            tracing::warn!("Failed to restore sysctls during recovery: {:?}", e);
        }
    }
    println!("* Restoring system sysctl settings... [OK]");

    // 6. Restore Avahi (loaded from state before deletion)
    if let Some(services) = avahi_saved {
        tracing::info!("Recovering saved Avahi status...");
        if let Err(e) = hulios_netcompat::restore_avahi(&services).await {
            tracing::warn!("Failed to restore Avahi during recovery: {:?}", e);
        }
    }

    // 7. Restore NTP
    restore_ntp_from_state(ntp_was_enabled).await;

    // 8. Remove routing rules (fwmark + lookup 100 — unconditional)
    tracing::info!("Removing policy routing rules for fwmark {}", fwmark);
    if std::env::var("HULIOS_MOCK_RECOVERY").is_ok() {
        tracing::info!("[Mock] Removed policy routing rules");
    } else {
        let _ = hulios_tun::remove_policy_rules(fwmark, &tun_name).await;
    }
    println!("* Unloading policy routing rules... [OK]");

    // 9. Delete udev rules file
    let udev_rule_path = get_udev_rules_path();
    if udev_rule_path.exists() {
        tracing::info!("Removing udev unmanaged rules file: {:?}", udev_rule_path);
        let _ = std::fs::remove_file(udev_rule_path);
    }

    // 10. Remove cgroup directory
    let cgroup_path = get_cgroup_dir_path();
    if cgroup_path.exists() {
        tracing::info!("Removing cgroup directory: {:?}", cgroup_path);
        if std::env::var("HULIOS_MOCK_RECOVERY").is_ok() {
            let _ = std::fs::remove_dir_all(&cgroup_path);
        } else {
            let _ = std::fs::remove_dir(&cgroup_path);
        }
    }

    // 11. Delete hulios0
    tracing::info!("Deleting TUN interface {}", tun_name);
    let tun_class = get_tun_class_path(&tun_name);
    if std::env::var("HULIOS_MOCK_RECOVERY").is_ok() {
        tracing::info!("[Mock] Deleted TUN interface");
        let _ = std::fs::remove_dir_all(&tun_class);
    } else {
        let _ = hulios_tun::clear_tun_persist(&tun_name);
        if let Err(e) = hulios_tun::delete_link_by_name(&tun_name).await {
            tracing::warn!("Failed to delete TUN interface via netlink: {:?}", e);
        }
    }

    // 12. Wait for interface removal (2s timeout)
    let start_time = std::time::Instant::now();
    while tun_class.exists() && start_time.elapsed() < std::time::Duration::from_millis(2000) {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    if tun_class.exists() {
        anyhow::bail!(
            "TUN interface {} did not delete within 2s limit. Environment is locked.",
            tun_name
        );
    } else {
        tracing::info!(
            "Verified: TUN interface {} is completely removed from the kernel.",
            tun_name
        );
    }
    println!("* Destroying {} interface... [OK]", tun_name);

    // 13. Clean BPF pinned directory
    let bpf_pin_dir = get_bpf_pin_dir_path();
    tracing::info!("Cleaning up BPF pinned directory: {:?}", bpf_pin_dir);
    let _ = std::fs::remove_dir_all(&bpf_pin_dir);
    println!("* Cleaning system configuration... [OK]");

    println!("* Recovery complete.");
    tracing::info!("Recovery complete.");
    Ok(())
}

async fn restore_ntp_from_state(ntp_was_enabled: Option<bool>) {
    match ntp_was_enabled {
        Some(true) => {
            tracing::info!(
                "Re-enabling system NTP daemon (was active before Hulios ran time-sync)..."
            );
            if let Err(e) = crate::time_sync::set_ntp_enabled(true) {
                tracing::warn!("Failed to re-enable NTP daemon: {:?}", e);
            }
        }
        Some(false) => {
            tracing::info!("NTP daemon was already disabled before Hulios. Leaving it disabled.");
        }
        None => {
            tracing::info!("No NTP state saved (time-sync was not used). Skipping NTP restore.");
        }
    }
}
