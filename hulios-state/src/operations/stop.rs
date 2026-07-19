use crate::types::*;
use anyhow::{Context, Result};
use caps::{CapSet, Capability};

fn has_net_admin_privilege() -> bool {
    nix::unistd::Uid::effective().is_root()
        || caps::has_cap(None, CapSet::Effective, Capability::CAP_NET_ADMIN).unwrap_or(false)
}

pub async fn stop() -> Result<()> {
    let state_path = get_state_toml_path();
    let state = if state_path.exists() {
        let content = std::fs::read_to_string(&state_path).context("Failed to read state file")?;
        toml::from_str::<RunningState>(&content).context("Failed to parse state file")?
    } else {
        RunningState {
            fwmark: 42,
            tun_name: "hulios0".to_string(),
            last_signal: "unknown".to_string(),
            saved_sysctls: None,
            avahi_saved: None,
            ntp_was_enabled: None,
            strict_lockdown: false,
            ipv6: None,
        }
    };
    let mode = if state.strict_lockdown {
        TeardownMode::StrictLockdown
    } else {
        TeardownMode::Normal
    };
    teardown(state, mode).await
}

pub async fn teardown(state: RunningState, mode: TeardownMode) -> Result<()> {
    println!("* Stopping Hulios VPN...");
    tracing::info!("Starting teardown sequence (mode: {:?})", mode);
    let mut errors = Vec::new();

    let mut active_handles = crate::get_active_handles().lock().unwrap().take();

    // Stop watchdogs
    if let Some(ref mut active) = active_handles {
        if let Some(task) = active.route_watchdog_task.take() {
            tracing::info!("Stopping Route watchdog...");
            task.abort();
        }
    }

    // 0. StopControlSocket
    if let Some(ref mut active) = active_handles {
        if let Some(task) = active.control_socket_task.take() {
            tracing::info!("Stopping control socket...");
            task.abort();
        }
    }
    let sock_path = get_control_sock_path();
    if sock_path.exists() {
        tracing::info!("Deleting control socket file...");
        if let Err(e) = std::fs::remove_file(&sock_path) {
            errors.push(anyhow::anyhow!(
                "Deleting control socket file failed: {:?}",
                e
            ));
        }
    }

    // 1. StopOnionmasq
    tracing::info!("Step 1/9: StopOnionmasq");
    if let Some(ref mut active) = active_handles {
        if let Some(handle) = active.onionmasq_handle.take() {
            tracing::info!("Stopping onionmasq...");
            if let Err(e) = hulios_onionmasq::stop_onionmasq(handle).await {
                errors.push(anyhow::anyhow!("StopOnionmasq failed: {:?}", e));
            }
        }
    }

    // Stop DNS Resolver
    if let Some(ref mut active) = active_handles {
        if let Some(handle) = active.dns_handle.take() {
            tracing::info!("Stopping DNS resolver...");
            handle.abort();
        }
    }
    println!("* Deactivating onionmasq & DNS resolver... [OK]");

    // 2. ShutdownArti
    tracing::info!("Step 2/9: ShutdownArti");
    if let Some(ref mut active) = active_handles {
        if let Some(client) = active.arti_client.take() {
            tracing::info!("Shutting down Arti...");
            let retire_res = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                tokio::task::spawn_blocking(move || {
                    std::mem::drop(client);
                }),
            )
            .await;
            if retire_res.is_err() {
                errors.push(anyhow::anyhow!("ShutdownArti timed out"));
            }
        }
    }

    // 3. DestroyTun
    tracing::info!("Step 3/9: DestroyTun");
    if has_net_admin_privilege() {
        if let Some(ref mut active) = active_handles {
            if let Some(handle) = active.tun_handle.take() {
                tracing::info!("Destroying TUN interface via handle...");
                if let Err(e) = hulios_tun::destroy_tun_interface(handle).await {
                    errors.push(anyhow::anyhow!("DestroyTun failed: {:?}", e));
                }
            }
        } else {
            tracing::info!("Destroying TUN interface via fallback...");
            if std::env::var("HULIOS_MOCK_RECOVERY").is_err() {
                if let Err(e) = hulios_tun::delete_link_by_name(&state.tun_name).await {
                    errors.push(anyhow::anyhow!(
                        "delete_link_by_name fallback failed: {:?}",
                        e
                    ));
                }
            } else {
                let tun_class = get_tun_class_path(&state.tun_name);
                let _ = std::fs::remove_dir_all(&tun_class);
            }
        }
    } else {
        tracing::debug!("Skipping privileged step DestroyTun (not running as root)");
    }
    println!("* Destroying {} interface... [OK]", state.tun_name);

    // 4. RemovePolicyRules
    tracing::info!("Step 4/9: RemovePolicyRules");
    if has_net_admin_privilege() {
        if std::env::var("HULIOS_MOCK_RECOVERY").is_ok() {
            tracing::info!("[Mock] Removed policy rules");
        } else {
            let strict = mode == TeardownMode::StrictLockdown;
            if let Err(e) =
                hulios_tun::remove_policy_rules_ex(state.fwmark, &state.tun_name, strict).await
            {
                errors.push(anyhow::anyhow!("RemovePolicyRules failed: {:?}", e));
            }
        }
    } else {
        tracing::debug!("Skipping privileged step RemoveRoutingRules (not running as root)");
    }
    let snapshot_path = get_routing_snapshot_path();
    if snapshot_path.exists() {
        let _ = std::fs::remove_file(snapshot_path);
    }
    println!("* Unloading policy routing rules... [OK]");

    // 6. RestoreSysctls
    tracing::info!("Step 6/9: RestoreSysctls");
    if has_net_admin_privilege() {
        if let Some(ref mut active) = active_handles {
            if let Some(saved) = active.saved_sysctls.take() {
                tracing::info!("Restoring sysctls...");
                if let Err(e) = hulios_tun::restore_sysctls(saved) {
                    errors.push(anyhow::anyhow!("RestoreSysctls failed: {:?}", e));
                }
            }
        }
    } else {
        tracing::debug!("Skipping privileged step RestoreSysctls (not running as root)");
    }
    println!("* Restoring system sysctl settings... [OK]");

    // 7. RestoreSystemdServices
    tracing::info!("Step 7/9: RestoreSystemdServices");
    if has_net_admin_privilege() {
        let rule_path = crate::types::get_udev_rules_path();
        if rule_path.exists() {
            tracing::info!("Removing udev unmanaged rules file...");
            if let Err(e) = std::fs::remove_file(&rule_path) {
                errors.push(anyhow::anyhow!(
                    "Remove udev unmanaged rules failed: {:?}",
                    e
                ));
            }
        }
        if std::env::var("HULIOS_MOCK_RECOVERY").is_err() {
            if let Err(e) = hulios_netcompat::remove_nm_unmanaged_conf().await {
                errors.push(anyhow::anyhow!("Remove NM unmanaged conf failed: {:?}", e));
            }
            if let Err(e) = hulios_netcompat::remove_nm_dispatcher().await {
                errors.push(anyhow::anyhow!("Remove NM dispatcher failed: {:?}", e));
            }
        }
        if let Some(ref mut active) = active_handles {
            if let Some(saved) = active.avahi_saved.take() {
                tracing::info!("Restoring Avahi...");
                if let Err(e) = hulios_netcompat::restore_avahi(&saved).await {
                    errors.push(anyhow::anyhow!("Restore Avahi failed: {:?}", e));
                }
            }
        }
    } else {
        tracing::debug!("Skipping privileged step RestoreSystemdServices (not running as root)");
    }
    println!("* Restoring system network configuration... [OK]");

    // 8. UnloadEbpf
    tracing::info!("Step 8/9: UnloadEbpf");
    if has_net_admin_privilege() {
        if let Some(ref mut active) = active_handles {
            if let Some(handles) = active.ebpf_handles.sock_mark_link.take() {
                tracing::info!("Unloading cgroup sock mark eBPF program...");
                std::mem::drop(handles);
            }
            if let Some(handles) = active.ebpf_handles.lsm_link.take() {
                tracing::info!("Unloading LSM eBPF program...");
                std::mem::drop(handles);
            }
        }
    } else {
        tracing::debug!("Skipping privileged step DetachEbpf (not running as root)");
    }
    println!("* Unloading eBPF programs... [OK]");

    // 9. DeleteStateFile
    tracing::info!("Step 9/9: DeleteStateFile");
    let state_path = get_state_toml_path();
    if state_path.exists() {
        // Overwrite to "clean" first
        let clean_state = RunningState {
            fwmark: state.fwmark,
            tun_name: state.tun_name.clone(),
            last_signal: "clean".to_string(),
            saved_sysctls: None,
            avahi_saved: None,
            ntp_was_enabled: state.ntp_was_enabled,
            strict_lockdown: state.strict_lockdown,
            ipv6: None,
        };
        if let Ok(clean_str) = toml::to_string(&clean_state) {
            let _ = std::fs::write(&state_path, clean_str);
        }
        tracing::info!("Deleting state file...");
        if let Err(e) = std::fs::remove_file(&state_path) {
            errors.push(anyhow::anyhow!("DeleteStateFile failed: {:?}", e));
        }
    }

    if !errors.is_empty() {
        let err_msg = errors
            .into_iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("; ");
        return Err(anyhow::anyhow!("Teardown encountered errors: {}", err_msg));
    }

    if !has_net_admin_privilege() {
        tracing::warn!("Teardown was run without root privileges; some network cleanups were skipped and must be handled via recovery");
    }

    println!("* Teardown complete.");
    Ok(())
}

pub async fn stop_application_only() -> Result<()> {
    tracing::info!("Stopping application-level handlers only...");
    let mut errors = Vec::new();
    let mut active_handles = crate::get_active_handles().lock().unwrap().take();

    if let Some(ref mut active) = active_handles {
        // Stop DNS Resolver
        if let Some(handle) = active.dns_handle.take() {
            tracing::info!("Stopping DNS resolver...");
            handle.abort();
        }

        // Stop onionmasq
        if let Some(handle) = active.onionmasq_handle.take() {
            tracing::info!("Stopping onionmasq...");
            if let Err(e) = hulios_onionmasq::stop_onionmasq(handle).await {
                errors.push(anyhow::anyhow!("StopOnionmasq failed: {:?}", e));
            }
        }

        // Shutdown Arti client
        if let Some(client) = active.arti_client.take() {
            tracing::info!("Shutting down Arti...");
            let retire_res = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                tokio::task::spawn_blocking(move || {
                    std::mem::drop(client);
                }),
            )
            .await;
            if retire_res.is_err() {
                errors.push(anyhow::anyhow!("ShutdownArti timed out"));
            }
        }
    }

    if !errors.is_empty() {
        let err_msg = errors
            .into_iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("; ");
        return Err(anyhow::anyhow!(
            "Stop application only encountered errors: {}",
            err_msg
        ));
    }

    Ok(())
}
