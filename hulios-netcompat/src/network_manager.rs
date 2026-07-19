use anyhow::{Context, Result};
use std::fs;
use std::path::Path;
use tokio::process::Command;

const NM_CONF_PATH: &str = "/etc/NetworkManager/conf.d/99-hulios-unmanaged.conf";
const NM_DISPATCHER_PATH: &str = "/etc/NetworkManager/dispatcher.d/99-hulios";

fn get_nm_conf_path() -> String {
    std::env::var("HULIOS_NM_CONF_PATH").unwrap_or_else(|_| NM_CONF_PATH.to_string())
}

fn get_nm_dispatcher_path() -> String {
    std::env::var("HULIOS_NM_DISPATCHER_PATH").unwrap_or_else(|_| NM_DISPATCHER_PATH.to_string())
}

async fn run_nmcli_reload() -> Result<()> {
    match Command::new("nmcli")
        .args(["general", "reload"])
        .status()
        .await
    {
        Ok(status) => {
            if !status.success() {
                tracing::warn!(
                    "nmcli general reload returned non-zero exit status: {:?}",
                    status.code()
                );
            }
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::info!("nmcli command not found, skipping reload");
            Ok(())
        }
        Err(e) => Err(e).context("Failed to execute nmcli general reload"),
    }
}

pub async fn write_nm_unmanaged_conf(tun_name: &str) -> Result<()> {
    write_nm_unmanaged_conf_ex(tun_name, false).await
}

pub async fn write_nm_unmanaged_conf_ex(tun_name: &str, connectivity_enabled: bool) -> Result<()> {
    let path_str = get_nm_conf_path();
    let path = Path::new(&path_str);

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directories for NM config: {:?}", parent))?;
    }

    let content = format!(
        "[keyfile]\nunmanaged-devices=interface-name:{}\n\n[connectivity]\nenabled={}\n",
        tun_name, connectivity_enabled
    );

    fs::write(path, content)
        .with_context(|| format!("Failed to write NM unmanaged config to {:?}", path))?;

    run_nmcli_reload().await?;

    Ok(())
}

pub async fn remove_nm_unmanaged_conf() -> Result<()> {
    let path_str = get_nm_conf_path();
    let path = Path::new(&path_str);

    if path.exists() {
        fs::remove_file(path)
            .with_context(|| format!("Failed to remove NM config file at {:?}", path))?;
    }

    run_nmcli_reload().await?;

    Ok(())
}

pub async fn install_nm_dispatcher(fwmark: u32, tun_name: &str, ipv6_enabled: bool) -> Result<()> {
    let path_str = get_nm_dispatcher_path();
    let path = Path::new(&path_str);

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "Failed to create directories for NM dispatcher: {:?}",
                parent
            )
        })?;
    }

    let script_content = format!(
        r#"#!/bin/bash
# Hulios routing integrity enforcer
# shellcheck disable=SC2034
IFACE="$1"
EVENT="$2"
[ "$EVENT" = "up" ] || [ "$EVENT" = "dhcp4-change" ] || exit 0
# Only enforce routing rules while Hulios daemon is actively running
test -f /run/hulios/state.toml || exit 0
ip rule show | grep -q "fwmark 0x{:x}" || ip rule add fwmark {} lookup main priority 100
ip rule show | grep -q "lookup 100" || ip rule add from all lookup 100 priority 200
ip route show table 100 | grep -q "default" || ip route add default dev {} table 100
"#,
        fwmark, fwmark, tun_name
    );

    fs::write(path, script_content)
        .with_context(|| format!("Failed to write NM dispatcher script to {:?}", path))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path)
            .with_context(|| format!("Failed to read metadata of {:?}", path))?
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms)
            .with_context(|| format!("Failed to set permissions on {:?}", path))?;
    }

    // Spawn iwd monitor task (skipped gracefully on D-Bus connection error or missing iwd)
    let tun_name_clone = tun_name.to_string();
    tokio::spawn(async move {
        if let Err(e) =
            crate::iwd::monitor_iwd_station_signals(fwmark, tun_name_clone, ipv6_enabled).await
        {
            tracing::debug!("iwd station monitor skipped or stopped: {:?}", e);
        }
    });

    Ok(())
}

pub async fn remove_nm_dispatcher() -> Result<()> {
    let path_str = get_nm_dispatcher_path();
    let path = Path::new(&path_str);

    if path.exists() {
        fs::remove_file(path)
            .with_context(|| format!("Failed to remove NM dispatcher script at {:?}", path))?;
    }

    Ok(())
}
