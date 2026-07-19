use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::process::Command;
use zbus::{proxy, Connection};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SavedSystemdServices {
    pub avahi_was_active: bool,
}

#[proxy(
    interface = "org.freedesktop.systemd1.Manager",
    default_service = "org.freedesktop.systemd1",
    default_path = "/org/freedesktop/systemd1"
)]
trait SystemdManager {
    fn get_unit(&self, name: &str) -> zbus::Result<zbus::zvariant::OwnedObjectPath>;
    fn stop_unit(&self, name: &str, mode: &str) -> zbus::Result<zbus::zvariant::OwnedObjectPath>;
    fn start_unit(&self, name: &str, mode: &str) -> zbus::Result<zbus::zvariant::OwnedObjectPath>;
}

#[proxy(
    interface = "org.freedesktop.systemd1.Unit",
    default_service = "org.freedesktop.systemd1"
)]
trait SystemdUnit {
    #[zbus(property)]
    fn active_state(&self) -> zbus::Result<String>;
}

async fn is_avahi_active_dbus() -> Result<bool> {
    let conn = Connection::system().await?;
    let manager = SystemdManagerProxy::new(&conn).await?;
    match manager.get_unit("avahi-daemon.service").await {
        Ok(path) => {
            let unit = SystemdUnitProxy::builder(&conn).path(path)?.build().await?;
            let state = unit.active_state().await?;
            Ok(state == "active")
        }
        Err(e) => {
            tracing::debug!("Failed to get unit avahi-daemon.service via D-Bus: {:?}", e);
            Ok(false)
        }
    }
}

async fn stop_avahi_dbus() -> Result<()> {
    let conn = Connection::system().await?;
    let manager = SystemdManagerProxy::new(&conn).await?;
    manager.stop_unit("avahi-daemon.service", "replace").await?;
    Ok(())
}

async fn start_avahi_dbus() -> Result<()> {
    let conn = Connection::system().await?;
    let manager = SystemdManagerProxy::new(&conn).await?;
    manager
        .start_unit("avahi-daemon.service", "replace")
        .await?;
    Ok(())
}

async fn is_avahi_active_cmd() -> Result<bool> {
    match Command::new("systemctl")
        .args(["is-active", "avahi-daemon.service"])
        .output()
        .await
    {
        Ok(output) => {
            let status_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
            Ok(status_str == "active")
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::info!("systemctl command not found, assuming avahi is inactive");
            Ok(false)
        }
        Err(e) => Err(e).context("Failed to execute systemctl is-active"),
    }
}

async fn stop_avahi_cmd() -> Result<()> {
    let status = Command::new("systemctl")
        .args(["stop", "avahi-daemon.service"])
        .status()
        .await
        .context("Failed to execute systemctl stop")?;
    if !status.success() {
        tracing::warn!("systemctl stop avahi-daemon.service returned non-zero status");
    }
    Ok(())
}

async fn start_avahi_cmd() -> Result<()> {
    let status = Command::new("systemctl")
        .args(["start", "avahi-daemon.service"])
        .status()
        .await
        .context("Failed to execute systemctl start")?;
    if !status.success() {
        tracing::warn!("systemctl start avahi-daemon.service returned non-zero status");
    }
    Ok(())
}

pub async fn suppress_avahi() -> Result<SavedSystemdServices> {
    let active = if std::env::var("HULIOS_FORCE_SYSTEMCTL").as_deref() == Ok("true") {
        is_avahi_active_cmd().await?
    } else {
        match is_avahi_active_dbus().await {
            Ok(act) => act,
            Err(e) => {
                tracing::debug!(
                    "D-Bus check failed: {:?}. Falling back to systemctl command.",
                    e
                );
                is_avahi_active_cmd().await?
            }
        }
    };

    if active {
        tracing::info!("avahi-daemon is active. Stopping it...");
        if std::env::var("HULIOS_FORCE_SYSTEMCTL").as_deref() == Ok("true") {
            stop_avahi_cmd().await?;
        } else {
            match stop_avahi_dbus().await {
                Ok(()) => {}
                Err(e) => {
                    tracing::debug!(
                        "D-Bus stop failed: {:?}. Falling back to systemctl command.",
                        e
                    );
                    stop_avahi_cmd().await?;
                }
            }
        }
    }

    Ok(SavedSystemdServices {
        avahi_was_active: active,
    })
}

pub async fn restore_avahi(saved: &SavedSystemdServices) -> Result<()> {
    if saved.avahi_was_active {
        tracing::info!("Restoring avahi-daemon to active state...");
        if std::env::var("HULIOS_FORCE_SYSTEMCTL").as_deref() == Ok("true") {
            start_avahi_cmd().await?;
        } else {
            match start_avahi_dbus().await {
                Ok(()) => {}
                Err(e) => {
                    tracing::debug!(
                        "D-Bus start failed: {:?}. Falling back to systemctl command.",
                        e
                    );
                    start_avahi_cmd().await?;
                }
            }
        }
    }
    Ok(())
}
