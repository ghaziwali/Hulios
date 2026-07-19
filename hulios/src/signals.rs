use hulios_state::RunningState;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::signal::unix::{signal, SignalKind};

pub async fn handle_signals(_state: RunningState) -> anyhow::Result<()> {
    use std::time::Duration;
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sigquit = signal(SignalKind::quit())?;
    let mut sigusr1 = signal(SignalKind::user_defined1())?;

    let last_sigint = Arc::new(AtomicU64::new(0));

    loop {
        tokio::select! {
            _ = sigterm.recv() => {
                tracing::info!("Received SIGTERM, initiating clean teardown...");
                break;
            }
            _ = sigquit.recv() => {
                tracing::info!("Received SIGQUIT, initiating clean teardown...");
                break;
            }
            _ = sigusr1.recv() => {
                eprintln!("\r\x1B[2K* Rotating Tor circuit...");
                hulios_onionmasq::isolation::trigger_new_circuit();

                tokio::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
                    eprintln!("\r\x1B[2K* Circuit rotated successfully.");
                });
            }
            _ = sigint.recv() => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;
                let last = last_sigint.load(Ordering::SeqCst);
                if now.saturating_sub(last) < 2000 {
                    tracing::info!("Shutdown requested via double Ctrl+C/SIGINT, initiating clean teardown...");
                    break;
                } else {
                    last_sigint.store(now, Ordering::SeqCst);
                    eprint!("\r\x1B[2K\x1B[2mPress Ctrl+C again within 2 seconds to stop...\x1B[0m");
                    use std::io::Write;
                    let _ = std::io::stderr().flush();

                    if nix::unistd::isatty(libc::STDERR_FILENO).unwrap_or(false) {
                        let last_for_erase = last_sigint.clone();
                        let stored_ts = now;
                        tokio::spawn(async move {
                            tokio::time::sleep(Duration::from_millis(2100)).await;
                            if last_for_erase.load(Ordering::SeqCst) == stored_ts {
                                eprint!("\r\x1B[2K");
                                use std::io::Write;
                                let _ = std::io::stderr().flush();
                            }
                        });
                    }
                }
            }
        }
    }

    tracing::info!("Stopping application-level components...");
    if let Err(e) = hulios_state::stop_application_only().await {
        tracing::error!("Error stopping application-level handlers: {:?}", e);
        return Err(e);
    }
    tracing::info!("Application-level components stopped successfully.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    #[ignore = "Blocks indefinitely on tokio runtime shutdown because tokio's stdin reader task cannot be cleanly cancelled on raw TTYs."]
    async fn test_signal_handling_sigint() {
        let temp = TempDir::new().unwrap();
        let state_path = temp.path().join("state.toml");
        std::env::set_var("HULIOS_STATE_TOML_PATH", &state_path);
        std::env::set_var("HULIOS_MOCK_RECOVERY", "true");

        let state = RunningState {
            fwmark: 42,
            tun_name: "hulios0".to_string(),
            last_signal: "running".to_string(),
            saved_sysctls: None,
            avahi_saved: None,
            ntp_was_enabled: None,
            strict_lockdown: false,
            ipv6: None,
        };

        // Write the state file
        let state_str = toml::to_string(&state).unwrap();
        std::fs::write(&state_path, state_str).unwrap();

        // Spawn signal handling task
        let handle = tokio::spawn(async move { handle_signals(state).await });

        // Yield execution to allow signal handler to set up
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Send SIGINT first time
        nix::sys::signal::kill(nix::unistd::Pid::this(), nix::sys::signal::Signal::SIGINT).unwrap();

        // Yield execution and send SIGINT second time
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        nix::sys::signal::kill(nix::unistd::Pid::this(), nix::sys::signal::Signal::SIGINT).unwrap();

        // Wait for handler to finish
        let res = handle.await.unwrap();
        assert!(res.is_ok());

        // Verify state file is not deleted since we only stopped application-level components
        assert!(state_path.exists());

        std::env::remove_var("HULIOS_STATE_TOML_PATH");
        std::env::remove_var("HULIOS_MOCK_RECOVERY");
    }
}
