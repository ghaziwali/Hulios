pub mod config;
pub mod ebpf;
pub mod privileges;
pub mod signals;

use clap::Parser;
use std::sync::Arc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    // Ensure runtime directory exists for state and supervisor sockets
    let run_dir = std::path::Path::new("/run/hulios");
    if !run_dir.exists() {
        let _ = std::fs::create_dir_all(run_dir);
    }
    if let Ok(meta) = std::fs::metadata(run_dir) {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = meta.permissions();
        perms.set_mode(0o755);
        let _ = std::fs::set_permissions(run_dir, perms);
    }

    let cli = hulios_cli::Cli::parse();

    match cli.command {
        hulios_cli::Commands::Start(start_args) => {
            if std::env::var("HULIOS_IS_WORKER").is_err() {
                config::ensure_default_config_exists();
                tracing::info!("Hulios Supervisor: Starting worker process...");
                #[allow(unused_imports)]
                use std::os::unix::process::CommandExt;
                let mut cmd = tokio::process::Command::new(std::env::current_exe()?);
                cmd.args(std::env::args_os().skip(1))
                    .env("HULIOS_IS_WORKER", "1");
                let mut child = cmd.spawn()?;

                let original_termios = if nix::unistd::isatty(libc::STDIN_FILENO).unwrap_or(false) {
                    let fd = unsafe { std::os::fd::BorrowedFd::borrow_raw(libc::STDIN_FILENO) };
                    if let Ok(mut termios) = nix::sys::termios::tcgetattr(fd) {
                        let original = termios.clone();
                        termios
                            .local_flags
                            .remove(nix::sys::termios::LocalFlags::ICANON);
                        termios
                            .local_flags
                            .remove(nix::sys::termios::LocalFlags::ECHO);
                        let _ = nix::sys::termios::tcsetattr(
                            fd,
                            nix::sys::termios::SetArg::TCSANOW,
                            &termios,
                        );
                        Some(original)
                    } else {
                        None
                    }
                } else {
                    None
                };

                let child_pid_for_stdin = child.id();
                tokio::spawn(async move {
                    use tokio::io::AsyncReadExt;
                    if !nix::unistd::isatty(libc::STDIN_FILENO).unwrap_or(false) {
                        return;
                    }
                    let mut stdin = tokio::io::stdin();
                    let mut buf = [0u8; 1];
                    while stdin.read_exact(&mut buf).await.is_ok() {
                        let c = buf[0];
                        if c == b'n' || c == b'N' {
                            if let Some(pid) = child_pid_for_stdin {
                                let _ = nix::sys::signal::kill(
                                    nix::unistd::Pid::from_raw(pid as i32),
                                    nix::sys::signal::Signal::SIGUSR1,
                                );
                            }
                        }
                    }
                });

                let mut sigterm =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
                let mut sigint =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;

                let sock_path = "/run/hulios/supervisor.sock";
                let _ = std::fs::remove_file(sock_path);
                let supervisor_listener = tokio::net::UnixListener::bind(sock_path)?;
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(sock_path, std::fs::Permissions::from_mode(0o660))?;

                let status = loop {
                    tokio::select! {
                        res = child.wait() => {
                            break res?;
                        }
                        _ = sigint.recv() => {
                            tracing::debug!("Supervisor caught SIGINT. Waiting for worker process to initiate shutdown...");
                        }
                        _ = sigterm.recv() => {
                            tracing::info!("Supervisor caught SIGTERM, waiting for worker process to exit...");
                            if let Some(pid) = child.id() {
                                let _ = nix::sys::signal::kill(
                                    nix::unistd::Pid::from_raw(pid as i32),
                                    nix::sys::signal::Signal::SIGTERM,
                                );
                            }
                            let wait_res = tokio::time::timeout(
                                std::time::Duration::from_secs(5),
                                child.wait(),
                            ).await;
                            match wait_res {
                                Ok(res) => break res?,
                                Err(_) => {
                                    tracing::warn!("Worker did not exit within 5 seconds of SIGTERM. Force-killing.");
                                    if let Some(pid) = child.id() {
                                        let pgid = -(pid as i32);
                                        unsafe {
                                            libc::kill(pgid, libc::SIGKILL);
                                        }
                                    }
                                    break child.wait().await?;
                                }
                            }
                        }
                        Ok((mut stream, _)) = supervisor_listener.accept() => {
                            use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
                            let (reader, mut writer) = stream.split();
                            let mut buf_reader = BufReader::new(reader);
                            let mut line = String::new();
                            if let Ok(n) = buf_reader.read_line(&mut line).await {
                                if n > 0 {
                                    if let Ok(req) = serde_json::from_str::<hulios_state::ControlRequest>(&line) {
                                        if req.cmd == "time-sync" {
                                            match hulios_state::run_time_sync(hulios_cli::TimeSyncMode::Consensus, None).await {
                                                Ok(_) => {
                                                    let _ = writer.write_all(b"{\"status\":\"ok\"}\n").await;
                                                }
                                                Err(e) => {
                                                    let err_msg = format!("{{\"status\":\"error\",\"message\":\"{}\"}}\n", e);
                                                    let _ = writer.write_all(err_msg.as_bytes()).await;
                                                }
                                            }
                                        } else {
                                            let _ = writer.write_all(b"{\"error\":\"Unknown command\"}\n").await;
                                        }
                                    } else {
                                        let _ = writer.write_all(b"{\"error\":\"Invalid JSON\"}\n").await;
                                    }
                                }
                            }
                        }
                    }
                };

                if child.id().is_some() {
                    let grace =
                        tokio::time::timeout(std::time::Duration::from_secs(3), child.wait()).await;
                    if grace.is_err() {
                        tracing::warn!(
                            "Worker did not exit within grace period. Force-killing process group."
                        );
                    }
                }

                if let Some(pid) = child.id() {
                    let pgid = -(pid as i32);
                    unsafe {
                        libc::kill(pgid, libc::SIGKILL);
                    }
                }

                let strict_lockdown = hulios_state::read_strict_lockdown_from_state();

                if status.success() || !hulios_state::get_state_toml_path().exists() {
                    tracing::info!("Restoring system configurations...");
                    let cleanup_res = if strict_lockdown {
                        hulios_state::stop().await
                    } else {
                        hulios_state::recover().await
                    };
                    if let Err(e) = cleanup_res {
                        tracing::error!("Supervisor recovery/stop failed: {:?}", e);
                    }
                } else {
                    tracing::error!("Hulios exited abnormally. The system is locked down for security (Fail-Secure) until `sudo hulios recover` is run.");
                }

                if let Some(termios) = original_termios {
                    let fd = unsafe { std::os::fd::BorrowedFd::borrow_raw(libc::STDIN_FILENO) };
                    let _ = nix::sys::termios::tcsetattr(
                        fd,
                        nix::sys::termios::SetArg::TCSANOW,
                        &termios,
                    );
                }

                std::process::exit(status.code().unwrap_or(1));
            }

            match hulios_cli::load_and_merge_config(start_args) {
                Ok(mut cfg) => {
                    let time_sync_enabled = cfg.time_sync.is_some();
                    cfg.privilege_callback =
                        Some(hulios_cli::PrivilegeCallback(Arc::new(move || {
                            privileges::drop_privileges(time_sync_enabled)?;
                            if std::env::var("HULIOS_MOCK_RECOVERY").is_err() {
                                privileges::apply_seccomp_filter()?;
                            }
                            Ok(())
                        })));

                    cfg.seccomp_callback = None;

                    cfg.bpf_bytecode = Some(
                        aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/hulios_ebpf.bpf.o"))
                            .to_vec(),
                    );

                    match hulios_state::startup(cfg).await {
                        Ok(state) => {
                            tracing::info!("Hulios started successfully (headless mode).");
                            let res = signals::handle_signals(state).await;
                            std::process::exit(if res.is_ok() { 0 } else { 1 });
                        }
                        Err(e) => {
                            tracing::error!("Startup failed: {:?}", e);
                            std::process::exit(1);
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("Failed to load configuration: {:?}", e);
                    std::process::exit(1);
                }
            }
        }
        other_command => match other_command {
            hulios_cli::Commands::Stop => {
                let sock_path = hulios_state::get_control_sock_path();
                let mut stop_succeeded = false;
                if sock_path.exists() {
                    if let Ok(mut stream) = tokio::net::UnixStream::connect(&sock_path).await {
                        use tokio::io::{AsyncReadExt, AsyncWriteExt};
                        if stream.write_all(b"{\"cmd\":\"stop\"}\n").await.is_ok() {
                            let mut buf = [0; 256];
                            match stream.read(&mut buf).await {
                                Ok(n) if n > 0 => {
                                    let resp_str = String::from_utf8_lossy(&buf[..n]);
                                    if resp_str.contains("\"status\":\"ok\"") {
                                        stop_succeeded = true;
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }

                if !stop_succeeded {
                    tracing::warn!("Failed to connect to control socket or stop daemon gracefully. Performing fallback local teardown...");
                    hulios_state::stop().await?;
                }

                hulios_state::recover().await?;
            }
            hulios_cli::Commands::Status => {
                if let Err(e) = hulios_state::display_status().await {
                    eprintln!("{}", e);
                    if hulios_state::detect_dirty_state().await.is_dirty() {
                        eprintln!("\n\x1B[2m* Suggestion: Stale network rules detected. Run 'sudo hulios recover' to restore standard connectivity.\x1B[0m");
                    }
                    std::process::exit(1);
                }
            }
            hulios_cli::Commands::Diagnose(args) => {
                if !args.json && !nix::unistd::Uid::effective().is_root() {
                    eprintln!("\x1B[2m* Warning: Running diagnostics without root privileges. Some checks may fail due to permissions.\x1B[0m\n");
                }
                match hulios_state::run_diagnose(args.json).await {
                    Ok(output) => {
                        println!("{}", output);
                    }
                    Err(e) => {
                        eprintln!("{}", e);
                        eprintln!("\n\x1B[2m* Suggestion: Stale network rules detected. Run 'sudo hulios recover' to restore standard connectivity.\x1B[0m");
                        std::process::exit(1);
                    }
                }
            }
            hulios_cli::Commands::Recover => {
                hulios_state::recover().await?;
            }
            hulios_cli::Commands::NewCircuit(_) => {
                tracing::info!("New-circuit command is not yet fully implemented.");
            }

            hulios_cli::Commands::Start(_) => unreachable!(),
        },
    }

    Ok(())
}
