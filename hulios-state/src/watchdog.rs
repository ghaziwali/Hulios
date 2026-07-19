use anyhow::Result;
use arti_client::TorClient;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::SystemTime;
use tor_rtcompat::PreferredRuntime;

#[derive(Serialize, Deserialize, Debug)]
pub struct ControlRequest {
    pub cmd: String,
    #[serde(default)]
    pub cgroup: Option<u64>,
}

static IP_CACHE: OnceLock<Mutex<(Option<String>, Option<SystemTime>)>> = OnceLock::new();

fn get_ip_cache() -> &'static Mutex<(Option<String>, Option<SystemTime>)> {
    IP_CACHE.get_or_init(|| Mutex::new((None, None)))
}

fn get_consensus_age_secs() -> u64 {
    let cache_dir = std::path::PathBuf::from("/var/lib/hulios/arti/arti-cache");
    if let Ok(entries) = std::fs::read_dir(cache_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file()
                && path
                    .file_name()
                    .map(|n| n.to_string_lossy().contains("consensus"))
                    .unwrap_or(false)
            {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    for line in content.lines() {
                        if line.starts_with("valid-after ") {
                            let parts: Vec<&str> = line.split_whitespace().collect();
                            if parts.len() >= 3 {
                                let datetime_str = format!("{} {}", parts[1], parts[2]);
                                if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(
                                    &datetime_str,
                                    "%Y-%m-%d %H:%M:%S",
                                ) {
                                    let now = chrono::Utc::now().naive_utc();
                                    if now > dt {
                                        return (now - dt).num_seconds() as u64;
                                    }
                                }
                            }
                        }
                    }
                }
                if let Ok(metadata) = entry.metadata() {
                    if let Ok(modified) = metadata.modified() {
                        if let Ok(elapsed) = modified.elapsed() {
                            return elapsed.as_secs();
                        }
                    }
                }
            }
        }
    }
    120
}

pub fn clear_ip_cache() {
    if let Ok(mut cache) = get_ip_cache().lock() {
        *cache = (None, None);
    }
}

pub async fn fetch_exit_ip() -> Result<String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()?;
    let resp = client
        .get("https://check.torproject.org/api/ip")
        .send()
        .await?;
    let val: serde_json::Value = resp.json().await?;
    if let Some(ip) = val.get("IP").and_then(|v| v.as_str()) {
        Ok(ip.to_string())
    } else {
        anyhow::bail!("Failed to parse IP from JSON response")
    }
}

pub async fn run_control_socket(
    listener: tokio::net::UnixListener,
    arti_client: Option<Arc<TorClient<PreferredRuntime>>>,
    status_handle: Option<hulios_onionmasq::TorStatusHandle>,
    start_time: SystemTime,
) {
    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let _arti_client = arti_client.clone();
                let status_handle = status_handle.clone();
                tokio::spawn(async move {
                    let peer_cred = stream.peer_cred().ok();
                    let my_uid = nix::unistd::getuid().as_raw();

                    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
                    let (reader, mut writer) = stream.into_split();
                    let mut reader = BufReader::new(reader);
                    let mut line = String::new();

                    while let Ok(n) = reader.read_line(&mut line).await {
                        if n == 0 {
                            break;
                        }

                        if let Ok(req) = serde_json::from_str::<ControlRequest>(&line) {
                            match req.cmd.as_str() {
                                "status" => {
                                    let exit_ip = "".to_string();

                                    let bootstrap =
                                        status_handle.as_ref().map(|sh| sh.percent()).unwrap_or(0);
                                    let circuits =
                                        status_handle.as_ref().map(|sh| sh.circuits()).unwrap_or(0);
                                    let consensus_age_secs = get_consensus_age_secs();
                                    let uptime_secs =
                                        start_time.elapsed().map(|d| d.as_secs()).unwrap_or(0);

                                    let resp = crate::StatusResponse {
                                        bootstrap,
                                        circuits,
                                        consensus_age_secs,
                                        exit_ip,
                                        uptime_secs,
                                    };

                                    if let Ok(resp_str) = serde_json::to_string(&resp) {
                                        let _ = writer
                                            .write_all(format!("{}\n", resp_str).as_bytes())
                                            .await;
                                    }
                                }
                                "new-circuit" => {
                                    let authorized = if let Some(ref cred) = peer_cred {
                                        cred.uid() == my_uid || cred.uid() == 0
                                    } else {
                                        false
                                    };
                                    if !authorized {
                                        let _ = writer
                                            .write_all(b"{\"error\":\"Permission denied\"}\n")
                                            .await;
                                    } else {
                                        let _ = writer
                                            .write_all(
                                                b"{\"status\":\"ok\",\"note\":\"use SIGUSR1\"}\n",
                                            )
                                            .await;
                                    }
                                }
                                "time-sync" => {
                                    let authorized = if let Some(ref cred) = peer_cred {
                                        cred.uid() == my_uid || cred.uid() == 0
                                    } else {
                                        false
                                    };
                                    if !authorized {
                                        let _ = writer
                                            .write_all(b"{\"error\":\"Permission denied\"}\n")
                                            .await;
                                    } else if std::env::var("HULIOS_MOCK_TIME_SYNC").is_ok() {
                                        let _ = writer.write_all(b"{\"status\":\"ok\"}\n").await;
                                    } else {
                                        match tokio::net::UnixStream::connect(
                                            "/run/hulios/supervisor.sock",
                                        )
                                        .await
                                        {
                                            Ok(mut sup_stream) => {
                                                if sup_stream
                                                    .write_all(b"{\"cmd\":\"time-sync\"}\n")
                                                    .await
                                                    .is_ok()
                                                {
                                                    let mut buf = [0; 512];
                                                    if let Ok(n) = sup_stream.read(&mut buf).await {
                                                        if n > 0 {
                                                            let _ =
                                                                writer.write_all(&buf[..n]).await;
                                                        } else {
                                                            let _ = writer.write_all(b"{\"error\":\"Empty response from supervisor\"}\n").await;
                                                        }
                                                    } else {
                                                        let _ = writer.write_all(b"{\"error\":\"Failed to read from supervisor\"}\n").await;
                                                    }
                                                } else {
                                                    let _ = writer.write_all(b"{\"error\":\"Failed to write to supervisor\"}\n").await;
                                                }
                                            }
                                            Err(e) => {
                                                let err_msg = format!("{{\"status\":\"error\",\"message\":\"Failed to connect to supervisor: {}\"}}\n", e);
                                                let _ = writer.write_all(err_msg.as_bytes()).await;
                                            }
                                        }
                                    }
                                }
                                "stop" => {
                                    let authorized = if let Some(ref cred) = peer_cred {
                                        cred.uid() == my_uid || cred.uid() == 0
                                    } else {
                                        false
                                    };
                                    if !authorized {
                                        let _ = writer
                                            .write_all(b"{\"error\":\"Permission denied\"}\n")
                                            .await;
                                    } else {
                                        let _ = writer.write_all(b"{\"status\":\"ok\"}\n").await;
                                        let _ = nix::sys::signal::kill(
                                            nix::unistd::Pid::this(),
                                            nix::sys::signal::Signal::SIGTERM,
                                        );
                                    }
                                }
                                _ => {
                                    let _ = writer
                                        .write_all(b"{\"error\":\"Unknown command\"}\n")
                                        .await;
                                }
                            }
                        } else {
                            let _ = writer.write_all(b"{\"error\":\"Invalid JSON\"}\n").await;
                        }
                        line.clear();
                    }
                });
            }
            Err(e) => {
                tracing::error!("Control socket accept error: {:?}", e);
            }
        }
    }
}

pub async fn run_route_watchdog(fwmark: u32, tun_name: String, ipv6_enabled: bool) {
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        if std::env::var("HULIOS_MOCK_RECOVERY").is_ok() {
            continue;
        }

        let rules_ok = crate::check_routing_rules(fwmark).await.is_ok();
        let table_ok = crate::check_table_100(&tun_name).await.is_ok();

        if !rules_ok || !table_ok {
            tracing::warn!("Route/policy rule drift detected! Restoring routing config...");
            if let Err(e) = hulios_tun::add_policy_rules(fwmark, &tun_name, ipv6_enabled).await {
                tracing::error!("Failed to restore routing config: {:?}", e);
            } else {
                tracing::info!("Routing config successfully restored.");
            }
        }
    }
}
