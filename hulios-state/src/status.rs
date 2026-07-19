use anyhow::Result;

pub async fn display_status() -> Result<()> {
    let state_path = crate::types::get_state_toml_path();
    if !state_path.exists() {
        return Err(anyhow::anyhow!("Hulios is not running"));
    }

    let sock_path = crate::types::get_control_sock_path();
    if !sock_path.exists() {
        return Err(anyhow::anyhow!("Hulios is not running"));
    }

    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixStream;

    let mut stream = match UnixStream::connect(&sock_path).await {
        Ok(s) => s,
        Err(_) => {
            return Err(anyhow::anyhow!("Hulios is not running"));
        }
    };

    let req = crate::types::StatusRequest {
        cmd: "status".to_string(),
    };
    let req_str = format!("{}\n", serde_json::to_string(&req)?);

    if stream.write_all(req_str.as_bytes()).await.is_err() {
        return Err(anyhow::anyhow!("Hulios is not running"));
    }

    let mut reader = BufReader::new(stream);
    let mut response_line = String::new();
    if reader.read_line(&mut response_line).await.is_err() {
        return Err(anyhow::anyhow!("Hulios is not running"));
    }

    let response: crate::types::StatusResponse = match serde_json::from_str(&response_line) {
        Ok(r) => r,
        Err(_) => {
            return Err(anyhow::anyhow!("Hulios is not running"));
        }
    };

    // Calculate consensus age
    let consensus_hours = response.consensus_age_secs / 3600;
    let consensus_mins = (response.consensus_age_secs % 3600) / 60;
    let consensus_age_str = format!("{} hours {} minutes", consensus_hours, consensus_mins);

    // Calculate uptime
    let uptime_hours = response.uptime_secs / 3600;
    let uptime_mins = (response.uptime_secs % 3600) / 60;
    let uptime_secs = response.uptime_secs % 60;
    let uptime_str = format!(
        "{} hours {} minutes {} seconds",
        uptime_hours, uptime_mins, uptime_secs
    );

    // Display IP
    let exit_ip_str = match crate::watchdog::fetch_exit_ip().await {
        Ok(ip) => ip,
        Err(_) => "unavailable".to_string(),
    };

    println!("{:<17} {}%", "Tor Bootstrap:", response.bootstrap);
    println!("{:<17} {}", "Consensus Age:", consensus_age_str);
    println!("{:<17} {}", "Current Exit IP:", exit_ip_str);
    println!("{:<17} {}", "Uptime:", uptime_str);

    Ok(())
}
