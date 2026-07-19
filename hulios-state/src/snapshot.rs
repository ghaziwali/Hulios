use anyhow::Result;
use serde::{Deserialize, Serialize};

pub fn detect_phys_iface() -> String {
    if let Ok(content) = std::fs::read_to_string("/proc/net/route") {
        for line in content.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 && parts[1] == "00000000" {
                return parts[0].to_string();
            }
        }
    }
    "eth0".to_string()
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RoutingSnapshot {
    pub rules_v4: String,
    pub rules_v6: String,
    pub routes: String,
}

pub async fn take_routing_snapshot() -> Result<()> {
    if std::env::var("HULIOS_MOCK_RECOVERY").is_ok() {
        return Ok(());
    }
    let rules_v4 = match tokio::process::Command::new("ip")
        .args(["rule", "show"])
        .output()
        .await
    {
        Ok(o) => String::from_utf8_lossy(&o.stdout).into_owned(),
        Err(_) => String::new(),
    };
    let rules_v6 = match tokio::process::Command::new("ip")
        .args(["-6", "rule", "show"])
        .output()
        .await
    {
        Ok(o) => String::from_utf8_lossy(&o.stdout).into_owned(),
        Err(_) => String::new(),
    };
    let routes = match tokio::process::Command::new("ip")
        .args(["route", "show", "table", "100"])
        .output()
        .await
    {
        Ok(o) => String::from_utf8_lossy(&o.stdout).into_owned(),
        Err(_) => String::new(),
    };

    let snapshot = RoutingSnapshot {
        rules_v4,
        rules_v6,
        routes,
    };
    let snapshot_str = toml::to_string(&snapshot)?;
    let snapshot_path = crate::types::get_routing_snapshot_path();
    if let Some(parent) = snapshot_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&snapshot_path, snapshot_str)?;
    Ok(())
}

pub async fn has_stale_rules(fwmark: u32) -> bool {
    if let Ok(mocked) = std::env::var("HULIOS_MOCK_IP_RULES") {
        return mocked == "true";
    }

    let has_v4 = match tokio::process::Command::new("ip")
        .args(["rule", "show"])
        .output()
        .await
    {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            stdout.contains(&format!("fwmark {:#x}", fwmark))
                || stdout.contains(&format!("fwmark {}", fwmark))
        }
        Err(_) => false,
    };
    let has_v6 = match tokio::process::Command::new("ip")
        .args(["-6", "rule", "show"])
        .output()
        .await
    {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            stdout.contains(&format!("fwmark {:#x}", fwmark))
                || stdout.contains(&format!("fwmark {}", fwmark))
        }
        Err(_) => false,
    };
    has_v4 || has_v6
}
