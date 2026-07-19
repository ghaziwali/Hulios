use anyhow::{Context, Result};

/// Query whether the system NTP daemon is currently enabled via timedatectl.
/// Returns true if NTP is active, false if disabled or timedatectl is unavailable.
pub fn query_ntp_enabled() -> bool {
    std::process::Command::new("timedatectl")
        .args(["show", "--property=NTP", "--value"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "yes")
        .unwrap_or(false)
}

/// Disable or re-enable the system NTP daemon via timedatectl.
pub fn set_ntp_enabled(enabled: bool) -> Result<()> {
    let arg = if enabled { "true" } else { "false" };
    let status = std::process::Command::new("timedatectl")
        .args(["set-ntp", arg])
        .status()
        .context("Failed to run timedatectl set-ntp")?;
    if !status.success() {
        anyhow::bail!(
            "timedatectl set-ntp {} failed with exit code: {:?}",
            arg,
            status.code()
        );
    }
    Ok(())
}

pub async fn run_time_sync(
    mode: hulios_cli::TimeSyncMode,
    consensus_window: Option<(std::time::SystemTime, std::time::SystemTime)>,
) -> Result<String> {
    if std::env::var("HULIOS_MOCK_TIME_SYNC").unwrap_or_default() == "pass" {
        return Ok("Clock drift: ±0s. Correction applied: No".to_string());
    }

    match mode {
        hulios_cli::TimeSyncMode::Consensus => {
            let has_privilege =
                if std::env::var("HULIOS_MOCK_TIME_SYNC").unwrap_or_default() == "clock_only" {
                    true
                } else {
                    let mut ts = libc::timespec {
                        tv_sec: 0,
                        tv_nsec: 0,
                    };
                    let check_res = unsafe {
                        if libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) == 0 {
                            libc::clock_settime(libc::CLOCK_REALTIME, &ts)
                        } else {
                            -1
                        }
                    };
                    check_res == 0
                };
            if !has_privilege {
                return Err(anyhow::anyhow!(
                    "Permission denied: CAP_SYS_TIME capability is required to sync time."
                ));
            }

            let (valid_after, valid_until) = if let Some((a, u)) = consensus_window {
                (
                    chrono::DateTime::<chrono::Utc>::from(a),
                    chrono::DateTime::<chrono::Utc>::from(u),
                )
            } else {
                let base_dir = std::env::var("HULIOS_ARTI_DIR_PATH")
                    .map(std::path::PathBuf::from)
                    .unwrap_or_else(|_| std::path::PathBuf::from("/var/lib/hulios/arti"));
                let mut consensus_files = find_consensus_files(&base_dir);
                let alt_dir = std::path::PathBuf::from("/var/lib/hulios");
                if consensus_files.is_empty() {
                    consensus_files = find_consensus_files(&alt_dir);
                }

                if consensus_files.is_empty() {
                    return Err(anyhow::anyhow!("No Tor consensus cache file found. Please ensure Hulios has bootstrapped Tor client first."));
                }

                let mut parsed_consensus = Vec::new();
                for path in consensus_files {
                    if let Ok(content) = std::fs::read_to_string(&path) {
                        if let Some((valid_after, valid_until)) =
                            extract_consensus_timestamps(&content)
                        {
                            parsed_consensus.push((valid_after, valid_until));
                        }
                    }
                }

                if parsed_consensus.is_empty() {
                    return Err(anyhow::anyhow!(
                        "Failed to parse timestamps from cached consensus files."
                    ));
                }

                parsed_consensus.sort_by_key(|c| c.0);
                *parsed_consensus.last().unwrap()
            };

            let now = chrono::Utc::now();
            if now >= valid_after && now <= valid_until {
                return Ok(
                    "Clock is within the consensus validity window. No coarse correction needed."
                        .to_string(),
                );
            }

            let duration = valid_until.signed_duration_since(valid_after);
            let median = valid_after + duration / 2;
            let drift = now.signed_duration_since(median).num_seconds();

            let mut applied = false;
            if drift.abs() > 1 {
                if std::env::var("HULIOS_MOCK_TIME_SYNC").unwrap_or_default() == "clock_only" {
                    applied = true;
                } else {
                    let secs = median.timestamp();
                    let nsecs = median.timestamp_subsec_nanos();
                    let set_ts = libc::timespec {
                        tv_sec: secs as libc::time_t,
                        tv_nsec: nsecs as libc::c_long,
                    };
                    let set_res = unsafe { libc::clock_settime(libc::CLOCK_REALTIME, &set_ts) };
                    if set_res != 0 {
                        return Err(anyhow::anyhow!(
                            "Failed to set clock time: {}",
                            std::io::Error::last_os_error()
                        ));
                    }
                    applied = true;
                }
            }

            let sign = if drift > 0 {
                "+"
            } else if drift < 0 {
                ""
            } else {
                "±"
            };
            Ok(format!(
                "Clock drift (coarse): {}{}s. Correction applied to median: {}",
                sign,
                drift,
                if applied { "Yes" } else { "No" }
            ))
        }
        hulios_cli::TimeSyncMode::Nts => {
            let has_privilege =
                if std::env::var("HULIOS_MOCK_TIME_SYNC").unwrap_or_default() == "clock_only" {
                    true
                } else {
                    let mut ts = libc::timespec {
                        tv_sec: 0,
                        tv_nsec: 0,
                    };
                    let check_res = unsafe {
                        if libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) == 0 {
                            libc::clock_settime(libc::CLOCK_REALTIME, &ts)
                        } else {
                            -1
                        }
                    };
                    check_res == 0
                };
            if !has_privilege {
                return Err(anyhow::anyhow!(
                    "Permission denied: CAP_SYS_TIME capability is required to sync time."
                ));
            }

            let chronyc_exists = std::process::Command::new("which")
                .arg("chronyc")
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);

            if !chronyc_exists {
                tracing::warn!("Chrony (chronyc) is not installed.");
                return Ok("Warning: Chrony (chronyc) is not installed.\nClock drift: ±0s. Correction applied: No".to_string());
            }

            let drift_secs = if let Ok(tracking) = std::process::Command::new("chronyc")
                .arg("tracking")
                .output()
            {
                let stdout = String::from_utf8_lossy(&tracking.stdout);
                parse_chrony_drift(&stdout).unwrap_or(0.0)
            } else {
                0.0
            };

            let config = hulios_cli::load_config_file().unwrap_or_default();
            let _socks_port = config.socks_port.unwrap_or(9050);

            let add_res = std::process::Command::new("chronyc")
                .args(["add", "server", "pool.nts.netnod.se", "nts"])
                .output();
            if let Err(e) = add_res {
                tracing::warn!("Failed to add NTS server in chronyc: {:?}", e);
            }

            let step_res = std::process::Command::new("chronyc")
                .arg("makestep")
                .output();

            let mut applied = false;
            match step_res {
                Ok(out) if out.status.success() => {
                    applied = true;
                }
                _ => {}
            }

            let drift_round = drift_secs.round() as i64;
            let sign = if drift_round > 0 {
                "+"
            } else if drift_round < 0 {
                ""
            } else {
                "±"
            };
            Ok(format!(
                "Clock drift: {}{}s. Correction applied: {}",
                sign,
                drift_round,
                if applied { "Yes" } else { "No" }
            ))
        }
    }
}

fn find_consensus_files(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut result = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                result.extend(find_consensus_files(&path));
            } else if path.is_file() {
                if let Some(name) = path.file_name() {
                    if name.to_string_lossy().contains("consensus") {
                        result.push(path);
                    }
                }
            }
        }
    }
    result
}

fn extract_consensus_timestamps(
    content: &str,
) -> Option<(chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>)> {
    let mut valid_after = None;
    let mut valid_until = None;
    for line in content.lines() {
        if line.starts_with("valid-after ") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                let datetime_str = format!("{} {}", parts[1], parts[2]);
                if let Ok(dt) =
                    chrono::NaiveDateTime::parse_from_str(&datetime_str, "%Y-%m-%d %H:%M:%S")
                {
                    valid_after = Some(chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(
                        dt,
                        chrono::Utc,
                    ));
                }
            }
        } else if line.starts_with("valid-until ") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                let datetime_str = format!("{} {}", parts[1], parts[2]);
                if let Ok(dt) =
                    chrono::NaiveDateTime::parse_from_str(&datetime_str, "%Y-%m-%d %H:%M:%S")
                {
                    valid_until = Some(chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(
                        dt,
                        chrono::Utc,
                    ));
                }
            }
        }
    }
    if let (Some(va), Some(vu)) = (valid_after, valid_until) {
        Some((va, vu))
    } else {
        None
    }
}

fn parse_chrony_drift(stdout: &str) -> Option<f64> {
    for line in stdout.lines() {
        if line.contains("System time") {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 2 {
                let val_str = parts[1].trim();
                let words: Vec<&str> = val_str.split_whitespace().collect();
                if !words.is_empty() {
                    if let Ok(mut val) = words[0].parse::<f64>() {
                        if val_str.contains("slow") {
                            val = -val;
                        }
                        return Some(val);
                    }
                }
            }
        }
    }
    None
}
