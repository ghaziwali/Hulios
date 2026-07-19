use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConflictInfo {
    pub existing_mark: u32,
    pub rule_description: String,
}

pub async fn detect_vpn_fwmark_conflict(our_mark: u32) -> Result<Option<ConflictInfo>> {
    if let Ok(mocked) = std::env::var("HULIOS_MOCK_NETLINK_CONFLICT") {
        if mocked == "true" {
            return Ok(Some(ConflictInfo {
                existing_mark: our_mark,
                rule_description: format!(
                    "ip rule (IPv4) priority 100 lookup main fwmark {}",
                    our_mark
                ),
            }));
        }
    } else {
        let (connection, rt_handle, _) =
            rtnetlink::new_connection().context("Failed to connect to netlink")?;
        tokio::spawn(connection);

        use futures::stream::TryStreamExt;
        use netlink_packet_route::rule::RuleAttribute;

        // Check V4 rules
        let mut rules = rt_handle.rule().get(rtnetlink::IpVersion::V4).execute();
        while let Some(rule) = rules
            .try_next()
            .await
            .context("Failed to list IPv4 policy rules")?
        {
            let fw_mark = rule.attributes.iter().find_map(|attr| match attr {
                RuleAttribute::FwMark(f) => Some(*f),
                _ => None,
            });
            if fw_mark == Some(our_mark) {
                let priority = rule.attributes.iter().find_map(|attr| match attr {
                    RuleAttribute::Priority(p) => Some(*p),
                    _ => None,
                });
                let table = if rule.header.table != 0 {
                    rule.header.table as u32
                } else {
                    rule.attributes
                        .iter()
                        .find_map(|attr| match attr {
                            RuleAttribute::Table(t) => Some(*t),
                            _ => None,
                        })
                        .unwrap_or(0)
                };
                let priority_str = priority
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "default".to_string());
                return Ok(Some(ConflictInfo {
                    existing_mark: our_mark,
                    rule_description: format!(
                        "ip rule (IPv4) priority {} lookup {} fwmark {}",
                        priority_str, table, our_mark
                    ),
                }));
            }
        }

        // Check V6 rules
        let mut rules = rt_handle.rule().get(rtnetlink::IpVersion::V6).execute();
        while let Some(rule) = rules
            .try_next()
            .await
            .context("Failed to list IPv6 policy rules")?
        {
            let fw_mark = rule.attributes.iter().find_map(|attr| match attr {
                RuleAttribute::FwMark(f) => Some(*f),
                _ => None,
            });
            if fw_mark == Some(our_mark) {
                let priority = rule.attributes.iter().find_map(|attr| match attr {
                    RuleAttribute::Priority(p) => Some(*p),
                    _ => None,
                });
                let table = if rule.header.table != 0 {
                    rule.header.table as u32
                } else {
                    rule.attributes
                        .iter()
                        .find_map(|attr| match attr {
                            RuleAttribute::Table(t) => Some(*t),
                            _ => None,
                        })
                        .unwrap_or(0)
                };
                let priority_str = priority
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "default".to_string());
                return Ok(Some(ConflictInfo {
                    existing_mark: our_mark,
                    rule_description: format!(
                        "ip rule (IPv6) priority {} lookup {} fwmark {}",
                        priority_str, table, our_mark
                    ),
                }));
            }
        }
    }

    let wg_dir_str =
        std::env::var("HULIOS_WG_CONF_DIR").unwrap_or_else(|_| "/etc/wireguard".to_string());
    let wg_dir = Path::new(&wg_dir_str);
    if wg_dir.exists() && wg_dir.is_dir() {
        if let Ok(entries) = fs::read_dir(wg_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("conf") {
                    if let Ok(content) = fs::read_to_string(&path) {
                        for line in content.lines() {
                            let line_no_comment = match line.split_once('#') {
                                Some((left, _)) => left,
                                None => match line.split_once(';') {
                                    Some((left, _)) => left,
                                    None => line,
                                },
                            };
                            let trimmed = line_no_comment.trim();
                            if let Some((key, val)) = trimmed.split_once('=') {
                                if key.trim().eq_ignore_ascii_case("fwmark") {
                                    let val_trimmed = val.trim();
                                    let parsed_mark = if val_trimmed.starts_with("0x")
                                        || val_trimmed.starts_with("0X")
                                    {
                                        u32::from_str_radix(&val_trimmed[2..], 16).ok()
                                    } else {
                                        val_trimmed.parse::<u32>().ok()
                                    };
                                    if parsed_mark == Some(our_mark) {
                                        let file_name = path
                                            .file_name()
                                            .and_then(|s| s.to_str())
                                            .unwrap_or("unknown");
                                        return Ok(Some(ConflictInfo {
                                            existing_mark: our_mark,
                                            rule_description: format!(
                                                "WireGuard config: {} (FwMark = {})",
                                                file_name, val_trimmed
                                            ),
                                        }));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(None)
}
