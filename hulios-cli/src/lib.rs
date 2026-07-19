use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Ipv6Mode {
    Disable,
    Tor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum TimeSyncMode {
    Consensus,
    Nts,
}

#[derive(Clone)]
pub struct PrivilegeCallback(pub std::sync::Arc<dyn Fn() -> anyhow::Result<()> + Send + Sync>);

impl std::fmt::Debug for PrivilegeCallback {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PrivilegeCallback")
    }
}

#[derive(Parser, Debug, Clone)]
#[command(name = "hulios")]
#[command(about = "Hulios transparent Tor proxy daemon", version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug, Clone)]
pub enum Commands {
    /// Start the transparent Tor proxy daemon
    Start(StartArgs),
    /// Stop the daemon and tear down routing rules
    Stop,
    /// Show current daemon running status and connection details
    Status,
    /// Run system diagnostics to check interface and routing health
    Diagnose(DiagnoseArgs),
    /// Force recover/clean up system network state (routing tables, firewall, DNS)
    Recover,
    #[command(hide = true)]
    NewCircuit(NewCircuitArgs),
}

#[derive(Parser, Debug, Clone, Serialize, Deserialize)]
pub struct StartArgs {
    /// Firewall mark (fwmark) to assign to proxied packets (default: 42)
    #[arg(long)]
    pub fwmark: Option<u32>,

    /// Custom name for the virtual TUN interface (default: "hulios0")
    #[arg(long)]
    pub tun_name: Option<String>,

    /// IPv6 routing mode: "disable" (blocks all IPv6) or "tor" (routes IPv6 over Tor)
    #[arg(long)]
    pub ipv6: Option<Ipv6Mode>,

    /// Expose a SOCKS5 proxy port (default: 9050)
    #[arg(long)]
    pub socks_port: Option<u16>,

    /// Country code of preferred Tor exit nodes (e.g. "us", "de")
    #[arg(long)]
    pub exit_nodes: Option<String>,

    /// Enable strict firewall lockdown to prevent leaks if the daemon exits abnormally
    #[arg(long, num_args = 0..=1, default_missing_value = "true", value_parser = clap::builder::BoolishValueParser::new())]
    pub strict_lockdown: Option<bool>,

    /// Clock synchronization mode during startup: "consensus" or "nts"
    #[arg(long)]
    pub time_sync: Option<TimeSyncMode>,

    /// Tor network bootstrap timeout in seconds (default: 120)
    #[arg(long)]
    pub bootstrap_timeout: Option<u64>,
}

#[derive(Parser, Debug, Clone)]
pub struct DiagnoseArgs {
    #[arg(long)]
    pub json: bool,
}

#[derive(Parser, Debug, Clone)]
pub struct NewCircuitArgs {
    #[arg(long)]
    pub cgroup: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuliosConfig {
    pub fwmark: u32,
    pub tun_name: String,
    pub ipv6: Ipv6Mode,
    pub socks_port: Option<u16>,
    pub exit_nodes: Option<String>,
    pub strict_lockdown: bool,
    pub time_sync: Option<TimeSyncMode>,
    pub bootstrap_timeout: u64,

    #[serde(skip)]
    pub privilege_callback: Option<PrivilegeCallback>,

    #[serde(skip)]
    pub seccomp_callback: Option<PrivilegeCallback>,

    #[serde(skip)]
    pub bpf_bytecode: Option<Vec<u8>>,

    #[serde(skip)]
    pub set_fields: HashSet<String>,
}

impl Default for HuliosConfig {
    fn default() -> Self {
        HuliosConfig {
            fwmark: 42,
            tun_name: "hulios0".to_string(),
            ipv6: Ipv6Mode::Tor,
            socks_port: None,
            exit_nodes: None,
            strict_lockdown: false,
            time_sync: None,
            bootstrap_timeout: 120,
            privilege_callback: None,
            seccomp_callback: None,
            bpf_bytecode: None,
            set_fields: HashSet::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct HuliosConfigRaw {
    pub fwmark: Option<u32>,
    pub tun_name: Option<String>,
    pub ipv6: Option<Ipv6Mode>,
    pub socks_port: Option<u16>,
    pub exit_nodes: Option<String>,
    pub strict_lockdown: Option<bool>,
    pub time_sync: Option<TimeSyncMode>,
    pub bootstrap_timeout: Option<u64>,
}

impl HuliosConfig {
    pub fn from_raw(raw: HuliosConfigRaw) -> Self {
        let mut config = HuliosConfig::default();
        if let Some(v) = raw.fwmark {
            config.fwmark = v;
            config.set_fields.insert("fwmark".to_string());
        }
        if let Some(v) = raw.tun_name {
            config.tun_name = v;
            config.set_fields.insert("tun_name".to_string());
        }
        if let Some(v) = raw.ipv6 {
            config.ipv6 = v;
            config.set_fields.insert("ipv6".to_string());
        }
        if let Some(v) = raw.socks_port {
            config.socks_port = Some(v);
            config.set_fields.insert("socks_port".to_string());
        }
        if let Some(v) = raw.exit_nodes {
            config.exit_nodes = Some(v.trim().to_string());
            config.set_fields.insert("exit_nodes".to_string());
        }
        if let Some(v) = raw.strict_lockdown {
            config.strict_lockdown = v;
            config.set_fields.insert("strict_lockdown".to_string());
        }
        if let Some(v) = raw.time_sync {
            config.time_sync = Some(v);
            config.set_fields.insert("time_sync".to_string());
        }
        if let Some(v) = raw.bootstrap_timeout {
            config.bootstrap_timeout = v;
            config.set_fields.insert("bootstrap_timeout".to_string());
        }
        config
    }
}

impl From<StartArgs> for HuliosConfig {
    fn from(args: StartArgs) -> Self {
        let mut config = HuliosConfig::default();
        if let Some(v) = args.fwmark {
            config.fwmark = v;
            config.set_fields.insert("fwmark".to_string());
        }
        if let Some(v) = args.tun_name {
            config.tun_name = v;
            config.set_fields.insert("tun_name".to_string());
        }
        if let Some(v) = args.ipv6 {
            config.ipv6 = v;
            config.set_fields.insert("ipv6".to_string());
        }
        if let Some(v) = args.socks_port {
            config.socks_port = Some(v);
            config.set_fields.insert("socks_port".to_string());
        }
        if let Some(v) = args.exit_nodes {
            config.exit_nodes = Some(v.trim().to_string());
            config.set_fields.insert("exit_nodes".to_string());
        }
        if let Some(v) = args.strict_lockdown {
            config.strict_lockdown = v;
            config.set_fields.insert("strict_lockdown".to_string());
        }
        if let Some(v) = args.time_sync {
            config.time_sync = Some(v);
            config.set_fields.insert("time_sync".to_string());
        }
        if let Some(v) = args.bootstrap_timeout {
            config.bootstrap_timeout = v;
            config.set_fields.insert("bootstrap_timeout".to_string());
        }
        config
    }
}

pub trait Merge {
    fn merge(self, r#override: Self) -> Self;
}

impl Merge for HuliosConfig {
    fn merge(self, r#override: Self) -> Self {
        let mut merged = self;
        if r#override.set_fields.contains("fwmark") {
            merged.fwmark = r#override.fwmark;
            merged.set_fields.insert("fwmark".to_string());
        }
        if r#override.set_fields.contains("tun_name") {
            merged.tun_name = r#override.tun_name;
            merged.set_fields.insert("tun_name".to_string());
        }
        if r#override.set_fields.contains("ipv6") {
            merged.ipv6 = r#override.ipv6;
            merged.set_fields.insert("ipv6".to_string());
        }
        if r#override.set_fields.contains("socks_port") {
            merged.socks_port = r#override.socks_port;
            merged.set_fields.insert("socks_port".to_string());
        }
        if r#override.set_fields.contains("exit_nodes") {
            merged.exit_nodes = r#override.exit_nodes;
            merged.set_fields.insert("exit_nodes".to_string());
        }
        if r#override.set_fields.contains("strict_lockdown") {
            merged.strict_lockdown = r#override.strict_lockdown;
            merged.set_fields.insert("strict_lockdown".to_string());
        }
        if r#override.set_fields.contains("time_sync") {
            merged.time_sync = r#override.time_sync;
            merged.set_fields.insert("time_sync".to_string());
        }
        if r#override.set_fields.contains("bootstrap_timeout") {
            merged.bootstrap_timeout = r#override.bootstrap_timeout;
            merged.set_fields.insert("bootstrap_timeout".to_string());
        }
        merged
    }
}

pub fn load_config_file_from_path<P: AsRef<std::path::Path>>(
    path: P,
) -> Result<HuliosConfig, anyhow::Error> {
    let path = path.as_ref();
    if path.exists() {
        let content = std::fs::read_to_string(path)?;
        let raw: HuliosConfigRaw = toml::from_str(&content)
            .map_err(|e| anyhow::anyhow!("Failed to parse config file: {}", e))?;
        Ok(HuliosConfig::from_raw(raw))
    } else {
        Ok(HuliosConfig::default())
    }
}

pub fn load_config_file() -> Result<HuliosConfig, anyhow::Error> {
    load_config_file_from_path("/etc/hulios/config.toml")
}

pub fn load_and_merge_config_from_path<P: AsRef<std::path::Path>>(
    cli_args: StartArgs,
    path: P,
) -> Result<HuliosConfig, anyhow::Error> {
    let file_cfg = load_config_file_from_path(path)?;
    let cli_cfg = HuliosConfig::from(cli_args);
    Ok(file_cfg.merge(cli_cfg))
}

pub fn load_and_merge_config(cli_args: StartArgs) -> Result<HuliosConfig, anyhow::Error> {
    load_and_merge_config_from_path(cli_args, "/etc/hulios/config.toml")
}

pub const CONFIG_TOML_EXAMPLE: &str = r#"# Hulios Configuration File Example

# Firewalld mark to identify Hulios traffic (default: 42)
# fwmark = 42

# TUN interface name (default: "hulios0")
# tun_name = "hulios0"

# IPv6 routing mode: "disable" or "tor" (default: "disable")
# ipv6 = "disable"

# Port to expose SOCKS5 proxy on
# socks_port = 9050

# Country codes of preferred Tor exit nodes (e.g., "us")
# exit_nodes = "us"

# Enable strict firewall lockdown (default: false)
# strict_lockdown = false

# NTP time-sync mode: "consensus" or "nts" (default: "consensus")
# time_sync = "consensus"

# Tor bootstrap timeout in seconds (default: 120)
# bootstrap_timeout = 120
"#;

pub fn init() {
    // Left for backward compatibility / initialization if needed.
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn get_temp_file_path() -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "hulios_config_test_{}.toml",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        path
    }

    #[test]
    fn test_parse_start_defaults() {
        let args = Cli::try_parse_from(["hulios", "start"]).unwrap();
        if let Commands::Start(start_args) = args.command {
            assert_eq!(start_args.fwmark, None);
            assert_eq!(start_args.tun_name, None);
            assert_eq!(start_args.ipv6, None);
            assert_eq!(start_args.bootstrap_timeout, None);
        } else {
            panic!("Expected start command");
        }
    }

    #[test]
    fn test_parse_start_overrides() {
        let args = Cli::try_parse_from([
            "hulios",
            "start",
            "--fwmark",
            "99",
            "--ipv6",
            "tor",
            "--bootstrap-timeout",
            "300",
        ])
        .unwrap();
        if let Commands::Start(start_args) = args.command {
            assert_eq!(start_args.fwmark, Some(99));
            assert_eq!(start_args.ipv6, Some(Ipv6Mode::Tor));
            assert_eq!(start_args.bootstrap_timeout, Some(300));
        } else {
            panic!("Expected start command");
        }
    }

    #[test]
    fn test_merge_precedence_levels() {
        // Precedence: CLI > config.toml > compiled default.
        // Let's test 3 different fields: fwmark, tun_name, and strict_lockdown.

        // Scenario 1: CLI sets value (wins over config and defaults)
        let tmp_file_path = get_temp_file_path();
        std::fs::write(
            &tmp_file_path,
            "fwmark = 100\ntun_name = \"huliostest\"\nstrict_lockdown = true\n",
        )
        .unwrap();

        let cli_args = StartArgs {
            fwmark: Some(42),
            tun_name: Some("cli0".to_string()),
            ipv6: None,
            socks_port: None,
            exit_nodes: None,
            strict_lockdown: Some(false),
            time_sync: None,
            bootstrap_timeout: None,
        };

        let resolved = load_and_merge_config_from_path(cli_args, &tmp_file_path).unwrap();
        assert_eq!(resolved.fwmark, 42); // CLI wins
        assert_eq!(resolved.tun_name, "cli0"); // CLI wins
        assert!(!resolved.strict_lockdown); // CLI wins

        // Scenario 2: Config sets value, CLI does not (config wins over default)
        let cli_args_empty = StartArgs {
            fwmark: None,
            tun_name: None,
            ipv6: None,
            socks_port: None,
            exit_nodes: None,
            strict_lockdown: None,
            time_sync: None,
            bootstrap_timeout: None,
        };

        let resolved =
            load_and_merge_config_from_path(cli_args_empty.clone(), &tmp_file_path).unwrap();
        assert_eq!(resolved.fwmark, 100); // Config wins
        assert_eq!(resolved.tun_name, "huliostest"); // Config wins
        assert!(resolved.strict_lockdown); // Config wins

        // Scenario 3: Neither sets value (default wins)
        let empty_tmp_file = get_temp_file_path();
        std::fs::write(&empty_tmp_file, "").unwrap();
        let resolved = load_and_merge_config_from_path(cli_args_empty, &empty_tmp_file).unwrap();
        assert_eq!(resolved.fwmark, 42); // Default wins
        assert_eq!(resolved.tun_name, "hulios0"); // Default wins
        assert!(!resolved.strict_lockdown); // Default wins

        let _ = std::fs::remove_file(&tmp_file_path);
        let _ = std::fs::remove_file(&empty_tmp_file);
    }

    #[test]
    fn test_config_file_parse_error() {
        let tmp_file_path = get_temp_file_path();
        std::fs::write(&tmp_file_path, "fwmark = \"invalid_type\"\n").unwrap();

        let cli_args = StartArgs {
            fwmark: None,
            tun_name: None,
            ipv6: None,
            socks_port: None,
            exit_nodes: None,
            strict_lockdown: None,
            time_sync: None,
            bootstrap_timeout: None,
        };

        let res = load_and_merge_config_from_path(cli_args, &tmp_file_path);
        assert!(res.is_err());
        let err_msg = res.err().unwrap().to_string();
        assert!(err_msg.contains("Failed to parse config file"));

        let _ = std::fs::remove_file(&tmp_file_path);
    }

    #[test]
    fn test_exit_nodes_trimming() {
        // 1. Test trimming from TOML config
        let tmp_file_path = get_temp_file_path();
        std::fs::write(&tmp_file_path, "exit_nodes = \"  us  \"\n").unwrap();

        let cli_args_empty = StartArgs {
            fwmark: None,
            tun_name: None,
            ipv6: None,
            socks_port: None,
            exit_nodes: None,
            strict_lockdown: None,
            time_sync: None,
            bootstrap_timeout: None,
        };

        let resolved = load_and_merge_config_from_path(cli_args_empty, &tmp_file_path).unwrap();
        assert_eq!(resolved.exit_nodes, Some("us".to_string()));

        let _ = std::fs::remove_file(&tmp_file_path);

        // 2. Test trimming from CLI args
        let cli_args = StartArgs {
            fwmark: None,
            tun_name: None,
            ipv6: None,
            socks_port: None,
            exit_nodes: Some("  fr  ".to_string()),
            strict_lockdown: None,
            time_sync: None,
            bootstrap_timeout: None,
        };

        let config: HuliosConfig = cli_args.into();
        assert_eq!(config.exit_nodes, Some("fr".to_string()));
    }
}
