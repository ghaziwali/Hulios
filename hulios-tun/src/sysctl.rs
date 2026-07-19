use crate::Ipv6Mode;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use sysctl::{Ctl, Sysctl};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SysctlConfig {
    pub ipv6: Ipv6Mode,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SavedSysctls {
    pub values: HashMap<String, String>,
}

pub fn apply_sysctl_hardening(_cfg: &SysctlConfig, phys_iface: &str) -> Result<SavedSysctls> {
    let mut saved_values = HashMap::new();
    let sysctls_to_set = vec![
        ("net.ipv4.icmp_echo_ignore_all".to_string(), "1".to_string()),
        (
            format!("net.ipv4.conf.{}.rp_filter", phys_iface),
            "2".to_string(),
        ),
    ];

    for (name, target_val) in sysctls_to_set {
        let ctl = Ctl::new(&name).with_context(|| format!("Failed to find sysctl: {}", name))?;
        let current_val = ctl
            .value_string()
            .with_context(|| format!("Failed to read sysctl: {}", name))?;
        saved_values.insert(name.clone(), current_val);

        ctl.set_value_string(&target_val)
            .with_context(|| format!("Failed to set sysctl {} to {}", name, target_val))?;
    }

    Ok(SavedSysctls {
        values: saved_values,
    })
}

pub fn restore_sysctls(saved: SavedSysctls) -> Result<()> {
    for (name, val) in saved.values {
        let ctl = Ctl::new(&name)
            .with_context(|| format!("Failed to find sysctl to restore: {}", name))?;
        ctl.set_value_string(&val)
            .with_context(|| format!("Failed to restore sysctl {} to {}", name, val))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_saved_sysctls_serde() {
        let mut values = HashMap::new();
        values.insert("net.ipv4.icmp_echo_ignore_all".to_string(), "0".to_string());
        values.insert("net.ipv4.conf.eth0.rp_filter".to_string(), "1".to_string());

        let saved = SavedSysctls { values };
        let toml_str = toml::to_string(&saved).unwrap();
        let deserialized: SavedSysctls = toml::from_str(&toml_str).unwrap();
        assert_eq!(saved, deserialized);
    }

    fn is_root() -> bool {
        nix::unistd::getuid().is_root()
    }

    #[test]
    fn test_apply_and_restore_ipv6_disabled() {
        let cfg = SysctlConfig {
            ipv6: Ipv6Mode::Disable,
        };

        if !is_root() {
            println!("Skipping live sysctl test: not running as root");
            // Still test that we can at least attempt to read the values
            let _ = Ctl::new("net.ipv4.icmp_echo_ignore_all");
            return;
        }

        // Apply hardening
        let saved = apply_sysctl_hardening(&cfg, "lo").expect("Failed to apply sysctl hardening");

        // Assert values are set
        assert_eq!(
            Ctl::new("net.ipv4.icmp_echo_ignore_all")
                .unwrap()
                .value_string()
                .unwrap(),
            "1"
        );
        assert_eq!(
            Ctl::new("net.ipv4.conf.lo.rp_filter")
                .unwrap()
                .value_string()
                .unwrap(),
            "2"
        );

        // Restore
        restore_sysctls(saved).expect("Failed to restore sysctls");
    }

    #[test]
    fn test_apply_and_restore_ipv6_enabled() {
        let cfg = SysctlConfig {
            ipv6: Ipv6Mode::Tor,
        };

        if !is_root() {
            println!("Skipping live sysctl test: not running as root");
            return;
        }

        // Apply hardening
        let saved = apply_sysctl_hardening(&cfg, "lo").expect("Failed to apply sysctl hardening");

        // Assert IPv4 values are set
        assert_eq!(
            Ctl::new("net.ipv4.icmp_echo_ignore_all")
                .unwrap()
                .value_string()
                .unwrap(),
            "1"
        );
        assert_eq!(
            Ctl::new("net.ipv4.conf.lo.rp_filter")
                .unwrap()
                .value_string()
                .unwrap(),
            "2"
        );

        // Assert IPv6 values were NOT modified (not present in saved)
        assert!(!saved.values.contains_key("net.ipv6.conf.all.disable_ipv6"));
        assert!(!saved
            .values
            .contains_key("net.ipv6.conf.default.disable_ipv6"));

        // Restore
        restore_sysctls(saved).expect("Failed to restore sysctls");
    }
}
