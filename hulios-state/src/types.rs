use arti_client::TorClient;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tor_rtcompat::PreferredRuntime;

pub struct EbpfHandlesState {
    pub sock_mark_link: Option<aya::programs::cgroup_sock::CgroupSockLink>,
    pub lsm_link: Option<aya::programs::lsm::LsmLink>,
    pub connect4_link: Option<aya::programs::cgroup_sock_addr::CgroupSockAddrLink>,
    pub connect6_link: Option<aya::programs::cgroup_sock_addr::CgroupSockAddrLink>,
    pub sendmsg4_link: Option<aya::programs::cgroup_sock_addr::CgroupSockAddrLink>,
    pub sendmsg6_link: Option<aya::programs::cgroup_sock_addr::CgroupSockAddrLink>,
}

pub struct ActiveHandles {
    pub ebpf_handles: EbpfHandlesState,
    pub tun_handle: Option<hulios_tun::TunHandle>,
    pub saved_sysctls: Option<hulios_tun::SavedSysctls>,
    pub avahi_saved: Option<hulios_netcompat::SavedSystemdServices>,
    pub arti_client: Option<Arc<TorClient<PreferredRuntime>>>,
    pub onionmasq_handle: Option<hulios_onionmasq::OnionmasqHandle>,
    pub tor_status_handle: Option<hulios_onionmasq::TorStatusHandle>,
    pub dns_handle: Option<hulios_dns::DnsHandle>,
    pub control_socket_task: Option<tokio::task::JoinHandle<()>>,
    pub route_watchdog_task: Option<tokio::task::JoinHandle<()>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TeardownMode {
    Normal,
    StrictLockdown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunningState {
    pub fwmark: u32,
    pub tun_name: String,
    pub last_signal: String,
    pub saved_sysctls: Option<hulios_tun::SavedSysctls>,
    pub avahi_saved: Option<hulios_netcompat::SavedSystemdServices>,
    pub ntp_was_enabled: Option<bool>,
    pub strict_lockdown: bool,
    pub ipv6: Option<hulios_cli::Ipv6Mode>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirtyStateReport {
    pub stale_rules: bool,
    pub stale_cgroup: bool,
    pub stale_tun_interface: bool,
    pub stale_state_file: bool,
    pub stale_bpf: bool,
}

impl DirtyStateReport {
    pub fn is_dirty(&self) -> bool {
        self.stale_rules
            || self.stale_cgroup
            || self.stale_tun_interface
            || self.stale_state_file
            || self.stale_bpf
    }
}

// Configurable paths for unit testing
pub fn get_udev_rules_path() -> PathBuf {
    std::env::var("HULIOS_UDEV_RULES_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/run/udev/rules.d/99-hulios-unmanaged.rules"))
}

pub fn get_state_toml_path() -> PathBuf {
    std::env::var("HULIOS_STATE_TOML_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/run/hulios/state.toml"))
}

pub fn get_cgroup_dir_path() -> PathBuf {
    get_cgroup_path().unwrap_or_else(|_| PathBuf::from("/sys/fs/cgroup/hulios"))
}

pub fn get_tun_class_path(tun_name: &str) -> PathBuf {
    if std::env::var("HULIOS_MOCK_RECOVERY").is_ok() {
        return std::env::var("HULIOS_TUN_CLASS_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                PathBuf::from(format!("/run/hulios/mock_sys_class_net_{}", tun_name))
            });
    }
    std::env::var("HULIOS_TUN_CLASS_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(format!("/sys/class/net/{}", tun_name)))
}

pub fn get_routing_snapshot_path() -> PathBuf {
    std::env::var("HULIOS_ROUTING_SNAPSHOT_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/run/hulios/routing_snapshot.toml"))
}

pub fn get_bpf_pin_dir_path() -> PathBuf {
    std::env::var("HULIOS_BPF_PIN_DIR_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/sys/fs/bpf/hulios"))
}

fn get_cgroup_path() -> Result<PathBuf, anyhow::Error> {
    if let Ok(mocked_path) = std::env::var("HULIOS_CGROUP_DIR_PATH") {
        return Ok(PathBuf::from(mocked_path));
    }

    let proc_cgroup = std::path::Path::new("/proc/self/cgroup");
    let sys_cgroup = std::path::Path::new("/sys/fs/cgroup");

    let controllers_path = sys_cgroup.join("cgroup.controllers");
    if !controllers_path.exists() {
        anyhow::bail!(
            "cgroup v2 is not mounted: {:?} is missing",
            controllers_path
        );
    }

    let content = std::fs::read_to_string(proc_cgroup)
        .map_err(|e| anyhow::anyhow!("Failed to read cgroup file {:?}: {}", proc_cgroup, e))?;

    let mut cgroup_v2_subpath = None;
    for line in content.lines() {
        let line = line.trim();
        if let Some(path_part) = line.strip_prefix("0::") {
            cgroup_v2_subpath = Some(path_part);
            break;
        }
    }

    let base_path = match cgroup_v2_subpath {
        Some(subpath) if subpath != "/" => {
            let subpath_clean = subpath.strip_prefix('/').unwrap_or(subpath);
            let full_path = sys_cgroup.join(subpath_clean);
            if full_path.exists() {
                full_path
            } else {
                sys_cgroup.to_path_buf()
            }
        }
        _ => sys_cgroup.to_path_buf(),
    };

    Ok(base_path.join("hulios"))
}

pub fn get_control_sock_path() -> PathBuf {
    std::env::var("HULIOS_CONTROL_SOCK_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/run/hulios/control.sock"))
}

#[derive(Serialize, Deserialize, Debug)]
pub struct StatusRequest {
    pub cmd: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StatusResponse {
    pub bootstrap: u8,
    pub circuits: u32,
    pub consensus_age_secs: u64,
    pub exit_ip: String,
    pub uptime_secs: u64,
}
