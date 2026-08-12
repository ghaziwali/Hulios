use std::os::unix::io::{AsRawFd, RawFd};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

pub mod sysctl;
pub use sysctl::{apply_sysctl_hardening, restore_sysctls, SavedSysctls, SysctlConfig};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Ipv6Mode {
    Disable,
    Tor,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunConfig {
    pub name: String,
    pub address: String,
    pub netmask: String,
    pub mtu: i32,
    pub ipv6: Ipv6Mode,
}

pub struct TunHandle {
    pub name: String,
    pub raw_fd: RawFd,
    pub device: Option<tun::platform::Device>,
    pub routing_task: Option<tokio::task::JoinHandle<()>>,
    pub write_tx: Option<mpsc::UnboundedSender<Vec<u8>>>,
}

impl AsRawFd for TunHandle {
    fn as_raw_fd(&self) -> RawFd {
        self.raw_fd
    }
}

pub trait PacketHandler: Send + Sync + 'static {
    fn handle_packet(&self, packet: &[u8]) -> Option<Vec<u8>>;
}

/*
impl TunHandle {
    pub fn start_routing_loop<H>(&mut self, handler: H) -> Result<mpsc::UnboundedSender<Vec<u8>>>
    where
        H: PacketHandler + 'static,
    {
        let device = self.device.take().ok_or_else(|| anyhow::anyhow!("Device already started or closed"))?;
        let (mut reader, mut writer) = tokio::io::split(device);
        let name = self.name.clone();

        let (write_tx, mut write_rx) = mpsc::unbounded_channel::<Vec<u8>>();

        let task = tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            loop {
                tokio::select! {
                    read_res = reader.read(&mut buf) => {
                        match read_res {
                            Ok(0) => {
                                tracing::info!("TUN device {} EOF", name);
                                break;
                            }
                            Ok(n) => {
                                let packet = &buf[..n];
                                if let Some(reply) = handler.handle_packet(packet) {
                                    if let Err(e) = writer.write_all(&reply).await {
                                        tracing::error!("Failed to write to TUN device {}: {:?}", name, e);
                                        break;
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::error!("Failed to read from TUN device {}: {:?}", name, e);
                                break;
                            }
                        }
                    }
                    write_opt = write_rx.recv() => {
                        match write_opt {
                            Some(packet) => {
                                if let Err(e) = writer.write_all(&packet).await {
                                    tracing::error!("Failed to write to TUN device {}: {:?}", name, e);
                                    break;
                                }
                            }
                            None => {
                                break;
                            }
                        }
                    }
                }
            }
        });

        self.routing_task = Some(task);
        self.write_tx = Some(write_tx.clone());
        Ok(write_tx)
    }
}
*/

impl Drop for TunHandle {
    fn drop(&mut self) {
        if let Some(task) = self.routing_task.take() {
            task.abort();
        }
        self.device.take();

        // Best effort deletion of the link using sync command
        let _ = std::process::Command::new("ip")
            .args(["link", "del", &self.name])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
}

pub async fn create_tun_interface(cfg: &TunConfig) -> Result<TunHandle> {
    let mut config = tun::Configuration::default();
    config
        .name(&cfg.name)
        .address(&cfg.address)
        .netmask(&cfg.netmask)
        .mtu(cfg.mtu)
        .up();

    let device = tun::create(&config)?;
    let raw_fd = device.as_raw_fd();

    if cfg.ipv6 == Ipv6Mode::Tor {
        let (connection, rt_handle, _) = rtnetlink::new_connection()?;
        tokio::spawn(connection);

        use futures::stream::TryStreamExt;
        let mut links = rt_handle
            .link()
            .get()
            .match_name(cfg.name.clone())
            .execute();
        if let Some(link) = links.try_next().await? {
            let addr: std::net::IpAddr = "fdbe::1".parse()?;
            rt_handle
                .address()
                .add(link.header.index, addr, 64)
                .execute()
                .await?;
        } else {
            return Err(anyhow::anyhow!("Interface {} not found", cfg.name));
        }

        // Add DNS magic alias (nodad: safe on TUN, no L2 broadcast domain)
        std::process::Command::new("ip")
            .args([
                "-6",
                "addr",
                "add",
                "fdbe::53/128",
                "dev",
                &cfg.name,
                "nodad",
            ])
            .status()
            .context("Failed to add IPv6 DNS alias fdbe::53 to TUN interface")?;
    }

    Ok(TunHandle {
        name: cfg.name.clone(),
        raw_fd,
        device: Some(device),
        routing_task: None,
        write_tx: None,
    })
}

pub async fn delete_link_by_name(name: &str) -> Result<()> {
    let (connection, rt_handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);

    use futures::stream::TryStreamExt;
    let mut links = rt_handle
        .link()
        .get()
        .match_name(name.to_string())
        .execute();
    let link_opt = match links.try_next().await {
        Ok(opt) => opt,
        Err(e) => {
            let code = match &e {
                rtnetlink::Error::NetlinkError(err_msg) => err_msg.code.map(|c| c.get()),
                _ => None,
            };
            if code.map(|c| c.abs()) == Some(libc::ENODEV)
                || code.map(|c| c.abs()) == Some(libc::ENOENT)
            {
                None
            } else {
                return Err(e.into());
            }
        }
    };

    if let Some(link) = link_opt {
        if let Err(e) = rt_handle.link().del(link.header.index).execute().await {
            let code = match &e {
                rtnetlink::Error::NetlinkError(err_msg) => err_msg.code.map(|c| c.get()),
                _ => None,
            };
            if code.map(|c| c.abs()) != Some(libc::ENOENT)
                && code.map(|c| c.abs()) != Some(libc::ENODEV)
            {
                return Err(e.into());
            }
        }
    }
    Ok(())
}

pub fn clear_tun_persist(name: &str) -> Result<()> {
    unsafe {
        let fd = libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR);
        if fd < 0 {
            return Err(anyhow::anyhow!("Failed to open /dev/net/tun"));
        }

        #[repr(C)]
        struct ifreq {
            ifr_name: [libc::c_char; libc::IFNAMSIZ],
            ifr_flags: libc::c_short,
        }

        let mut ifr: ifreq = std::mem::zeroed();
        ifr.ifr_flags = (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short;

        let name_bytes = name.as_bytes();
        let len = std::cmp::min(name_bytes.len(), libc::IFNAMSIZ - 1);
        std::ptr::copy_nonoverlapping(
            name_bytes.as_ptr(),
            ifr.ifr_name.as_mut_ptr() as *mut u8,
            len,
        );

        let tunsetiff = 0x400454ca;
        if libc::ioctl(fd, tunsetiff, &mut ifr) < 0 {
            libc::close(fd);
            return Err(anyhow::anyhow!("Failed to bind to TUN device {}", name));
        }

        let tunsetpersist = 0x400454cb;
        if libc::ioctl(fd, tunsetpersist, 0) < 0 {
            libc::close(fd);
            return Err(anyhow::anyhow!("Failed to clear persist flag on {}", name));
        }

        libc::close(fd);
    }
    Ok(())
}

pub async fn destroy_tun_interface(mut handle: TunHandle) -> Result<()> {
    if let Some(task) = handle.routing_task.take() {
        task.abort();
    }
    handle.device.take();

    let _ = clear_tun_persist(&handle.name);
    delete_link_by_name(&handle.name).await
}

use anyhow::Context;

pub async fn add_table100_default(tun_name: &str, ipv6_enabled: bool) -> Result<()> {
    // Get interface index directly using POSIX:
    let ifindex = nix::net::if_::if_nametoindex(tun_name)
        .context("Failed to get interface index using if_nametoindex")?;

    let (connection, rt_handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);

    // Add IPv4 default route to table 100
    let add_v4_res = rt_handle
        .route()
        .add()
        .v4()
        .table_id(100)
        .output_interface(ifindex)
        .priority(100)
        .destination_prefix(std::net::Ipv4Addr::UNSPECIFIED, 0)
        .execute()
        .await;

    if add_v4_res.as_ref().err().and_then(|e| match e {
        rtnetlink::Error::NetlinkError(err_msg) => err_msg.code.map(|c| c.get()),
        _ => None,
    }) != Some(-libc::EEXIST)
    {
        add_v4_res?;
    }

    // Add IPv6 default route to table 100
    if ipv6_enabled {
        let add_v6_res = rt_handle
            .route()
            .add()
            .v6()
            .table_id(100)
            .output_interface(ifindex)
            .priority(100)
            .destination_prefix(std::net::Ipv6Addr::UNSPECIFIED, 0)
            .execute()
            .await;

        if let Err(rtnetlink::Error::NetlinkError(err_msg)) = &add_v6_res {
            if err_msg.code.map(|c| c.get()) != Some(-libc::EEXIST) {
                // If it is another error, we could log or return, but let's ignore since IPv6 support is optional
                tracing::debug!(
                    "Failed to add IPv6 default route to table 100: {:?}",
                    err_msg
                );
            }
        }
    }

    // Add blackhole routes with metric 999 to prevent leaks
    let ip_args = [
        vec![
            "route",
            "add",
            "blackhole",
            "default",
            "table",
            "100",
            "metric",
            "999",
        ],
        vec![
            "-6",
            "route",
            "add",
            "blackhole",
            "default",
            "table",
            "100",
            "metric",
            "999",
        ],
    ];
    for args in &ip_args {
        let output = tokio::process::Command::new("ip").args(args).output().await;
        match output {
            Ok(out) => {
                if !out.status.success() {
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    if !stderr.contains("File exists") && !stderr.contains("EEXIST") {
                        tracing::debug!("Failed to add blackhole route: {}", stderr.trim());
                    }
                }
            }
            Err(e) => {
                tracing::debug!("Failed to execute ip route command: {:?}", e);
            }
        }
    }

    Ok(())
}

pub async fn add_policy_rules(fwmark: u32, tun_name: &str, ipv6_enabled: bool) -> Result<()> {
    let (connection, rt_handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);

    use netlink_packet_route::rule::RuleAction;

    // Rule 1: fwmark <fwmark> lookup main priority 100
    let r1_v4 = rt_handle
        .rule()
        .add()
        .v4()
        .fw_mark(fwmark)
        .table_id(254)
        .priority(100)
        .action(RuleAction::ToTable)
        .execute()
        .await;
    if let Err(rtnetlink::Error::NetlinkError(err_msg)) = &r1_v4 {
        if err_msg.code.map(|c| c.get()) != Some(-libc::EEXIST) {
            r1_v4?;
        }
    } else {
        r1_v4?;
    }

    let r1_v6 = rt_handle
        .rule()
        .add()
        .v6()
        .fw_mark(fwmark)
        .table_id(254)
        .priority(100)
        .action(RuleAction::ToTable)
        .execute()
        .await;
    if let Err(rtnetlink::Error::NetlinkError(err_msg)) = &r1_v6 {
        if err_msg.code.map(|c| c.get()) != Some(-libc::EEXIST) {
            r1_v6?;
        }
    } else {
        r1_v6?;
    }

    // Rule 2: from all lookup 100 priority 200
    let r2_v4 = rt_handle
        .rule()
        .add()
        .v4()
        .table_id(100)
        .priority(200)
        .action(RuleAction::ToTable)
        .execute()
        .await;
    if let Err(rtnetlink::Error::NetlinkError(err_msg)) = &r2_v4 {
        if err_msg.code.map(|c| c.get()) != Some(-libc::EEXIST) {
            r2_v4?;
        }
    } else {
        r2_v4?;
    }

    let r2_v6 = rt_handle
        .rule()
        .add()
        .v6()
        .table_id(100)
        .priority(200)
        .action(RuleAction::ToTable)
        .execute()
        .await;
    if let Err(rtnetlink::Error::NetlinkError(err_msg)) = &r2_v6 {
        if err_msg.code.map(|c| c.get()) != Some(-libc::EEXIST) {
            r2_v6?;
        }
    } else {
        r2_v6?;
    }

    // Route default dev tun_name table 100
    add_table100_default(tun_name, ipv6_enabled).await?;

    Ok(())
}

pub async fn check_routing_rules(fwmark: u32) -> Result<()> {
    if std::env::var("HULIOS_MOCK_IP_RULES").is_ok() {
        if std::env::var("HULIOS_MOCK_IP_RULES").unwrap() == "fail" {
            anyhow::bail!("ip rule show does not contain fwmark {} rule", fwmark);
        }
        return Ok(());
    }

    let (connection, rt_handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);

    use futures::stream::TryStreamExt;
    use netlink_packet_route::rule::RuleAttribute;

    let mut rules = rt_handle.rule().get(rtnetlink::IpVersion::V4).execute();
    let mut has_fwmark = false;
    let mut has_table_100 = false;

    while let Some(rule) = rules.try_next().await? {
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

        let fw = rule.attributes.iter().find_map(|attr| match attr {
            RuleAttribute::FwMark(mark) => Some(*mark),
            _ => None,
        });

        if fw == Some(fwmark) {
            has_fwmark = true;
        }
        if table == 100 {
            has_table_100 = true;
        }
    }

    if !has_fwmark {
        anyhow::bail!("ip rule show does not contain fwmark {} rule", fwmark);
    }
    if !has_table_100 {
        anyhow::bail!("ip rule show does not contain table 100 rule");
    }
    Ok(())
}

pub async fn check_table_100(tun_name: &str) -> Result<()> {
    if std::env::var("HULIOS_MOCK_IP_ROUTES").is_ok() {
        if std::env::var("HULIOS_MOCK_IP_ROUTES").unwrap() == "fail" {
            anyhow::bail!(
                "ip route show table 100 does not contain default dev {}",
                tun_name
            );
        }
        return Ok(());
    }

    let (connection, rt_handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);

    use futures::stream::TryStreamExt;
    use netlink_packet_route::route::RouteAttribute;

    let mut routes = rt_handle.route().get(rtnetlink::IpVersion::V4).execute();
    let mut has_default_table100 = false;

    while let Some(route) = routes.try_next().await? {
        let table = if route.header.table != 0 {
            route.header.table as u32
        } else {
            route.attributes
                .iter()
                .find_map(|attr| match attr {
                    RouteAttribute::Table(t) => Some(*t),
                    _ => None,
                })
                .unwrap_or(0)
        };

        if table == 100 && route.header.destination_prefix_length == 0 {
            has_default_table100 = true;
            break;
        }
    }

    if !has_default_table100 {
        anyhow::bail!(
            "ip route show table 100 does not contain default dev {}",
            tun_name
        );
    }
    Ok(())
}

pub async fn remove_policy_rules(fwmark: u32, tun_name: &str) -> Result<()> {
    remove_policy_rules_ex(fwmark, tun_name, false).await
}

pub async fn remove_policy_rules_ex(
    fwmark: u32,
    tun_name: &str,
    strict_lockdown: bool,
) -> Result<()> {
    let (connection, rt_handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);

    use futures::stream::TryStreamExt;
    use netlink_packet_route::route::RouteAttribute;
    use netlink_packet_route::rule::RuleAttribute;

    for ip_ver in [rtnetlink::IpVersion::V4, rtnetlink::IpVersion::V6] {
        let mut rules = rt_handle.rule().get(ip_ver).execute();
        while let Some(rule) = rules.try_next().await? {
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
            let fw_mark = rule.attributes.iter().find_map(|attr| match attr {
                RuleAttribute::FwMark(f) => Some(*f),
                _ => None,
            });

            let should_delete = (priority == Some(100) && fw_mark == Some(fwmark) && table == 254)
                || (!strict_lockdown && priority == Some(200) && table == 100);

            if should_delete {
                if let Err(e) = rt_handle.rule().del(rule).execute().await {
                    let code = match &e {
                        rtnetlink::Error::NetlinkError(err_msg) => err_msg.code.map(|c| c.get()),
                        _ => None,
                    };
                    if code.map(|c| c.abs()) != Some(libc::ENOENT)
                        && code.map(|c| c.abs()) != Some(libc::ENODEV)
                    {
                        return Err(e.into());
                    }
                }
            }
        }
    }

    let mut ifindex = None;
    let mut links = rt_handle
        .link()
        .get()
        .match_name(tun_name.to_string())
        .execute();
    let link_opt = match links.try_next().await {
        Ok(opt) => opt,
        Err(e) => {
            let code = match &e {
                rtnetlink::Error::NetlinkError(err_msg) => err_msg.code.map(|c| c.get()),
                _ => None,
            };
            if code.map(|c| c.abs()) == Some(libc::ENODEV)
                || code.map(|c| c.abs()) == Some(libc::ENOENT)
            {
                None
            } else {
                return Err(e.into());
            }
        }
    };
    if let Some(link) = link_opt {
        ifindex = Some(link.header.index);
    }

    if let Some(idx) = ifindex {
        for ip_ver in [rtnetlink::IpVersion::V4, rtnetlink::IpVersion::V6] {
            let mut routes = rt_handle.route().get(ip_ver).execute();
            while let Some(route) = routes.try_next().await? {
                let table = if route.header.table != 0 {
                    route.header.table as u32
                } else {
                    route
                        .attributes
                        .iter()
                        .find_map(|attr| match attr {
                            RouteAttribute::Table(t) => Some(*t),
                            _ => None,
                        })
                        .unwrap_or(0)
                };
                let oif = route.attributes.iter().find_map(|attr| match attr {
                    RouteAttribute::Oif(i) => Some(*i),
                    _ => None,
                });

                if table == 100 && oif == Some(idx) {
                    if let Err(e) = rt_handle.route().del(route).execute().await {
                        let code = match &e {
                            rtnetlink::Error::NetlinkError(err_msg) => {
                                err_msg.code.map(|c| c.get())
                            }
                            _ => None,
                        };
                        if code.map(|c| c.abs()) != Some(libc::ENOENT)
                            && code.map(|c| c.abs()) != Some(libc::ENODEV)
                        {
                            return Err(e.into());
                        }
                    }
                }
            }
        }
    }

    // Remove blackhole routes
    if !strict_lockdown {
        let ip_del_args = [
            vec![
                "route",
                "del",
                "blackhole",
                "default",
                "table",
                "100",
                "metric",
                "999",
            ],
            vec![
                "-6",
                "route",
                "del",
                "blackhole",
                "default",
                "table",
                "100",
                "metric",
                "999",
            ],
        ];
        for args in &ip_del_args {
            let output = tokio::process::Command::new("ip").args(args).output().await;
            match output {
                Ok(out) => {
                    if !out.status.success() {
                        let stderr = String::from_utf8_lossy(&out.stderr);
                        if !stderr.contains("No such process")
                            && !stderr.contains("Cannot find device")
                            && !stderr.contains("No such file or directory")
                        {
                            tracing::debug!("Failed to delete blackhole route: {}", stderr.trim());
                        }
                    }
                }
                Err(e) => {
                    tracing::debug!("Failed to execute ip route command: {:?}", e);
                }
            }
        }
    }

    Ok(())
}

pub async fn check_policy_rules(fwmark: u32, tun_name: &str) -> bool {
    let check_res = async {
        let (connection, rt_handle, _) = rtnetlink::new_connection()?;
        tokio::spawn(connection);

        use futures::stream::TryStreamExt;
        use netlink_packet_route::route::RouteAttribute;
        use netlink_packet_route::rule::RuleAttribute;

        let mut has_r1 = false;
        let mut has_r2 = false;

        let mut rules = rt_handle.rule().get(rtnetlink::IpVersion::V4).execute();
        while let Some(rule) = rules.try_next().await? {
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
            let fw_mark = rule.attributes.iter().find_map(|attr| match attr {
                RuleAttribute::FwMark(f) => Some(*f),
                _ => None,
            });

            if priority == Some(100) && fw_mark == Some(fwmark) && table == 254 {
                has_r1 = true;
            }
            if priority == Some(200) && table == 100 {
                has_r2 = true;
            }
        }

        let mut has_route = false;
        let mut ifindex = None;
        let mut links = rt_handle
            .link()
            .get()
            .match_name(tun_name.to_string())
            .execute();
        if let Some(link) = links.try_next().await? {
            ifindex = Some(link.header.index);
        }

        if let Some(idx) = ifindex {
            let mut routes = rt_handle.route().get(rtnetlink::IpVersion::V4).execute();
            while let Some(route) = routes.try_next().await? {
                let table = if route.header.table != 0 {
                    route.header.table as u32
                } else {
                    route
                        .attributes
                        .iter()
                        .find_map(|attr| match attr {
                            RouteAttribute::Table(t) => Some(*t),
                            _ => None,
                        })
                        .unwrap_or(0)
                };
                let oif = route.attributes.iter().find_map(|attr| match attr {
                    RouteAttribute::Oif(i) => Some(*i),
                    _ => None,
                });

                if table == 100 && oif == Some(idx) {
                    has_route = true;
                }
            }
        }

        Ok::<bool, anyhow::Error>(has_r1 && has_r2 && has_route)
    }
    .await;

    check_res.unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tun_config_serialization() {
        let cfg = TunConfig {
            name: "hulios_test".to_string(),
            address: "10.242.0.1".to_string(),
            netmask: "255.255.255.0".to_string(),
            mtu: 1420,
            ipv6: Ipv6Mode::Tor,
        };
        let serialized = toml::to_string(&cfg).unwrap();
        let deserialized: TunConfig = toml::from_str(&serialized).unwrap();
        assert_eq!(deserialized.name, "hulios_test");
        assert_eq!(deserialized.mtu, 1420);
        assert_eq!(deserialized.ipv6, Ipv6Mode::Tor);
    }
}
