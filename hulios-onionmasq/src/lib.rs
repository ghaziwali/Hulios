use anyhow::Result;
use std::os::fd::AsRawFd;
use std::str::FromStr;
use std::sync::atomic::{AtomicU32, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::info;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ArtiConfig {
    pub storage_dir: Option<String>,
    pub exit_nodes: Option<String>,
    pub bootstrap_timeout: Option<Duration>,
}

#[derive(Debug, thiserror::Error)]
pub enum HuliosError {
    #[error("Tor bootstrap timed out")]
    BootstrapTimeout,
    #[error("Arti client error: {0}")]
    Arti(#[from] arti_client::Error),
    #[error("Tor configuration error: {0}")]
    TorConfig(#[from] tor_config::ConfigBuildError),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Other error: {0}")]
    Other(String),
}

#[derive(Debug, Clone)]
pub struct TorStatusHandle {
    pub bootstrap_percent: Arc<AtomicU8>,
    pub active_circuits: Arc<AtomicU32>,
}

impl TorStatusHandle {
    pub fn new() -> Self {
        Self {
            bootstrap_percent: Arc::new(AtomicU8::new(0)),
            active_circuits: Arc::new(AtomicU32::new(0)),
        }
    }

    pub fn percent(&self) -> u8 {
        self.bootstrap_percent.load(Ordering::Relaxed)
    }

    pub fn circuits(&self) -> u32 {
        self.active_circuits.load(Ordering::Relaxed)
    }
}

impl Default for TorStatusHandle {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OnionmasqConfig {
    pub storage_dir: Option<String>,
    pub exit_nodes: Option<String>,
    pub bootstrap_timeout: Option<Duration>,
    #[serde(default)]
    pub socks_port: Option<u16>,
}

#[async_trait::async_trait]
pub trait TorResolver: Send + Sync + 'static {
    async fn resolve(&self, hostname: &str) -> Result<Vec<std::net::IpAddr>, arti_client::Error>;
    async fn resolve_ptr(&self, addr: std::net::IpAddr) -> Result<Vec<String>, arti_client::Error>;
}

#[async_trait::async_trait]
impl<R: tor_rtcompat::Runtime> TorResolver for arti_client::TorClient<R> {
    async fn resolve(&self, hostname: &str) -> Result<Vec<std::net::IpAddr>, arti_client::Error> {
        self.resolve(hostname).await
    }
    async fn resolve_ptr(&self, addr: std::net::IpAddr) -> Result<Vec<String>, arti_client::Error> {
        self.resolve_ptr(addr).await
    }
}

pub struct OnionmasqHandle {
    pub task: tokio::task::JoinHandle<()>,
    pub socks_task: Option<tokio::task::JoinHandle<()>>,
    pub tor_client: Arc<dyn TorResolver>,

    pub dns_task: Option<tokio::task::JoinHandle<()>>,
    pub consensus_window: Option<(std::time::SystemTime, std::time::SystemTime)>,
}

impl OnionmasqHandle {
    pub fn set_dns_task(&mut self, dns_task: tokio::task::JoinHandle<()>) {
        self.dns_task = Some(dns_task);
    }
}

impl Drop for OnionmasqHandle {
    fn drop(&mut self) {
        self.task.abort();
        if let Some(ref socks_task) = self.socks_task {
            socks_task.abort();
        }
        if let Some(ref dns_task) = self.dns_task {
            dns_task.abort();
        }
    }
}

pub async fn start_onionmasq(
    tun_fd: std::os::fd::RawFd,
    cfg: &OnionmasqConfig,
    status_handle: TorStatusHandle,
) -> Result<OnionmasqHandle> {
    unsafe {
        let mut opt = 1;
        if libc::ioctl(tun_fd, libc::FIONBIO, &mut opt) < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }

    let device = TunDevice {
        fd: tokio::io::unix::AsyncFd::new(tun_fd)?,
    };

    let mut config = onionmasq::config::TunnelConfig::default();
    config.disable_fs_permission_checks = true;
    if let Some(ref storage_dir) = cfg.storage_dir {
        config.state_dir = Some(std::path::PathBuf::from(format!(
            "{}/arti-data",
            storage_dir
        )));
        config.cache_dir = Some(std::path::PathBuf::from(format!(
            "{}/arti-cache",
            storage_dir
        )));
        config.pt_dir = Some(std::path::PathBuf::from(format!(
            "{}/arti-pts",
            storage_dir
        )));
    }

    let scaffolding = isolation::HuliosScaffolding {
        exit_country: cfg.exit_nodes.clone(),
    };

    let mut onion_tunnel = onionmasq::OnionTunnel::create_custom(scaffolding, device, config)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create OnionTunnel: {:?}", e))?;

    let arti_client = unsafe {
        let tunnel_ref = &onion_tunnel
            as *const onionmasq::OnionTunnel<isolation::HuliosScaffolding, TunDevice>
            as *const onionmasq::OnionTunnel<isolation::HuliosScaffolding>;
        (*tunnel_ref).get_tor_client()
    };

    let mut bootstrap_events = onion_tunnel.get_bootstrap_events();
    let status_handle_clone = status_handle.clone();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let mut ready_tx = Some(ready_tx);

    tokio::spawn(async move {
        use futures::StreamExt;
        use std::io::Write;
        while let Some(status) = bootstrap_events.next().await {
            let pct = (status.as_frac() * 100.0) as u8;
            status_handle_clone
                .bootstrap_percent
                .store(pct, Ordering::Relaxed);

            let filled = (pct / 5) as usize;
            let bar = format!(
                "{}>{}",
                "=".repeat(filled.saturating_sub(1)),
                " ".repeat(20 - filled)
            );

            print!("\r[Phase 12/14] Bootstrapping Tor: [{}] {}% ", bar, pct);
            let _ = std::io::stdout().flush();

            if status.ready_for_traffic() {
                println!("\r[Phase 12/14] Bootstrapping Tor: [====================] 100% [OK]");
                let _ = std::io::stdout().flush();
                if let Some(tx) = ready_tx.take() {
                    let _ = tx.send(());
                }
                break;
            }
        }
    });

    let task = tokio::spawn(async move {
        if let Err(e) = onion_tunnel.run().await {
            tracing::error!("OnionTunnel run error: {:?}", e);
        }
    });

    let bootstrap_timeout = cfg.bootstrap_timeout.unwrap_or(Duration::from_secs(120));
    info!(
        "Waiting for OnionTunnel Tor client to bootstrap (timeout: {:?})...",
        bootstrap_timeout
    );

    match tokio::time::timeout(bootstrap_timeout, ready_rx).await {
        Ok(Ok(())) => {
            info!("OnionTunnel Tor client successfully bootstrapped.");
            status_handle
                .bootstrap_percent
                .store(100, Ordering::Relaxed);
        }
        Ok(Err(_)) => {
            return Err(anyhow::anyhow!(
                "Bootstrap event channel closed prematurely"
            ));
        }
        Err(_) => {
            return Err(anyhow::anyhow!("Tor bootstrap timed out"));
        }
    }

    let consensus_window: Option<(std::time::SystemTime, std::time::SystemTime)> = {
        let dirmgr = arti_client.dirmgr();
        match dirmgr.netdir(tor_netdir::Timeliness::Timely) {
            Ok(netdir) => {
                let lifetime = netdir.lifetime();
                Some((lifetime.valid_after(), lifetime.valid_until()))
            }
            Err(e) => {
                tracing::warn!(
                    "Could not extract consensus lifetime for time sync: {:?}",
                    e
                );
                None
            }
        }
    };

    if let Some(ref exit_country) = cfg.exit_nodes {
        let country_code = onionmasq::CountryCode::from_str(exit_country)
            .map_err(|e| anyhow::anyhow!("Invalid country code '{}': {}", exit_country, e))?;
        let dirmgr = arti_client.dirmgr();
        let netdir = dirmgr
            .netdir(tor_netdir::Timeliness::Timely)
            .map_err(|e| anyhow::anyhow!("Tor network directory not available: {}", e))?;

        let mut found = false;
        use tor_geoip::HasCountryCode;
        for relay in netdir.relays() {
            if relay.low_level_details().is_flagged_exit() {
                if let Some(relay_cc) = relay.country_code() {
                    if relay_cc == country_code {
                        found = true;
                        break;
                    }
                }
            }
        }
        if !found {
            return Err(anyhow::anyhow!(
                "No active Tor exit relays found in country '{}'. Connections would fail.",
                exit_country.to_uppercase()
            ));
        }
    }

    let exit_country_code = if let Some(ref exit_country) = cfg.exit_nodes {
        let country_code = onionmasq::CountryCode::from_str(exit_country)
            .map_err(|e| anyhow::anyhow!("Invalid country code '{}': {}", exit_country, e))?;
        Some(country_code)
    } else {
        None
    };

    let socks_task = if let Some(port) = cfg.socks_port {
        let (handle, _) =
            socks::run_socks_proxy(port, arti_client.clone(), exit_country_code).await?;
        Some(handle)
    } else {
        None
    };

    Ok(OnionmasqHandle {
        task,
        socks_task,
        tor_client: Arc::new(arti_client.clone()),

        dns_task: None,
        consensus_window,
    })
}

pub async fn stop_onionmasq(handle: OnionmasqHandle) -> Result<()> {
    if let Some(ref socks_task) = handle.socks_task {
        socks_task.abort();
    }
    if let Some(ref dns_task) = handle.dns_task {
        dns_task.abort();
    }
    handle.task.abort();
    Ok(())
}

pub mod isolation;
pub mod mss;
pub mod socks;

struct TunDevice {
    fd: tokio::io::unix::AsyncFd<std::os::fd::RawFd>,
}

impl tokio::io::AsyncRead for TunDevice {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        loop {
            match self.fd.poll_read_ready(cx) {
                std::task::Poll::Ready(Ok(mut guard)) => {
                    let fd = self.fd.as_raw_fd();
                    let unfilled = buf.initialize_unfilled();
                    let ret = unsafe {
                        libc::read(
                            fd,
                            unfilled.as_mut_ptr() as *mut libc::c_void,
                            unfilled.len(),
                        )
                    };
                    if ret < 0 {
                        let err = std::io::Error::last_os_error();
                        if err.kind() == std::io::ErrorKind::WouldBlock {
                            guard.clear_ready();
                            continue;
                        }
                        return std::task::Poll::Ready(Err(err));
                    }

                    let read_len = ret as usize;
                    let read_bytes =
                        unsafe { std::slice::from_raw_parts(unfilled.as_ptr(), read_len) };
                    if mss::reject_udp_and_icmp(read_bytes, fd) {
                        continue;
                    }

                    buf.advance(read_len);

                    let after = buf.filled().len();
                    if after > before {
                        let bytes = &mut buf.filled_mut()[before..after];
                        mss::clamp_mss(bytes, 1300);
                    }

                    return std::task::Poll::Ready(Ok(()));
                }
                std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                std::task::Poll::Pending => return std::task::Poll::Pending,
            }
        }
    }
}

impl tokio::io::AsyncWrite for TunDevice {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        loop {
            match self.fd.poll_write_ready(cx) {
                std::task::Poll::Ready(Ok(mut guard)) => {
                    let fd = self.fd.as_raw_fd();
                    let ret =
                        unsafe { libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len()) };
                    if ret < 0 {
                        let err = std::io::Error::last_os_error();
                        if err.kind() == std::io::ErrorKind::WouldBlock {
                            guard.clear_ready();
                            continue;
                        }
                        return std::task::Poll::Ready(Err(err));
                    }
                    return std::task::Poll::Ready(Ok(ret as usize));
                }
                std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                std::task::Poll::Pending => return std::task::Poll::Pending,
            }
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        let fd = self.fd.as_raw_fd();
        let ret = unsafe { libc::fsync(fd) };
        if ret < 0 {
            return std::task::Poll::Ready(Err(std::io::Error::last_os_error()));
        }
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::task::Poll::Ready(Ok(()))
    }
}

impl std::os::fd::AsRawFd for TunDevice {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.fd.as_raw_fd()
    }
}
