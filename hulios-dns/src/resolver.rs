use std::net::IpAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, UdpSocket};
use tracing::{debug, error};

use arti_client::TorClient;
use tor_rtcompat::PreferredRuntime;

use hickory_proto::op::{Header, HeaderCounts, Metadata, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, PTR};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_server::net::runtime::Time;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo, Server};
use hickory_server::zone_handler::MessageResponseBuilder;

use crate::check_rebinding;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DnsConfig {
    pub listen_addr: Option<String>,
}

pub struct DnsHandle {
    pub handle: tokio::task::JoinHandle<()>,
}

impl DnsHandle {
    pub fn abort(&self) {
        self.handle.abort();
    }
}

pub use hulios_onionmasq::TorResolver;

#[derive(Default)]
pub struct MockTorResolver {
    pub resolve_mock: std::sync::Mutex<std::collections::HashMap<String, Vec<IpAddr>>>,
    pub resolve_ptr_mock: std::sync::Mutex<std::collections::HashMap<IpAddr, Vec<String>>>,
}

impl MockTorResolver {
    pub fn new() -> Self {
        Self {
            resolve_mock: std::sync::Mutex::new(std::collections::HashMap::new()),
            resolve_ptr_mock: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }
}

#[async_trait::async_trait]
impl TorResolver for MockTorResolver {
    async fn resolve(&self, hostname: &str) -> Result<Vec<IpAddr>, arti_client::Error> {
        if let Some(ips) = self.resolve_mock.lock().unwrap().get(hostname) {
            Ok(ips.clone())
        } else {
            Ok(vec![])
        }
    }
    async fn resolve_ptr(&self, addr: IpAddr) -> Result<Vec<String>, arti_client::Error> {
        if let Some(names) = self.resolve_ptr_mock.lock().unwrap().get(&addr) {
            Ok(names.clone())
        } else {
            Ok(vec![])
        }
    }
}

pub struct ForwardingHandler {
    pub resolver: Arc<dyn TorResolver>,
}

#[async_trait::async_trait]
impl RequestHandler for ForwardingHandler {
    async fn handle_request<R: ResponseHandler, T: Time>(
        &self,
        request: &Request,
        response_handle: R,
    ) -> ResponseInfo {
        let mut response_handle = response_handle;
        let query = &request.queries.queries()[0];
        debug!("DNS Query received: {:?}", query);
        let name = query.name().to_string();
        let hostname = name.trim_end_matches('.').to_string();
        let qtype = query.query_type();

        let mut header = Header {
            metadata: Metadata::response_from_request(&request.metadata),
            counts: HeaderCounts::default(),
        };

        match qtype {
            RecordType::A | RecordType::AAAA => {
                match self.resolver.resolve(&hostname).await {
                    Ok(ips) => {
                        let mut has_rebinding = false;
                        for ip in &ips {
                            if !check_rebinding(*ip) {
                                has_rebinding = true;
                                break;
                            }
                        }

                        if has_rebinding {
                            debug!(
                                "DNS Rebinding detected for hostname {} (IPs: {:?})",
                                hostname, ips
                            );
                            header.metadata.response_code = ResponseCode::Refused;
                            let response = MessageResponseBuilder::from_message_request(request)
                                .build(header.metadata, vec![], vec![], vec![], vec![]);
                            response_handle
                                .send_response(response)
                                .await
                                .unwrap_or_else(|e| {
                                    debug!("Failed to send DNS response: {:?}", e);
                                    ResponseInfo::from(header)
                                })
                        } else {
                            let mut records = Vec::new();
                            for ip in &ips {
                                let rdata = match ip {
                                    IpAddr::V4(ipv4) => RData::A(A::from(*ipv4)),
                                    IpAddr::V6(ipv6) => RData::AAAA(AAAA::from(*ipv6)),
                                };
                                let name_parsed = match Name::from_str_relaxed(&name) {
                                    Ok(n) => n,
                                    Err(_) => query.name().clone().into(),
                                };
                                records.push(Record::from_rdata(name_parsed, 3600, rdata));
                            }
                            let records_refs: Vec<&Record> = records.iter().collect();
                            let response = MessageResponseBuilder::from_message_request(request)
                                .build(header.metadata, records_refs, vec![], vec![], vec![]);
                            response_handle
                                .send_response(response)
                                .await
                                .unwrap_or_else(|e| {
                                    debug!("Failed to send DNS response: {:?}", e);
                                    ResponseInfo::from(header)
                                })
                        }
                    }
                    Err(e) => {
                        debug!("Tor resolve error for {}: {:?}", hostname, e);
                        header.metadata.response_code = ResponseCode::ServFail;
                        let response = MessageResponseBuilder::from_message_request(request).build(
                            header.metadata,
                            vec![],
                            vec![],
                            vec![],
                            vec![],
                        );
                        response_handle
                            .send_response(response)
                            .await
                            .unwrap_or_else(|e| {
                                debug!("Failed to send DNS response: {:?}", e);
                                ResponseInfo::from(header)
                            })
                    }
                }
            }
            RecordType::PTR => {
                if let Some(ip) = parse_ptr_name(&hostname) {
                    match self.resolver.resolve_ptr(ip).await {
                        Ok(names) => {
                            let mut records = Vec::new();
                            for n in names {
                                let name_parsed = match Name::from_str_relaxed(&n) {
                                    Ok(parsed) => parsed,
                                    Err(_) => continue,
                                };
                                let rdata = RData::PTR(PTR(name_parsed));
                                let name_query_parsed = match Name::from_str_relaxed(&name) {
                                    Ok(n) => n,
                                    Err(_) => query.name().clone().into(),
                                };
                                records.push(Record::from_rdata(name_query_parsed, 3600, rdata));
                            }
                            let records_refs: Vec<&Record> = records.iter().collect();
                            let response = MessageResponseBuilder::from_message_request(request)
                                .build(header.metadata, records_refs, vec![], vec![], vec![]);
                            response_handle
                                .send_response(response)
                                .await
                                .unwrap_or_else(|e| {
                                    debug!("Failed to send DNS response: {:?}", e);
                                    ResponseInfo::from(header)
                                })
                        }
                        Err(e) => {
                            debug!("Tor resolve_ptr error for {}: {:?}", hostname, e);
                            header.metadata.response_code = ResponseCode::ServFail;
                            let response = MessageResponseBuilder::from_message_request(request)
                                .build(header.metadata, vec![], vec![], vec![], vec![]);
                            response_handle
                                .send_response(response)
                                .await
                                .unwrap_or_else(|e| {
                                    debug!("Failed to send DNS response: {:?}", e);
                                    ResponseInfo::from(header)
                                })
                        }
                    }
                } else {
                    debug!("Could not parse PTR IP from hostname {}", hostname);
                    header.metadata.response_code = ResponseCode::NXDomain;
                    let response = MessageResponseBuilder::from_message_request(request).build(
                        header.metadata,
                        vec![],
                        vec![],
                        vec![],
                        vec![],
                    );
                    response_handle
                        .send_response(response)
                        .await
                        .unwrap_or_else(|e| {
                            debug!("Failed to send DNS response: {:?}", e);
                            ResponseInfo::from(header)
                        })
                }
            }
            _ => {
                debug!("Unsupported query type {:?}", qtype);
                header.metadata.response_code = ResponseCode::NotImp;
                let response = MessageResponseBuilder::from_message_request(request).build(
                    header.metadata,
                    vec![],
                    vec![],
                    vec![],
                    vec![],
                );
                response_handle
                    .send_response(response)
                    .await
                    .unwrap_or_else(|e| {
                        debug!("Failed to send DNS response: {:?}", e);
                        ResponseInfo::from(header)
                    })
            }
        }
    }
}

pub fn parse_ptr_name(name: &str) -> Option<IpAddr> {
    let name_lower = name.to_lowercase();
    let name_trimmed = name_lower.trim_end_matches('.');

    if name_trimmed.ends_with(".in-addr.arpa") {
        let ip_part = name_trimmed.strip_suffix(".in-addr.arpa")?;
        let segments: Vec<&str> = ip_part.split('.').collect();
        if segments.len() != 4 {
            return None;
        }
        let reversed: Vec<&str> = segments.into_iter().rev().collect();
        let ip_str = reversed.join(".");
        ip_str.parse::<std::net::Ipv4Addr>().ok().map(IpAddr::V4)
    } else if name_trimmed.ends_with(".ip6.arpa") {
        let ip_part = name_trimmed.strip_suffix(".ip6.arpa")?;
        let segments: Vec<&str> = ip_part.split('.').collect();
        if segments.len() != 32 {
            return None;
        }
        let reversed: Vec<&str> = segments.into_iter().rev().collect();
        let mut hex_str = String::new();
        for (i, nibble) in reversed.iter().enumerate() {
            if i > 0 && i % 4 == 0 {
                hex_str.push(':');
            }
            hex_str.push_str(nibble);
        }
        hex_str.parse::<std::net::Ipv6Addr>().ok().map(IpAddr::V6)
    } else {
        None
    }
}

pub async fn start_dns_resolver_with_sockets(
    resolver: Arc<dyn TorResolver>,
    udp_sockets: Vec<UdpSocket>,
    tcp_listeners: Vec<TcpListener>,
) -> Result<DnsHandle, anyhow::Error> {
    let handler = ForwardingHandler { resolver };
    let mut server = Server::new(handler);
    for sock in udp_sockets {
        server.register_socket(sock);
    }
    for listener in tcp_listeners {
        server.register_listener(listener, std::time::Duration::from_secs(5), 1024);
    }

    let handle = tokio::spawn(async move {
        if let Err(e) = server.block_until_done().await {
            error!("DNS server error: {:?}", e);
        }
    });

    Ok(DnsHandle { handle })
}

pub async fn start_dns_resolver_with_client(
    resolver: Arc<dyn TorResolver>,
    cfg: &DnsConfig,
    ipv6_enabled: bool,
) -> Result<DnsHandle, anyhow::Error> {
    let listen_addr = cfg.listen_addr.as_deref().unwrap_or("127.0.0.1:53");
    let mut udp_sockets = vec![UdpSocket::bind(listen_addr).await?];
    let mut tcp_listeners = vec![TcpListener::bind(listen_addr).await?];

    if ipv6_enabled {
        let magic = hulios_common::HULIOS_DNS_IPV6_MAGIC_STR;
        let addr6 = format!("[{}]:53", magic);
        if let Ok(u6) = UdpSocket::bind(&addr6).await {
            if let Ok(t6) = TcpListener::bind(&addr6).await {
                udp_sockets.push(u6);
                tcp_listeners.push(t6);
            }
        }
    }

    start_dns_resolver_with_sockets(resolver, udp_sockets, tcp_listeners).await
}

pub async fn start_dns_resolver(
    arti: Arc<TorClient<PreferredRuntime>>,
    cfg: &DnsConfig,
    ipv6_enabled: bool,
) -> Result<DnsHandle, anyhow::Error> {
    start_dns_resolver_with_client(arti as Arc<dyn TorResolver>, cfg, ipv6_enabled).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_resolver::config::{NameServerConfig, ResolverConfig, ResolverOpts};
    use hickory_resolver::net::runtime::TokioRuntimeProvider;
    use hickory_resolver::net::{DnsError, NetError};
    use hickory_resolver::TokioResolver;
    use std::str::FromStr;

    #[tokio::test]
    async fn test_dns_resolution_and_rebinding_and_ptr() {
        let mock_resolver = Arc::new(MockTorResolver::new());

        // Setup mock data
        {
            let mut resolve = mock_resolver.resolve_mock.lock().unwrap();
            resolve.insert(
                "example.com".to_string(),
                vec![IpAddr::from_str("93.184.215.14").unwrap()],
            );
            resolve.insert(
                "rebind.com".to_string(),
                vec![IpAddr::from_str("127.0.0.1").unwrap()],
            );
            resolve.insert(
                "rebind-private.com".to_string(),
                vec![IpAddr::from_str("10.0.0.5").unwrap()],
            );

            let mut ptr = mock_resolver.resolve_ptr_mock.lock().unwrap();
            ptr.insert(
                IpAddr::from_str("8.8.8.8").unwrap(),
                vec!["dns.google".to_string()],
            );
        }

        // Bind to dynamic ports
        let udp_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();

        let local_addr = udp_socket.local_addr().unwrap();

        // Start server
        let dns_handle = start_dns_resolver_with_sockets(
            mock_resolver.clone() as Arc<dyn TorResolver>,
            vec![udp_socket],
            vec![tcp_listener],
        )
        .await
        .unwrap();

        // Setup client resolver pointing to our mock server
        let mut config = ResolverConfig::from_parts(None, vec![], vec![]);
        let mut ns_config = NameServerConfig::udp(local_addr.ip());
        ns_config.connections[0].port = local_addr.port();
        config.add_name_server(ns_config);
        let mut opts = ResolverOpts::default();
        // Fast timeout for tests
        opts.timeout = std::time::Duration::from_secs(3);
        opts.attempts = 1;

        let resolver = TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
            .build()
            .unwrap();

        // 1. Test standard A resolution
        let response = resolver.lookup_ip("example.com.").await.unwrap();
        let ips: Vec<IpAddr> = response.iter().collect();
        assert_eq!(ips, vec![IpAddr::from_str("93.184.215.14").unwrap()]);

        // 2. Test DNS rebinding protection (RFC1918 private / loopback IP)
        let err_loopback = resolver.lookup_ip("rebind.com.").await.unwrap_err();
        match err_loopback {
            NetError::Dns(DnsError::NoRecordsFound(no_records)) => {
                assert_eq!(no_records.response_code, ResponseCode::Refused);
            }
            NetError::Dns(DnsError::ResponseCode(code)) => {
                assert_eq!(code, ResponseCode::Refused);
            }
            other => panic!("Expected Refused, got {:?}", other),
        }

        let err_private = resolver.lookup_ip("rebind-private.com.").await.unwrap_err();
        match err_private {
            NetError::Dns(DnsError::NoRecordsFound(no_records)) => {
                assert_eq!(no_records.response_code, ResponseCode::Refused);
            }
            NetError::Dns(DnsError::ResponseCode(code)) => {
                assert_eq!(code, ResponseCode::Refused);
            }
            other => panic!("Expected Refused, got {:?}", other),
        }

        // 3. Test PTR query handling
        let ptr_response = resolver
            .reverse_lookup(IpAddr::from_str("8.8.8.8").unwrap())
            .await
            .unwrap();
        let names: Vec<String> = ptr_response
            .answers()
            .iter()
            .filter_map(|r| match &r.data {
                RData::PTR(ptr) => Some(ptr.0.to_utf8().trim_end_matches('.').to_string()),
                _ => None,
            })
            .collect();
        assert_eq!(names, vec!["dns.google".to_string()]);

        // Clean up
        dns_handle.abort();
    }
}
