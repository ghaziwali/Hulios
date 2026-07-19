use arti_client::TorClient;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info};

pub async fn run_socks_proxy<R: tor_rtcompat::Runtime + Clone>(
    port: u16,
    arti: TorClient<R>,
    exit_country: Option<arti_client::CountryCode>,
) -> Result<(tokio::task::JoinHandle<()>, u16), std::io::Error> {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).await?;
    let bound_port = listener.local_addr()?.port();
    info!("SOCKS5 proxy listening on 127.0.0.1:{}", bound_port);

    let task = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((socket, addr)) => {
                    debug!("SOCKS5 proxy connection from {:?}", addr);
                    let arti_clone = arti.clone();
                    let exit_country = exit_country;
                    tokio::spawn(async move {
                        if let Err(e) =
                            handle_socks_connection(socket, arti_clone, exit_country).await
                        {
                            debug!("SOCKS5 connection error: {:?}", e);
                        }
                    });
                }
                Err(e) => {
                    debug!("SOCKS5 accept error: {:?}", e);
                }
            }
        }
    });
    Ok((task, bound_port))
}

async fn handle_socks_connection<R: tor_rtcompat::Runtime + Clone>(
    mut socket: TcpStream,
    arti: TorClient<R>,
    exit_country: Option<arti_client::CountryCode>,
) -> Result<(), anyhow::Error> {
    let mut header = [0u8; 2];
    socket.read_exact(&mut header).await?;
    let version = header[0];
    let nmethods = header[1];
    if version != 0x05 {
        return Err(anyhow::anyhow!("Unsupported SOCKS version: {}", version));
    }

    let mut methods = vec![0u8; nmethods as usize];
    socket.read_exact(&mut methods).await?;

    if !methods.contains(&0x00) {
        socket.write_all(&[0x05, 0xFF]).await?;
        return Err(anyhow::anyhow!("No acceptable authentication methods"));
    }

    socket.write_all(&[0x05, 0x00]).await?;

    let mut req_header = [0u8; 4];
    socket.read_exact(&mut req_header).await?;
    let req_ver = req_header[0];
    let cmd = req_header[1];
    let atyp = req_header[3];

    if req_ver != 0x05 {
        return Err(anyhow::anyhow!(
            "Unsupported SOCKS request version: {}",
            req_ver
        ));
    }

    if cmd != 0x01 {
        send_error_reply(&mut socket, 0x07).await?;
        return Err(anyhow::anyhow!("Unsupported SOCKS command: {}", cmd));
    }

    let dest_addr = match atyp {
        0x01 => {
            let mut ipv4 = [0u8; 4];
            socket.read_exact(&mut ipv4).await?;
            let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::from(ipv4));
            ip.to_string()
        }
        0x03 => {
            let len = socket.read_u8().await? as usize;
            let mut domain_bytes = vec![0u8; len];
            socket.read_exact(&mut domain_bytes).await?;
            String::from_utf8(domain_bytes)?
        }
        0x04 => {
            let mut ipv6 = [0u8; 16];
            socket.read_exact(&mut ipv6).await?;
            let ip = std::net::IpAddr::V6(std::net::Ipv6Addr::from(ipv6));
            ip.to_string()
        }
        _ => {
            send_error_reply(&mut socket, 0x08).await?;
            return Err(anyhow::anyhow!("Unsupported address type: {}", atyp));
        }
    };

    let dest_port = socket.read_u16().await?;

    debug!("SOCKS5 connecting to {}:{}", dest_addr, dest_port);

    let mut prefs = arti_client::StreamPrefs::new();
    if let Some(cc) = exit_country {
        prefs.exit_country(cc);
    }
    match arti
        .connect_with_prefs((dest_addr.as_str(), dest_port), &prefs)
        .await
    {
        Ok(mut tor_stream) => {
            let reply = [
                0x05, // VER
                0x00, // REP (Success)
                0x00, // RSV
                0x01, // ATYP (IPv4)
                0x00, 0x00, 0x00, 0x00, // BND.ADDR
                0x00, 0x00, // BND.PORT
            ];
            socket.write_all(&reply).await?;

            let _ = tokio::io::copy_bidirectional(&mut socket, &mut tor_stream).await;
            Ok(())
        }
        Err(e) => {
            debug!(
                "Arti connect failed to {}:{}: {:?}",
                dest_addr, dest_port, e
            );
            send_error_reply(&mut socket, 0x01).await?;
            Err(e.into())
        }
    }
}

async fn send_error_reply(socket: &mut TcpStream, rep: u8) -> Result<(), std::io::Error> {
    let reply = [
        0x05, // VER
        rep,  // REP
        0x00, // RSV
        0x01, // ATYP (IPv4)
        0x00, 0x00, 0x00, 0x00, // BND.ADDR
        0x00, 0x00, // BND.PORT
    ];
    socket.write_all(&reply).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use arti_client::TorClientConfig;
    use tor_rtcompat::PreferredRuntime;

    static TEST_ID: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    fn get_test_client(runtime: PreferredRuntime) -> TorClient<PreferredRuntime> {
        let id = TEST_ID.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let temp_dir = std::env::temp_dir().join(format!("hulios-test-socks-{}", id));
        let _ = std::fs::create_dir_all(&temp_dir);

        let mut config_builder = TorClientConfig::builder();
        let cache_path = temp_dir.join("cache").to_string_lossy().into_owned();
        let state_path = temp_dir.join("state").to_string_lossy().into_owned();
        config_builder
            .storage()
            .cache_dir(arti_client::config::CfgPath::new(cache_path));
        config_builder
            .storage()
            .state_dir(arti_client::config::CfgPath::new(state_path));
        let config = config_builder.build().unwrap();

        TorClient::with_runtime(runtime)
            .config(config)
            .create_unbootstrapped()
            .unwrap()
    }

    #[tokio::test]
    async fn test_socks_port_conflict() {
        let runtime = PreferredRuntime::current().unwrap();
        let client = get_test_client(runtime);

        let _listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = _listener.local_addr().unwrap().port();

        let res = run_socks_proxy(port, client, None).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_socks_handshake_and_failure() {
        let runtime = PreferredRuntime::current().unwrap();
        let client = get_test_client(runtime);

        let (handle, port) = run_socks_proxy(0, client, None).await.unwrap();

        let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();

        // 1. Send handshake greeting
        stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();

        // 2. Read greeting response
        let mut response = [0u8; 2];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [0x05, 0x00]);

        // 3. Send connect request (IPv4 127.0.0.1:80)
        stream
            .write_all(&[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 80])
            .await
            .unwrap();

        // 4. Read response, expect general failure (0x01) because Tor client is unbootstrapped
        let mut reply = [0u8; 10];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[0], 0x05); // VER
        assert_eq!(reply[1], 0x01); // REP (General failure)

        handle.abort();
    }

    #[tokio::test]
    async fn test_socks_unsupported_version() {
        let runtime = PreferredRuntime::current().unwrap();
        let client = get_test_client(runtime);

        let (handle, port) = run_socks_proxy(0, client, None).await.unwrap();

        let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();

        // Send invalid version (SOCKS4)
        stream.write_all(&[0x04, 0x01, 0x00]).await.unwrap();

        // Stream should close or fail
        let mut response = [0u8; 2];
        match stream.read(&mut response).await {
            Ok(n) => assert_eq!(n, 0),
            Err(e) => {
                assert!(
                    e.kind() == std::io::ErrorKind::ConnectionReset
                        || e.kind() == std::io::ErrorKind::BrokenPipe
                );
            }
        }

        handle.abort();
    }
}
