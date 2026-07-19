use std::fs;

/// Check if a local address+port is in LISTEN/UNCONN state using /proc/net/tcp and /proc/net/udp.
/// `ip_hex`: IPv4 address in little-endian hex uppercase or lowercase, e.g. "0100007F" for 127.0.0.1
/// `port_hex`: port in big-endian hex uppercase or lowercase, e.g. "0035" for 53
/// Returns true if found in either /proc/net/tcp or /proc/net/udp.
fn is_port_listening_proc(ip_hex: &str, port_hex: &str) -> bool {
    let target = format!("{}:{}", ip_hex, port_hex);
    for path in &["/proc/net/tcp", "/proc/net/udp"] {
        if let Ok(content) = fs::read_to_string(path) {
            for line in content.lines().skip(1) {
                let cols: Vec<&str> = line.split_whitespace().collect();
                if cols.len() >= 2 && cols[1].eq_ignore_ascii_case(&target) {
                    return true;
                }
            }
        }
    }
    false
}

pub fn hickory_bind_ip() -> &'static str {
    if is_port_listening_proc("0100007F", "0035") {
        "127.0.0.2"
    } else {
        "127.0.0.1"
    }
}

pub fn detect_active_interfaces() -> Vec<String> {
    let mut interfaces = Vec::new();
    if let Ok(entries) = fs::read_dir("/sys/class/net/") {
        for entry in entries.flatten() {
            if let Ok(name) = entry.file_name().into_string() {
                if !name.starts_with("lo")
                    && !name.starts_with("docker")
                    && !name.starts_with("virbr")
                    && !name.starts_with("hulios")
                {
                    interfaces.push(name);
                }
            }
        }
    }
    interfaces.sort();
    interfaces
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hickory_bind_ip() {
        let ip = hickory_bind_ip();
        assert!(ip == "127.0.0.1" || ip == "127.0.0.2");
    }

    #[test]
    fn test_detect_active_interfaces() {
        let ifaces = detect_active_interfaces();
        for iface in &ifaces {
            assert!(!iface.starts_with("lo"));
            assert!(!iface.starts_with("hulios"));
            assert!(!iface.starts_with("docker"));
            assert!(!iface.starts_with("virbr"));
        }
    }
}
