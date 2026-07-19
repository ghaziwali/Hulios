use std::net::IpAddr;

/// Checks if an IP address is safe (publicly routable) or should be blocked (private/local/reserved).
///
/// Returns `true` if the address is safe, `false` if it should be blocked.
pub fn check_rebinding(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(ipv4) => {
            !(ipv4.is_private()
                || ipv4.is_loopback()
                || ipv4.is_link_local()
                || ipv4.is_broadcast()
                || ipv4.is_documentation()
                || ipv4.is_unspecified())
        }
        IpAddr::V6(ipv6) => {
            if ipv6.is_loopback() || ipv6.is_unspecified() {
                return false;
            }

            let octets = ipv6.octets();
            let segments = ipv6.segments();

            // ULA (fc00::/7)
            if (octets[0] & 0xfe) == 0xfc {
                return false;
            }

            // Link-local (fe80::/10)
            if octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80 {
                return false;
            }

            // Documentation addresses: 2001:db8::/32 and 3fff::/20
            if (segments[0] == 0x2001 && segments[1] == 0xdb8)
                || (segments[0] == 0x3fff && (segments[1] & 0xf000) == 0)
            {
                return false;
            }

            // Benchmark addresses: 2001:2::/48
            if segments[0] == 0x2001 && segments[1] == 0x2 && segments[2] == 0 {
                return false;
            }

            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_ipv4_rebinding() {
        // Safe / Public
        assert!(check_rebinding(IpAddr::from_str("8.8.8.8").unwrap()));
        assert!(check_rebinding(IpAddr::from_str("1.1.1.1").unwrap()));
        assert!(check_rebinding(IpAddr::from_str("200.1.2.3").unwrap()));

        // Private blocks
        assert!(!check_rebinding(IpAddr::from_str("10.0.0.1").unwrap()));
        assert!(!check_rebinding(IpAddr::from_str("172.16.0.5").unwrap()));
        assert!(!check_rebinding(IpAddr::from_str("192.168.1.1").unwrap()));

        // Loopback
        assert!(!check_rebinding(IpAddr::from_str("127.0.0.1").unwrap()));

        // Link-local
        assert!(!check_rebinding(IpAddr::from_str("169.254.0.1").unwrap()));

        // Broadcast
        assert!(!check_rebinding(
            IpAddr::from_str("255.255.255.255").unwrap()
        ));

        // Documentation
        assert!(!check_rebinding(IpAddr::from_str("192.0.2.1").unwrap()));
        assert!(!check_rebinding(IpAddr::from_str("198.51.100.2").unwrap()));
        assert!(!check_rebinding(IpAddr::from_str("203.0.113.3").unwrap()));

        // Unspecified
        assert!(!check_rebinding(IpAddr::from_str("0.0.0.0").unwrap()));
    }

    #[test]
    fn test_ipv6_rebinding() {
        // Safe / Public
        assert!(check_rebinding(
            IpAddr::from_str("2001:4860:4860::8888").unwrap()
        ));
        assert!(check_rebinding(
            IpAddr::from_str("2606:4700:4700::1111").unwrap()
        ));

        // Loopback
        assert!(!check_rebinding(IpAddr::from_str("::1").unwrap()));

        // Unspecified
        assert!(!check_rebinding(IpAddr::from_str("::").unwrap()));

        // ULA (fc00::/7)
        assert!(!check_rebinding(IpAddr::from_str("fc00::1").unwrap()));
        assert!(!check_rebinding(
            IpAddr::from_str("fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff").unwrap()
        ));

        // Link-local (fe80::/10)
        assert!(!check_rebinding(IpAddr::from_str("fe80::1").unwrap()));
        assert!(!check_rebinding(IpAddr::from_str("febf::ffff").unwrap()));

        // Documentation
        assert!(!check_rebinding(IpAddr::from_str("2001:db8::1").unwrap()));
        assert!(!check_rebinding(IpAddr::from_str("3fff::1234").unwrap()));
        assert!(!check_rebinding(
            IpAddr::from_str("3fff:0fff:ffff:ffff:ffff:ffff:ffff:ffff").unwrap()
        ));

        // Benchmark (2001:2::/48)
        assert!(!check_rebinding(IpAddr::from_str("2001:2::1").unwrap()));
        assert!(!check_rebinding(
            IpAddr::from_str("2001:2:0:ffff::1").unwrap()
        ));
    }
}
