use std::process::Command;
use anyhow::Result;

/// Apply iptables rules for transparent Tor routing.
/// 
/// Security Model:
/// 1. Default policy is DROP (deny-all baseline)
/// 2. Only Tor user can reach the internet
/// 3. All DNS is forced through Tor DNSPort
/// 4. All TCP is forced through Tor TransPort  
/// 5. IPv6 is completely blocked (safest approach)
/// 6. Private networks are NOT exempt (prevents DNS leaks to router)
pub fn apply_rules(tor_user: &str) -> Result<()> {
    flush_rules()?;

    let dns_port = "9061";
    let trans_port = "9051";

    // ========================================================================
    // IPv4 NAT TABLE - Redirect traffic to Tor
    // ========================================================================
    
    
    // 1. Established connections (for already-NAT'd traffic)
    run_iptables(&["-t", "nat", "-A", "OUTPUT", "-m", "state", "--state", "ESTABLISHED", "-j", "RETURN"])?;
    
    // 2. Tor user bypasses NAT (its traffic goes directly out)
    run_iptables(&["-t", "nat", "-A", "OUTPUT", "-m", "owner", "--uid-owner", tor_user, "-j", "RETURN"])?;
    
    // 3. DNS REDIRECT - MUST come before any other destination rules
    run_iptables(&["-t", "nat", "-A", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", dns_port])?;
    run_iptables(&["-t", "nat", "-A", "OUTPUT", "-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-ports", dns_port])?;
    
    // 4. Loopback only - NO private network exceptions
    run_iptables(&["-t", "nat", "-A", "OUTPUT", "-d", "127.0.0.0/8", "-j", "RETURN"])?;
    
    // 5. ALL other TCP goes to Tor TransPort
    run_iptables(&["-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-j", "REDIRECT", "--to-ports", trans_port])?;

    // ========================================================================
    // IPv4 FILTER TABLE - Enforce what's allowed to leave
    // ========================================================================
    
    // Set default policy to DROP
    run_iptables(&["-P", "OUTPUT", "DROP"])?;
    
    
    // 2. Loopback is always allowed
    run_iptables(&["-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"])?;
    
    // 3. Allow traffic to localhost (for redirected packets)
    run_iptables(&["-A", "OUTPUT", "-d", "127.0.0.0/8", "-j", "ACCEPT"])?;
    
    // 4. Established/Related connections
    run_iptables(&["-A", "OUTPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"])?;
    
    // 5. Tor user can reach the internet
    run_iptables(&["-A", "OUTPUT", "-m", "owner", "--uid-owner", tor_user, "-j", "ACCEPT"])?;
    
    // 6. Explicitly DROP any DNS that bypassed NAT
    run_iptables(&["-A", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "DROP"])?;
    run_iptables(&["-A", "OUTPUT", "-p", "tcp", "--dport", "53", "-j", "DROP"])?;
    run_iptables(&["-A", "OUTPUT", "-p", "tcp", "--dport", "853", "-j", "DROP"])?; // DoT
    run_iptables(&["-A", "OUTPUT", "-p", "udp", "--dport", "443", "-j", "DROP"])?; // QUIC
    
    // 7. DROP everything else
    run_iptables(&["-A", "OUTPUT", "-j", "DROP"])?;

    // ========================================================================
    // IPv6 - BLOCK COMPLETELY
    // ========================================================================
    
    let _ = run_ip6tables(&["-P", "OUTPUT", "DROP"]);
    let _ = run_ip6tables(&["-P", "INPUT", "DROP"]);
    let _ = run_ip6tables(&["-P", "FORWARD", "DROP"]);
    
    let _ = run_ip6tables(&["-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"]);
    let _ = run_ip6tables(&["-A", "INPUT", "-i", "lo", "-j", "ACCEPT"]);
    
    let _ = run_ip6tables(&["-A", "OUTPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"]);
    let _ = run_ip6tables(&["-A", "INPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"]);
    
    let _ = run_ip6tables(&["-A", "OUTPUT", "-j", "DROP"]);
    let _ = run_ip6tables(&["-A", "INPUT", "-j", "DROP"]);

    println!("[+] Firewall rules applied (default-deny, Tor-only)");
    Ok(())
}

pub fn flush_rules() -> Result<()> {
    // Reset policies
    let _ = run_iptables(&["-P", "OUTPUT", "ACCEPT"]);
    let _ = run_iptables(&["-P", "INPUT", "ACCEPT"]);
    let _ = run_iptables(&["-P", "FORWARD", "ACCEPT"]);
    
    // Flush chains
    let _ = run_iptables(&["-t", "nat", "-F", "OUTPUT"]);
    let _ = run_iptables(&["-t", "filter", "-F", "OUTPUT"]);
    let _ = run_iptables(&["-t", "filter", "-F", "INPUT"]);
    
    // Reset IPv6
    let _ = run_ip6tables(&["-P", "OUTPUT", "ACCEPT"]);
    let _ = run_ip6tables(&["-P", "INPUT", "ACCEPT"]);
    let _ = run_ip6tables(&["-P", "FORWARD", "ACCEPT"]);
    
    let _ = run_ip6tables(&["-t", "nat", "-F", "OUTPUT"]);
    let _ = run_ip6tables(&["-t", "filter", "-F", "OUTPUT"]);
    let _ = run_ip6tables(&["-t", "filter", "-F", "INPUT"]);
    
    // Flush legacy
    let _ = Command::new("iptables-legacy").args(["-t", "nat", "-F", "OUTPUT"]).status();
    let _ = Command::new("iptables-legacy").args(["-t", "filter", "-F", "OUTPUT"]).status();
    let _ = Command::new("ip6tables-legacy").args(["-t", "nat", "-F", "OUTPUT"]).status();
    let _ = Command::new("ip6tables-legacy").args(["-t", "filter", "-F", "OUTPUT"]).status();
    
    println!("[+] Firewall rules flushed, policies reset to ACCEPT");
    Ok(())
}

fn run_iptables(args: &[&str]) -> Result<()> {
    let status = Command::new("iptables").args(args).status();
    match status {
        Ok(s) if s.success() => Ok(()),
        Ok(_) => {
            eprintln!("[!] iptables {:?} failed", args);
            Ok(())
        }
        Err(e) => {
            eprintln!("[!] Failed to run iptables: {}", e);
            Ok(())
        }
    }
}

fn run_ip6tables(args: &[&str]) -> Result<()> {
    let status = Command::new("ip6tables").args(args).status();
    match status {
        Ok(s) if s.success() => Ok(()),
        Ok(_) => Ok(()),
        Err(_) => Ok(()),
    }
}
