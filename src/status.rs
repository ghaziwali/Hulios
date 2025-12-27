use anyhow::{Result, Context};
use serde::Deserialize;
use colored::*;

#[derive(Deserialize)]
struct TorStatus {
    #[serde(rename = "IsTor")]
    is_tor: bool,
    #[serde(rename = "IP")]
    ip: String,
}

pub fn print_status() {
    match check_status() {
        Ok(status) => {
            println!("\n[+] Status: {}", if status.is_tor { "The shadows are calm".green() } else { "The shadows whisper".red() });
            println!("[+] Ip: {}\n", status.ip.cyan());
        }
        Err(e) => {
            eprintln!("{} {}", "[!] Error checking status:".red(), e);
             println!("[*] Trying simple IP check via ifconfig.me...");
             // Fallback
             let _ = std::process::Command::new("curl").arg("ifconfig.me").status();
             println!("");
        }
    }
}

fn check_status() -> Result<TorStatus> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;
        
    let resp = client.get("https://check.torproject.org/api/ip")
        .send()
        .context("Failed to connect to check.torproject.org")?;
        
    let status: TorStatus = resp.json().context("Failed to parse JSON")?;
    Ok(status)
}
