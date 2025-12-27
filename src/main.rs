use clap::{Parser, Subcommand};
use colored::*;
use std::process;

mod engine;
mod iptables;
mod status;

#[derive(Parser)]
#[command(name = "hulios")]
#[command(about = "HULIOS: An engine to make Tor Network your default gateway", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Start,
    Stop,
    Restart,
    Status,
    Flush,
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Start => {
            println!("{}", "[+] Starting HULIOS...".green());
            if let Err(e) = engine::start() {
                eprintln!("{} {}", "[!] Error starting HULIOS:".red(), e);
                process::exit(1);
            }
            println!("{}", "[+] HULIOS started successfully.".green());
        }
        Commands::Stop => {
            println!("{}", "[+] Stopping HULIOS...".yellow());
            if let Err(e) = engine::stop() {
                eprintln!("{} {}", "[!] Error stopping HULIOS:".red(), e);
                process::exit(1);
            }
             println!("{}", "[+] HULIOS stopped.".green());
        }
        Commands::Restart => {
            println!("{}", "[+] Restarting HULIOS...".yellow());
            if let Err(e) = engine::restart() {
                eprintln!("{} {}", "[!] Error restarting HULIOS:".red(), e);
                process::exit(1);
            }
             println!("{}", "[+] HULIOS restarted.".green());
        }
        Commands::Status => {
             status::print_status();
        }
        Commands::Flush => {
            println!("{}", "[+] Flushing IPTables rules...".yellow());
            if let Err(e) = engine::flush() {
                 eprintln!("{} {}", "[!] Error flushing rules:".red(), e);
                 process::exit(1);
            }
             println!("{}", "[+] Rules flushed.".green());
        }
    }
}
