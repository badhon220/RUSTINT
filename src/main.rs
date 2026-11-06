use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde::Serialize;
use std::{net::ToSocketAddrs, process::Command};

#[derive(Parser)]
#[command(name = "rustint", version, about = "Passive OSINT toolkit — only query public information you are allowed to access.")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    /// Print machine-readable JSON
    #[arg(long, global = true)]
    json: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Resolve a domain to IP addresses using the system resolver
    Dns { domain: String },
    /// Show basic IP information (reverse DNS + address classification)
    Ip { address: String },
    /// Query public RDAP registration data for a domain or IP
    Rdap { target: String },
    /// Check whether a username profile URL responds on selected public sites
    Username { username: String },
    /// Validate email syntax and inspect its domain's DNS resolution (not mailbox existence)
    Email { address: String },
}

#[derive(Serialize)]
struct Record<T: Serialize> { tool: &'static str, target: String, result: T }

fn print<T: Serialize>(tool: &'static str, target: String, result: T, json: bool) -> Result<()> {
    let record = Record { tool, target, result };
    if json {
        println!("{}", serde_json::to_string_pretty(&record)?);
    } else {
        println!("{} — {}", record.tool, record.target);
        println!("{}", serde_json::to_string_pretty(&record.result)?);
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Dns { domain } => {
            let host = format!("{}:443", domain);
            let mut ips: Vec<String> = host.to_socket_addrs()
                .with_context(|| format!("DNS lookup failed for {domain}"))?
                .map(|x| x.ip().to_string()).collect();
            ips.sort(); ips.dedup();
            print("dns", domain, serde_json::json!({"addresses": ips}), cli.json)?;
        }
        Commands::Ip { address } => {
            let ip: std::net::IpAddr = address.parse().context("Invalid IP address")?;
            let reverse = tokio::task::spawn_blocking(move || {
                (ip, format!("{}:0", ip).to_socket_addrs().ok()
                    .and_then(|mut it| it.next()).map(|x| x.ip().to_string()))
            }).await?;
            let (ip, _) = reverse;
            let result = match ip {
                std::net::IpAddr::V4(v) => serde_json::json!({
                    "ip": v.to_string(), "is_private": v.is_private(),
                    "is_loopback": v.is_loopback(), "is_link_local": v.is_link_local(),
                    "is_multicast": v.is_multicast()
                }),
                std::net::IpAddr::V6(v) => serde_json::json!({
                    "ip": v.to_string(), "is_loopback": v.is_loopback(),
                    "is_multicast": v.is_multicast(), "is_unique_local": v.is_unique_local()
                })
            };
            print("ip", address, result, cli.json)?;
        }
        Commands::Rdap { target } => {
            let url = if target.parse::<std::net::IpAddr>().is_ok() {
                format!("https://rdap.org/ip/{target}")
            } else {
                format!("https://rdap.org/domain/{}", target.trim_end_matches('.'))
            };
            let response = reqwest::Client::builder()
                .user_agent("RUSTINT/0.1 (passive OSINT; contact: set-your-contact-in-README)")
                .build()?.get(&url).send().await?;
            let status = response.status();
            let body: serde_json::Value = response.json().await
                .context("RDAP response was not valid JSON")?;
            if !status.is_success() {
                anyhow::bail!("RDAP returned HTTP {status}: {}", body);
            }
            print("rdap", target, body, cli.json)?;
        }
        Commands::Username { username } => {
            let output = Command::new("python3").args(["-m", "rustint_py", "username", &username])
                .output().context("Could not run Python. Install Python 3 and ensure python3 is on PATH.")?;
            if !output.status.success() {
                anyhow::bail!("{}", String::from_utf8_lossy(&output.stderr));
            }
            let value: serde_json::Value = serde_json::from_slice(&output.stdout)
                .context("Python module returned invalid JSON")?;
            print("username", username, value, cli.json)?;
        }
        Commands::Email { address } => {
            let output = Command::new("python3").args(["-m", "rustint_py", "email", &address])
                .output().context("Could not run Python. Install Python 3 and ensure python3 is on PATH.")?;
            if !output.status.success() {
                anyhow::bail!("{}", String::from_utf8_lossy(&output.stderr));
            }
            let value: serde_json::Value = serde_json::from_slice(&output.stdout)?;
            print("email", address, value, cli.json)?;
        }
    }
    Ok(())
}
