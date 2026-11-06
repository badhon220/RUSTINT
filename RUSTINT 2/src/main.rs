use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde::Serialize;
use std::{net::ToSocketAddrs, process::Command};

#[derive(Parser)]
#[command(name = "rustint", version, about = "Passive OSINT for public information and authorized research")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    #[arg(long, global = true)]
    json: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Resolve a domain using the system DNS resolver
    Dns { domain: String },
    /// Show basic classification for an IP address
    Ip { address: String },
    /// Fetch public RDAP data for a domain or IP
    Rdap { target: String },
    /// Check public profile URL reachability on selected sites
    Username { username: String },
    /// Check email syntax and resolve its domain (not mailbox verification)
    Email { address: String },
}

#[derive(Serialize)]
struct Output<T: Serialize> {
    tool: &'static str,
    target: String,
    result: T,
}

fn emit<T: Serialize>(tool: &'static str, target: String, result: T, json: bool) -> Result<()> {
    let output = Output { tool, target, result };
    if json {
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("{}: {}", output.tool, output.target);
        println!("{}", serde_json::to_string_pretty(&output.result)?);
    }
    Ok(())
}

fn run_python(mode: &str, value: &str) -> Result<serde_json::Value> {
    let output = Command::new("python3")
        .args(["-m", "rustint_py", mode, value])
        .output()
        .context("Python 3 is required. Install it with: sudo apt install python3")?;
    if !output.status.success() {
        anyhow::bail!("{}", String::from_utf8_lossy(&output.stderr));
    }
    Ok(serde_json::from_slice(&output.stdout).context("Python module returned invalid JSON")?)
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Dns { domain } => {
            let mut addresses: Vec<String> = format!("{domain}:443")
                .to_socket_addrs()
                .with_context(|| format!("DNS resolution failed for {domain}"))?
                .map(|addr| addr.ip().to_string())
                .collect();
            addresses.sort();
            addresses.dedup();
            emit("dns", domain, serde_json::json!({"addresses": addresses}), cli.json)?;
        }
        Commands::Ip { address } => {
            let ip: std::net::IpAddr = address.parse().context("Invalid IP address")?;
            let details = match ip {
                std::net::IpAddr::V4(v) => serde_json::json!({
                    "ip": v.to_string(),
                    "private": v.is_private(),
                    "loopback": v.is_loopback(),
                    "link_local": v.is_link_local(),
                    "multicast": v.is_multicast(),
                    "unspecified": v.is_unspecified()
                }),
                std::net::IpAddr::V6(v) => serde_json::json!({
                    "ip": v.to_string(),
                    "loopback": v.is_loopback(),
                    "multicast": v.is_multicast(),
                    "unique_local": v.is_unique_local(),
                    "unspecified": v.is_unspecified()
                })
            };
            emit("ip", address, details, cli.json)?;
        }
        Commands::Rdap { target } => {
            let url = if target.parse::<std::net::IpAddr>().is_ok() {
                format!("https://rdap.org/ip/{target}")
            } else {
                format!("https://rdap.org/domain/{}", target.trim_end_matches('.'))
            };
            let response = reqwest::Client::builder()
                .user_agent("RUSTINT/0.1 passive-osint")
                .build()?
                .get(url)
                .send()
                .await?;
            let status = response.status();
            let body: serde_json::Value = response.json().await.context("RDAP response was not JSON")?;
            if !status.is_success() {
                anyhow::bail!("RDAP request failed with HTTP {status}: {body}");
            }
            emit("rdap", target, body, cli.json)?;
        }
        Commands::Username { username } => {
            let result = run_python("username", &username)?;
            emit("username", username, result, cli.json)?;
        }
        Commands::Email { address } => {
            let result = run_python("email", &address)?;
            emit("email", address, result, cli.json)?;
        }
    }
    Ok(())
}
