use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde_json::{json, Value};
use std::{collections::BTreeSet, fs, net::IpAddr, path::PathBuf};
use trust_dns_resolver::{
    config::{ResolverConfig, ResolverOpts},
    proto::rr::RecordType,
    TokioAsyncResolver,
};

#[derive(Parser)]
#[command(name = "rustint", version, about = "Passive OSINT for public information and authorized research")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    /// Save results as JSON to a file
    #[arg(long, global = true, value_name = "FILE")]
    output: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Commands {
    /// Query common DNS record types (A, AAAA, MX, TXT, NS, CNAME)
    Dns { domain: String },
    /// Discover publicly logged subdomains using Certificate Transparency (crt.sh)
    Subdomains { domain: String },
    /// Check MX, SPF and DMARC DNS configuration for an email domain
    Email { address: String },
    /// Show basic classification for an IP address
    Ip { address: String },
    /// Fetch public RDAP registration data for a domain or IP
    Rdap { target: String },
    /// Check public profile URL responses on selected platforms
    Username { username: String },
}

fn normalize_domain(input: &str) -> Result<String> {
    let value = input.trim().trim_end_matches('.').to_ascii_lowercase();
    anyhow::ensure!(!value.is_empty() && !value.contains('/') && !value.contains('@'),
        "Provide a domain name only, e.g. example.com");
    anyhow::ensure!(value.len() <= 253 && value.split('.').all(|label| {
        !label.is_empty() && label.len() <= 63 &&
        label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') &&
        !label.starts_with('-') && !label.ends_with('-')
    }), "Invalid domain name");
    Ok(value)
}

async fn query_records(resolver: &TokioAsyncResolver, name: &str, kind: RecordType) -> Vec<String> {
    match resolver.lookup(name, kind).await {
        Ok(lookup) => lookup.iter().map(|record| record.to_string()).collect(),
        Err(_) => Vec::new(),
    }
}

async fn dns_result(domain: &str) -> Result<Value> {
    let domain = normalize_domain(domain)?;
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
    let mut records = serde_json::Map::new();
    for (label, kind) in [
        ("A", RecordType::A), ("AAAA", RecordType::AAAA),
        ("MX", RecordType::MX), ("TXT", RecordType::TXT),
        ("NS", RecordType::NS), ("CNAME", RecordType::CNAME),
    ] {
        let values = query_records(&resolver, &domain, kind).await;
        records.insert(label.to_string(), json!(values));
    }
    Ok(json!({
        "domain": domain,
        "records": records,
        "note": "Queries use the configured DNS resolver. Empty arrays mean no answer was returned; they do not prove a record can never exist."
    }))
}

async fn email_result(address: &str) -> Result<Value> {
    anyhow::ensure!(address.len() <= 254 && address.matches('@').count() == 1,
        "Provide one email address in name@domain format");
    let (local, raw_domain) = address.split_once('@').context("Invalid email address")?;
    anyhow::ensure!(!local.is_empty() && !local.chars().any(char::is_whitespace)
        && !local.starts_with('.') && !local.ends_with('.'), "Invalid email local part");
    let domain = normalize_domain(raw_domain)?;
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
    let mx = query_records(&resolver, &domain, RecordType::MX).await;
    let txt = query_records(&resolver, &domain, RecordType::TXT).await;
    let dmarc = query_records(&resolver, &format!("_dmarc.{domain}"), RecordType::TXT).await;
    let spf: Vec<String> = txt.iter().filter(|v| v.to_ascii_lowercase().contains("v=spf1"))
        .cloned().collect();
    Ok(json!({
        "email": address,
        "syntax_valid_basic": true,
        "domain": domain,
        "mx": mx,
        "spf_txt": spf,
        "dmarc_txt": dmarc,
        "mailbox_verified": false,
        "note": "DNS policy checks do not verify mailbox existence, ownership, or deliverability."
    }))
}

async fn subdomains_result(domain: &str) -> Result<Value> {
    let domain = normalize_domain(domain)?;
    let url = format!("https://crt.sh/?q=%25.{}&output=json", domain);
    let response = reqwest::Client::builder()
        .user_agent("RUSTINT/0.2 (passive certificate-transparency lookup)")
        .timeout(std::time::Duration::from_secs(25))
        .build()?
        .get(&url).send().await?;
    let status = response.status();
    anyhow::ensure!(status.is_success(), "crt.sh returned HTTP {status}");
    let rows: Vec<Value> = response.json().await.context("crt.sh response was not valid JSON")?;
    let suffix = format!(".{domain}");
    let mut names = BTreeSet::new();
    for row in rows {
        if let Some(value) = row.get("name_value").and_then(Value::as_str) {
            for item in value.lines() {
                let name = item.trim().trim_start_matches("*.").trim_end_matches('.').to_ascii_lowercase();
                if name == domain || name.ends_with(&suffix) {
                    names.insert(name);
                }
            }
        }
    }
    Ok(json!({
        "domain": domain,
        "source": "crt.sh (public Certificate Transparency logs)",
        "count": names.len(),
        "subdomains": names.into_iter().collect::<Vec<_>>(),
        "note": "Passive certificate-log discovery only. Results may include historical names and do not prove a host is currently active."
    }))
}

async fn rdap_result(target: &str) -> Result<Value> {
    let url = if target.parse::<IpAddr>().is_ok() {
        format!("https://rdap.org/ip/{target}")
    } else {
        format!("https://rdap.org/domain/{}", normalize_domain(target)?)
    };
    let response = reqwest::Client::builder()
        .user_agent("RUSTINT/0.2 (passive OSINT)")
        .timeout(std::time::Duration::from_secs(25))
        .build()?.get(url).send().await?;
    let status = response.status();
    let body: Value = response.json().await.context("RDAP response was not valid JSON")?;
    anyhow::ensure!(status.is_success(), "RDAP returned HTTP {status}: {body}");
    Ok(body)
}

fn ip_result(address: &str) -> Result<Value> {
    let ip: IpAddr = address.parse().context("Invalid IP address")?;
    Ok(match ip {
        IpAddr::V4(v) => json!({
            "ip": v.to_string(), "private": v.is_private(), "loopback": v.is_loopback(),
            "link_local": v.is_link_local(), "multicast": v.is_multicast(),
            "unspecified": v.is_unspecified(), "global_unicast": !v.is_private() && !v.is_loopback()
        }),
        IpAddr::V6(v) => json!({
            "ip": v.to_string(), "loopback": v.is_loopback(), "multicast": v.is_multicast(),
            "unique_local": v.is_unique_local(), "unspecified": v.is_unspecified(),
            "link_local": v.is_unicast_link_local()
        })
    })
}

async fn run() -> Result<()> {
    let cli = Cli::parse();
    let (tool, target, result) = match &cli.command {
        Commands::Dns { domain } => ("dns", domain.clone(), dns_result(domain).await?),
        Commands::Subdomains { domain } => ("subdomains", domain.clone(), subdomains_result(domain).await?),
        Commands::Email { address } => ("email", address.clone(), email_result(address).await?),
        Commands::Ip { address } => ("ip", address.clone(), ip_result(address)?),
        Commands::Rdap { target } => ("rdap", target.clone(), rdap_result(target).await?),
        Commands::Username { username } => {
            let output = std::process::Command::new("python3")
                .args(["-m", "rustint_py", "username", username])
                .output().context("Python 3 is required for username checks")?;
            anyhow::ensure!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
            ("username", username.clone(), serde_json::from_slice(&output.stdout)?)
        }
    };
    let document = json!({"tool": tool, "target": target, "result": result});
    let rendered = serde_json::to_string_pretty(&document)?;
    if let Some(path) = cli.output {
        fs::write(&path, format!("{rendered}\n"))
            .with_context(|| format!("Could not write report to {}", path.display()))?;
        println!("[+] JSON report saved to {}", path.display());
    } else {
        println!("{tool}: {target}");
        println!("{}", serde_json::to_string_pretty(&document["result"])?);
    }
    Ok(())
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("[!] {error:#}");
        std::process::exit(1);
    }
}
