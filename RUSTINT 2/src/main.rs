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

    let client = reqwest::Client::builder()
        .user_agent("RUSTINT/0.3 (passive subdomain discovery)")
        .timeout(std::time::Duration::from_secs(60))
        .build()?;

    let response = client.get(&url).send().await?;
    let status = response.status();
    anyhow::ensure!(status.is_success(), "crt.sh returned HTTP {status}");

    let rows: Vec<Value> = response.json().await
        .context("crt.sh response was not valid JSON")?;

    let suffix = format!(".{domain}");
    let mut names = BTreeSet::new();

    for row in rows {
        if let Some(value) = row.get("name_value").and_then(Value::as_str) {
            for item in value.lines() {
                let name = item.trim()
                    .trim_start_matches("*.")
                    .trim_end_matches('.')
                    .to_ascii_lowercase();

                if name == domain || name.ends_with(&suffix) {
                    names.insert(name);
                }
            }
        }
    }

    let resolver = TokioAsyncResolver::tokio(
        ResolverConfig::default(),
        ResolverOpts::default()
    );

    let mut results = Vec::new();
    let mut resolved_count = 0usize;
    let mut unresolved_count = 0usize;

    for name in names {
        let a_lookup = resolver.lookup(&name, RecordType::A).await;
        let aaaa_lookup = resolver.lookup(&name, RecordType::AAAA).await;

        let (a_records, a_error) = match a_lookup {
            Ok(lookup) => (
                lookup.iter().map(|r| r.to_string()).collect::<Vec<_>>(),
                None
            ),
            Err(error) => (Vec::new(), Some(error.to_string()))
        };

        let (aaaa_records, aaaa_error) = match aaaa_lookup {
            Ok(lookup) => (
                lookup.iter().map(|r| r.to_string()).collect::<Vec<_>>(),
                None
            ),
            Err(error) => (Vec::new(), Some(error.to_string()))
        };

        let has_address = !a_records.is_empty() || !aaaa_records.is_empty();

        let a_no_records = a_error.as_ref().map_or(false, |e| {
            e.contains("no record found")
        });
        let aaaa_no_records = aaaa_error.as_ref().map_or(false, |e| {
            e.contains("no record found")
        });

        let has_error = (a_error.is_some() && !a_no_records)
            || (aaaa_error.is_some() && !aaaa_no_records);

        let state = if has_address {
            resolved_count += 1;
            "resolved"
        } else if has_error {
            unresolved_count += 1;
            "lookup_error"
        } else {
            unresolved_count += 1;
            "no_dns_answer"
        };

        results.push(json!({
            "hostname": name,
            "status": state,
            "A": a_records,
            "AAAA": aaaa_records,
            "A_error": a_error,
            "AAAA_error": aaaa_error
        }));
    }

    Ok(json!({
        "domain": domain,
        "source": "crt.sh (public Certificate Transparency logs)",
        "count": results.len(),
        "resolved_count": resolved_count,
        "unresolved_count": unresolved_count,
        "subdomains": results,
        "note": "DNS resolution does not prove that a website is reachable or that a service is running. Lookup errors are reported separately."
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
        .timeout(std::time::Duration::from_secs(60))
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


fn csv_report(tool: &str, result: &Value) -> Result<String> {
    let mut writer = csv::Writer::from_writer(Vec::new());

    if tool == "subdomains" {
        writer.write_record(["hostname", "status", "A", "AAAA"])?;

        if let Some(items) = result["subdomains"].as_array() {
            for item in items {
                writer.write_record([
                    item["hostname"].as_str().unwrap_or(""),
                    item["status"].as_str().unwrap_or(""),
                    &item["A"].as_array()
                        .map(|v| v.iter().filter_map(Value::as_str)
                        .collect::<Vec<_>>().join(";"))
                        .unwrap_or_default(),
                    &item["AAAA"].as_array()
                        .map(|v| v.iter().filter_map(Value::as_str)
                        .collect::<Vec<_>>().join(";"))
                        .unwrap_or_default(),
                ])?;
            }
        }
    } else {
        writer.write_record(["field", "value"])?;

        fn flatten(
            writer: &mut csv::Writer<Vec<u8>>,
            prefix: &str,
            value: &Value
        ) -> Result<()> {
            match value {
                Value::Object(map) => {
                    for (key, child) in map {
                        let path = if prefix.is_empty() {
                            key.clone()
                        } else {
                            format!("{prefix}.{key}")
                        };
                        flatten(writer, &path, child)?;
                    }
                }
                Value::Array(items) => {
                    for (index, child) in items.iter().enumerate() {
                        flatten(writer, &format!("{prefix}[{index}]"), child)?;
                    }
                }
                _ => {
                    writer.write_record([prefix, &value.to_string()])?;
                }
            }
            Ok(())
        }

        flatten(&mut writer, "", result)?;
    }

    let bytes = writer.into_inner()?;
    Ok(String::from_utf8(bytes)?)
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
        let extension = path.extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();

        let (content, format) = match extension.as_str() {
            "json" => (format!("{rendered}\n"), "JSON"),
            "csv" => (csv_report(tool, &result)?, "CSV"),
            _ => anyhow::bail!("Unsupported report format. Use .json or .csv"),
        };

        fs::write(&path, content)
            .with_context(|| format!("Could not write report to {}", path.display()))?;
        println!("[+] {format} report saved to {}", path.display());
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
