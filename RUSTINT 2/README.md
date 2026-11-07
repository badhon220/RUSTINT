# RUSTINT

**Linux-first passive OSINT toolkit | Rust + Python**

RUSTINT is designed for authorized security research using publicly available information.

## v0.3.0 Features

- **DNS:** A, AAAA, MX, TXT, NS and CNAME lookups.
- **Subdomains:** Passive discovery using public Certificate Transparency logs via crt.sh.
- **Live DNS validation:** Checks discovered hostnames for IPv4 and IPv6 DNS records.
- **DNS status:** Reports `resolved`, `no_dns_answer`, and `lookup_error`.
- **Email:** MX, SPF and DMARC DNS configuration checks.
- **IP:** Basic IPv4 and IPv6 classification.
- **RDAP:** Public domain and IP registration information.
- **Username:** HTTP response checks for selected public profile URLs.
- **JSON reports:** Structured machine-readable reports.
- **CSV reports:** Spreadsheet-compatible reports.

## Kali Linux Installation

Install prerequisites:

```bash
sudo apt update
sudo apt install -y git curl build-essential python3


```bash
source "$HOME/.cargo/env"
git clone https://github.com/badhon220/RUSTINT.git
cd RUSTINT/"RUSTINT 2"
chmod +x install.sh
./install.sh
```

## Usage

```bash
rustint --help
rustint dns example.com
rustint subdomains example.com
rustint email user@example.com
rustint ip 8.8.8.8
rustint rdap example.com
rustint username octocat
```

## Report Export

```bash
rustint dns example.com --output dns-report.json
rustint subdomains example.com --output subdomains.json
rustint subdomains example.com --output subdomains.csv
```

## Limitations

- Certificate Transparency results may include historical hostnames.
- DNS resolution does not prove a website is reachable.
- Email checks do not verify mailbox existence.
- RDAP data may be incomplete or rate-limited.
- Username HTTP responses do not prove account ownership.

## Responsible Use

Only investigate domains and information you are authorized to assess. Respect privacy, service terms, rate limits and applicable laws.

## Uninstall

```bash
rm -f "$HOME/.local/bin/rustint"
rm -rf "$HOME/.local/share/rustint"
```

## License

MIT
```
