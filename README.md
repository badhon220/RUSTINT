# RUSTINT

**Linux-first passive OSINT toolkit | Rust + Python**

RUSTINT is designed for authorized security research using public information. It does not attempt account login, bypass access controls, exploit systems, or verify private mailbox ownership.

## v0.2 features

- **DNS:** A, AAAA, MX, TXT, NS and CNAME lookups using a DNS resolver library.
- **Subdomains:** passive discovery from public Certificate Transparency logs via crt.sh.
- **Email domain checks:** MX, SPF TXT and DMARC TXT inspection. No mailbox verification.
- **IP:** local IP address classification.
- **RDAP:** public domain/IP registration data.
- **Username:** HTTP reachability checks for selected public profile URLs.
- **Reports:** save any command result as JSON with `--output`.

## Kali Linux installation

```bash
sudo apt update
sudo apt install -y git curl build-essential python3
```

Install Rust/Cargo if missing using the official rustup instructions at https://rustup.rs, then:

```bash
source "$HOME/.cargo/env"
git clone https://github.com/badhon220/RUSTINT.git
cd RUSTINT
chmod +x install.sh
./install.sh
```

If needed, add the local binary directory to PATH:

```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
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

Save machine-readable results:

```bash
rustint dns example.com --output dns-report.json
rustint subdomains example.com --output subdomains-report.json
rustint email user@example.com --output email-report.json
```

## Data sources and limitations

- DNS results come from the system-configured recursive resolver. Empty record lists mean no answer was returned for that query.
- Subdomains come from public Certificate Transparency logs. They can be historical, duplicated across certificates, or inactive; this is not a live-host scan.
- Email DNS checks inspect domain mail configuration only. They do not confirm mailbox existence, ownership, or deliverability.
- RDAP data may be redacted, incomplete, or rate-limited by registry services.
- Username checks use HTTP responses as leads only; redirects, login pages, blocks and rate limits can mislead.
- `--output` writes JSON locally. Treat reports as potentially sensitive and do not publish them without review.

## Responsible use

Only investigate domains and information you are authorized to assess. Respect privacy, service terms, rate limits and applicable law. Subdomain discovery is passive; do not assume discovered names are in scope for active testing.

## Uninstall

```bash
rm -f "$HOME/.local/bin/rustint"
rm -rf "$HOME/.local/share/rustint"
```

## License

MIT
