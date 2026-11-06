# RUSTINT

A small, practical, passive OSINT toolkit built with **Rust + Python**. It is designed for public-information lookups and authorized research. It does not attempt login, bypass access controls, exploit systems, or verify private mailbox ownership.

## Features (v0.1)
- `dns`: resolve a domain using the machine's configured DNS resolver.
- `ip`: validate an IP and report basic address classifications.
- `rdap`: retrieve public domain/IP registration data from `rdap.org`.
- `username`: check public profile URL reachability on a small set of sites.
- `email`: basic syntax validation and domain address resolution (not mailbox verification).

## Requirements
- Rust stable + Cargo
- Python 3.9+
- Internet access for RDAP and username lookups

## Run from source

```bash
git clone https://github.com/YOUR-USERNAME/RUSTINT.git
cd RUSTINT
export PYTHONPATH="$PWD/python"
cargo run -- dns example.com
cargo run -- ip 8.8.8.8
cargo run -- rdap example.com
cargo run -- username octocat
cargo run -- email user@example.com
cargo run -- --json rdap example.com
```

On Windows, set `PYTHONPATH` to the project's `python` directory in PowerShell:
```powershell
$env:PYTHONPATH = "$PWD/python"
cargo run -- username octocat
```

## Notes
- DNS uses the OS resolver and may return A/AAAA addresses only; it is not a full DNS record enumerator.
- Username results are heuristic. A reachable URL can be a login page, redirect, rate limit, or unrelated page.
- Email checks do not establish that an address exists or belongs to anyone.
- RDAP providers can rate-limit or return incomplete records.
- Use only on targets and data you are authorized to investigate. Respect site terms, privacy, and applicable law.
- Be polite: avoid high-volume requests. The username module uses sequential requests with an 8-second timeout.

## Roadmap
- Add proper MX/TXT/CNAME DNS record support.
- Add WHOIS fallback only where legally and operationally appropriate.
- Add source attribution, caching, retry/backoff, and unit/integration tests.
- Add export formats and a report command.

## License
MIT
