# RUSTINT

**Fast. Reliable. Open-Source Intelligence.**

RUSTINT is a Linux-first passive OSINT toolkit built with Rust and Python. It collects and checks public information for authorized research. It does not attempt account login, bypass access controls, exploit systems, or verify private mailbox ownership.

## Kali Linux support

Kali Linux is the primary target. Debian- and Ubuntu-based distributions should also work when Rust/Cargo and Python 3 are installed.

## Features in v0.1

| Command | Function |
|---|---|
| `rustint dns DOMAIN` | Resolve a domain using the system resolver (A/AAAA addresses) |
| `rustint ip ADDRESS` | Show basic IP address classifications |
| `rustint rdap TARGET` | Fetch public RDAP registration data for a domain or IP |
| `rustint username NAME` | Check public profile URL responses on selected platforms |
| `rustint email ADDRESS` | Validate basic syntax and resolve the email domain |

Add `--json` for machine-readable output, for example `rustint --json rdap example.com`.

## 1. Install prerequisites on Kali

```bash
sudo apt update
sudo apt install -y git curl build-essential python3
```

Install Rust and Cargo with the official rustup installer if they are not already installed:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

Verify:

```bash
rustc --version
cargo --version
python3 --version
```

## 2. Download and install RUSTINT

```bash
git clone https://github.com/badhon220/RUSTINT.git
cd RUSTINT
chmod +x install.sh
./install.sh
```

If `~/.local/bin` is not in your PATH:

```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

## 3. Run

```bash
rustint --help
rustint dns example.com
rustint ip 8.8.8.8
rustint rdap example.com
rustint username octocat
rustint email user@example.com
rustint --json rdap example.com
```

## Run without installing

```bash
export PYTHONPATH="$PWD/python"
cargo run -- dns example.com
cargo run -- rdap example.com
cargo run -- username octocat
cargo run -- email user@example.com
```

## Limitations

- DNS currently uses the system resolver and returns address results; it is not a full DNS record enumerator.
- Username checks are heuristic. A URL response does not prove that an account exists or belongs to a particular person.
- Email checks do not verify MX records, mailbox existence, ownership, or deliverability.
- RDAP and public sites may rate-limit requests or return incomplete information.
- Internet access is required for RDAP and username checks.

Use only public information and systems you are authorized to investigate. Respect privacy, platform terms, and applicable law. Avoid high-volume requests.

## Uninstall

```bash
rm -f "$HOME/.local/bin/rustint"
rm -rf "$HOME/.local/share/rustint"
```

## Roadmap

- Full DNS record support (MX, TXT, NS, CNAME)
- Passive subdomain discovery with source attribution
- SPF/DMARC checks
- Caching, retry/backoff, automated tests, and HTML reports

## License

MIT
