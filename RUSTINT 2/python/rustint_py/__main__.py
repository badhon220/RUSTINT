import json
import re
import socket
import sys
import urllib.error
import urllib.request

SITES = {
    "GitHub": "https://github.com/{}",
    "GitLab": "https://gitlab.com/{}",
    "Reddit": "https://www.reddit.com/user/{}",
    "Codeberg": "https://codeberg.org/{}",
    "Mastodon.social": "https://mastodon.social/@{}",
}

def check_username(username):
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,39}", username):
        raise ValueError("Username must be 1-39 characters (letters, numbers, dot, underscore, hyphen).")
    checks = {}
    for service, template in SITES.items():
        url = template.format(username)
        request = urllib.request.Request(url, headers={"User-Agent": "RUSTINT/0.1 public-profile-check"})
        try:
            with urllib.request.urlopen(request, timeout=8) as response:
                checks[service] = {"http_status": response.status, "url": url}
        except urllib.error.HTTPError as error:
            checks[service] = {"http_status": error.code, "url": url}
        except (urllib.error.URLError, TimeoutError) as error:
            checks[service] = {"error": str(getattr(error, "reason", error)), "url": url}
    return {
        "username": username,
        "checks": checks,
        "limitation": "HTTP response is only a lead. It does not prove an account exists or identify its owner."
    }

def check_email(address):
    if len(address) > 254 or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", address):
        raise ValueError("Invalid basic email syntax.")
    domain = address.rsplit("@", 1)[1].strip(".")
    try:
        addresses = sorted({entry[4][0] for entry in socket.getaddrinfo(domain, None)})
    except socket.gaierror:
        addresses = []
    return {
        "email": address,
        "syntax_valid": True,
        "domain": domain,
        "domain_addresses": addresses,
        "limitation": "This does not verify MX records, mailbox existence, ownership, or deliverability."
    }

def main():
    if len(sys.argv) != 3 or sys.argv[1] not in {"username", "email"}:
        raise SystemExit("Usage: python3 -m rustint_py {username|email} VALUE")
    try:
        result = check_username(sys.argv[2]) if sys.argv[1] == "username" else check_email(sys.argv[2])
        print(json.dumps(result, indent=2))
    except ValueError as error:
        print(error, file=sys.stderr)
        raise SystemExit(2)

if __name__ == "__main__":
    main()
