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
    "Mastodon.social": "https://mastodon.social/@{}",
    "Codeberg": "https://codeberg.org/{}",
}

def username_lookup(username):
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,39}", username):
        raise ValueError("Username must be 1-39 characters: letters, numbers, dot, underscore or hyphen.")
    results = {}
    for site, template in SITES.items():
        url = template.format(username)
        req = urllib.request.Request(url, headers={"User-Agent": "RUSTINT/0.1 (public profile URL checker)"})
        try:
            with urllib.request.urlopen(req, timeout=8) as response:
                results[site] = {"status": response.status, "url": url, "reachable": True}
        except urllib.error.HTTPError as exc:
            results[site] = {"status": exc.code, "url": url, "reachable": exc.code not in (404, 410)}
        except (urllib.error.URLError, TimeoutError) as exc:
            results[site] = {"status": None, "url": url, "error": str(exc.reason if hasattr(exc, "reason") else exc)}
    return {"username": username, "checks": results,
            "note": "HTTP reachability is only a lead, not proof that an account exists or belongs to a person."}

def email_check(address):
    if len(address) > 254 or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", address):
        raise ValueError("Email address does not pass basic syntax validation.")
    domain = address.rsplit("@", 1)[1].strip(".")
    try:
        records = sorted({item[4][0] for item in socket.getaddrinfo(domain, None)})
    except socket.gaierror:
        records = []
    return {"email": address, "syntax_valid": True, "domain": domain,
            "domain_addresses": records,
            "note": "This does not verify MX records, mailbox existence, ownership, or deliverability."}

def main():
    if len(sys.argv) != 3 or sys.argv[1] not in ("username", "email"):
        raise SystemExit("Usage: python -m rustint_py {username|email} VALUE")
    try:
        result = username_lookup(sys.argv[2]) if sys.argv[1] == "username" else email_check(sys.argv[2])
        print(json.dumps(result, indent=2))
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(2)

if __name__ == "__main__":
    main()
