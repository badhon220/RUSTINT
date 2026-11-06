import json
import re
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
        raise ValueError("Username must be 1-39 characters: letters, numbers, dot, underscore or hyphen.")
    checks = {}
    for service, template in SITES.items():
        url = template.format(username)
        request = urllib.request.Request(url, headers={"User-Agent": "RUSTINT/0.2 public-profile-check"})
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
        "limitation": "HTTP responses are leads only; they do not prove account ownership or identity."
    }

def main():
    if len(sys.argv) != 3 or sys.argv[1] != "username":
        raise SystemExit("Usage: python3 -m rustint_py username USERNAME")
    try:
        print(json.dumps(check_username(sys.argv[2]), indent=2))
    except ValueError as error:
        print(error, file=sys.stderr)
        raise SystemExit(2)

if __name__ == "__main__":
    main()
