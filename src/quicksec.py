"""quicksec — quick security info for a given URL.

Usage: quicksec <url>
"""

import sys
import ssl
import socket
import datetime
import types
import urllib.parse
import requests
from requests.exceptions import RequestException

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

OK   = "  [OK]  "
WARN = " [WARN] "
FAIL = " [FAIL] "
INFO = " [INFO] "


def get_ssl_info(hostname, port=443):
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher_name, tls_version, _ = ssock.cipher()
                return {
                    "cert": cert,
                    "cipher": cipher_name,
                    "tls_version": tls_version,
                    "error": None,
                }
    except ssl.SSLCertVerificationError as e:
        return {"error": f"Certificate verification failed: {e}"}
    except ssl.SSLError as e:
        return {"error": f"SSL error: {e}"}
    except Exception as e:
        return {"error": str(e)}


def get_cn(name_tuples):
    for pair in name_tuples:
        for k, v in pair:
            if k == "commonName":
                return v
    return "unknown"


def parse_ssl_date(date_str):
    dt = datetime.datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
    return dt.replace(tzinfo=datetime.timezone.utc)


def check_https_redirect(hostname):
    """Return True if plain HTTP redirects to HTTPS."""
    try:
        r = requests.get(f"http://{hostname}", timeout=10, allow_redirects=True)
        return r.url.startswith("https://")
    except RequestException:
        return False


def fetch(url):
    try:
        r = requests.get(url, timeout=10, allow_redirects=True)
        return r, None
    except RequestException as e:
        return None, str(e)


def section(title):
    print(f"\n--- {title} ---")


def main(url=None):
    if url is None:
        if len(sys.argv) < 2:
            print("Usage: quicksec <url>")
            sys.exit(1)
        url = sys.argv[1]

    raw = url
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw

    parsed = urllib.parse.urlparse(raw)
    hostname = parsed.hostname
    url = raw

    print(f"\n{'='*58}")
    print(f"  Security check  >>  {hostname}")
    print(f"{'='*58}")

    # ── SSL / TLS ─────────────────────────────────────────────
    section("SSL / TLS")
    ssl_info = get_ssl_info(hostname)
    if ssl_info["error"]:
        print(f"{FAIL} {ssl_info['error']}")
    else:
        cert = ssl_info["cert"]
        cn = get_cn(cert.get("subject", []))
        not_after = parse_ssl_date(cert["notAfter"])
        days_left = (not_after - datetime.datetime.now(datetime.UTC)).days

        expiry_tag = OK if days_left > 30 else (WARN if days_left > 0 else FAIL)
        print(f"{OK   } Valid certificate  CN={cn}")
        print(f"{expiry_tag} Expires {not_after.date()}  ({days_left} days)")
        print(f"{INFO } Protocol: {ssl_info['tls_version']}  |  Cipher: {ssl_info['cipher']}")

        san = cert.get("subjectAltName", [])
        if san:
            names = ", ".join(v for _, v in san)
            print(f"{INFO } SANs: {names}")

    # ── HTTPS redirect ────────────────────────────────────────
    section("HTTPS redirect")
    redirects = check_https_redirect(hostname)
    tag = OK if redirects else WARN
    print(f"{tag} HTTP -> HTTPS redirect: {'yes' if redirects else 'no'}")

    # ── HTTP response & headers ───────────────────────────────
    section("Security headers")
    resp, err = fetch(url)
    if err or resp is None:
        print(f"{FAIL} Could not fetch {url}: {err}")
    else:
        hdrs = resp.headers

        server = hdrs.get("Server")
        if server:
            print(f"{WARN} Server header present: {server}")
        else:
            print(f"{OK  } Server header hidden")

        x_powered = hdrs.get("X-Powered-By")
        if x_powered:
            print(f"{WARN} X-Powered-By exposed: {x_powered}")

        for hdr in SECURITY_HEADERS:
            val = hdrs.get(hdr)
            if val:
                short = val if len(val) <= 60 else val[:57] + "..."
                print(f"{OK  } {hdr}: {short}")
            else:
                print(f"{WARN} {hdr}: missing")

        # ── Cookies ───────────────────────────────────────────
        section("Cookies")
        if not resp.cookies:
            print(f"{INFO } No cookies set")
        else:
            for cookie in resp.cookies:
                flags = []
                if cookie.secure:
                    flags.append("Secure")
                if cookie.has_nonstandard_attr("HttpOnly"):
                    flags.append("HttpOnly")
                samesite = cookie.get_nonstandard_attr("SameSite")
                if samesite:
                    flags.append(f"SameSite={samesite}")
                missing = []
                if not cookie.secure:
                    missing.append("Secure")
                if not cookie.has_nonstandard_attr("HttpOnly"):
                    missing.append("HttpOnly")
                tag = OK if not missing else WARN
                flag_str = ", ".join(flags) if flags else "none"
                miss_str = f"  (missing: {', '.join(missing)})" if missing else ""
                print(f"{tag} {cookie.name}  [{flag_str}]{miss_str}")

    print(f"\n{'='*58}\n")


class _QuicksecModule(types.ModuleType):
    def __call__(self, url):
        main(url)

sys.modules[__name__].__class__ = _QuicksecModule

if __name__ == "__main__":
    main()
