# quicksec

A command-line tool and Python library for quickly auditing the security posture of any website. Pass it a URL and get a structured report covering TLS, HTTP security headers, HTTPS enforcement, and cookie flags — no config needed.

[![CI](https://github.com/nGubbins/quicksec/actions/workflows/ci.yml/badge.svg)](https://github.com/nGubbins/quicksec/actions/workflows/ci.yml)

---

## Install

```bash
pip install quicksec
```

---

## Usage

### CLI

```bash
quicksec <url>
```

The scheme is optional — `quicksec example.com` defaults to `https://`.

```bash
quicksec github.com
quicksec https://example.com
quicksec http://legacy-site.com
```

### Python

```python
import quicksec

results = quicksec("github.com")  # returns a list of strings

# print the full report
print("\n".join(results))

# filter for warnings and failures
issues = [r for r in results if "[WARN]" in r or "[FAIL]" in r]
```

### Sample output

```
==========================================================
  Security check  >>  github.com
==========================================================

--- SSL / TLS ---
  [OK]   Valid certificate  CN=github.com
  [OK]   Expires 2026-06-03  (39 days)
 [INFO]  Protocol: TLSv1.3  |  Cipher: TLS_AES_128_GCM_SHA256
 [INFO]  SANs: github.com, www.github.com

--- HTTPS redirect ---
  [OK]   HTTP -> HTTPS redirect: yes

--- Security headers ---
 [WARN]  Server header present: github.com
  [OK]   Strict-Transport-Security: max-age=31536000; includeSubdomains; preload
  [OK]   Content-Security-Policy: default-src 'none'; base-uri 'self'; ...
  [OK]   X-Frame-Options: deny
  [OK]   X-Content-Type-Options: nosniff
  [OK]   Referrer-Policy: origin-when-cross-origin, strict-origin-when-cross-origin
 [WARN]  Permissions-Policy: missing

--- Cookies ---
  [OK]   _gh_sess  [Secure, HttpOnly, SameSite=Lax]
 [WARN]  _octo  [Secure, SameSite=Lax]  (missing: HttpOnly)
```

---

## What it checks

| Check | Details |
|---|---|
| **SSL / TLS** | Certificate validity, expiry (warns under 30 days), TLS version, cipher suite, SANs |
| **HTTPS redirect** | Whether plain HTTP redirects to HTTPS |
| **Security headers** | `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy` |
| **Info disclosure** | Flags `Server` and `X-Powered-By` headers |
| **Cookies** | Checks each cookie for `Secure`, `HttpOnly`, and `SameSite` flags |

### Status indicators

| Tag | Meaning |
|---|---|
| `[OK]` | Passes the check |
| `[WARN]` | Present but could be improved, or missing a recommended header |
| `[FAIL]` | Missing or broken (e.g. expired cert, SSL error) |
| `[INFO]` | Informational — no judgement |

---

## Use cases

- **Pre-launch audit** — run before deploying a new site to catch missing headers or misconfigured TLS
- **Third-party vendor review** — quickly assess the security hygiene of an API or partner domain
- **Security regression check** — spot headers that quietly disappeared after a config change
- **CTF / bug bounty recon** — fast first-pass on a target to see what's exposed
- **Scripting** — integrate into your own tooling using the Python API

---

## Contributing

Contributions are welcome. The codebase is intentionally small — all logic lives in `src/quicksec.py`.

```bash
git clone https://github.com/nGubbins/quicksec.git
cd quicksec
python -m venv env
source env/bin/activate   # Windows: env\Scripts\activate
pip install -r requirements.txt
pytest
```

The core functions you'll want to work with:

| Function | Description |
|---|---|
| `check(url)` | Runs all checks, returns `list[str]` |
| `get_ssl_info(hostname)` | Returns cert, cipher, and TLS version as a dict |
| `fetch(url)` | Returns `(response, error)` — wraps `requests.get` |
| `check_https_redirect(hostname)` | Returns `True` if HTTP redirects to HTTPS |

To add a new check, add your logic inside `check()` and append result lines using the `OK`, `WARN`, `FAIL`, or `INFO` prefixes. Add tests in `tests/test_quicksec.py`.

---

## License

MIT
