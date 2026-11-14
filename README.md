# Cybersecurity Tools — Learning Project

Three small Python tools built for learning cybersecurity basics, by
**Muhammad Farhan Iqbal**. All Python **stdlib only** — no packages to
install. All tests run on synthetic / local data only.

## Tools

### 1. Password Strength Checker + Hashing Demo — `password_checker.py`
Scores a password (length, upper/lower/digit/symbol, common-password
check) and labels it **Weak / Medium / Strong**, and shows its SHA-256
hash. The password is **never stored or sent anywhere**.

```bash
python password_checker.py 'MyStr0ng!Pass#2026'
python password_checker.py '123456'
```

### 2. Localhost Port Scanner — `port_scanner.py`
Scans open ports on **your own computer only** (127.0.0.1) from the
default list: `21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 8080`.
Any other host is refused with a clear error.

```bash
python port_scanner.py
python port_scanner.py --ports 80,443,8080
python port_scanner.py --host example.com   # refused — localhost only
```

### 3. Phishing URL Checker — `phishing_checker.py`
Checks a URL against a local SQLite database (`phishing.db`) plus
heuristic rules (IP as host, too many subdomains, `@` in URL,
suspicious keywords, lookalike brand names, plain http on login
pages, very long URL, punycode). Prints a verdict
**SAFE / SUSPICIOUS / FLAGGED** with reasons, and logs every check.

```bash
python phishing_checker.py --init-db          # build the database
python phishing_checker.py https://www.google.com
python phishing_checker.py http://192.168.99.99/login
python phishing_checker.py --add-domain bad-lookalike.example --reason "Test entry"
```

### All-in-one menu — `main.py`
```bash
python main.py password 'MyStr0ng!Pass#2026'
python main.py scan
python main.py phishing --init-db
python main.py phishing https://www.google.com
```

## Database — `phishing.db` (SQLite)

Created with `python phishing_checker.py --init-db` (or
`python main.py phishing --init-db`). Rebuilding deletes old data.

| Table | Columns |
|---|---|
| `flagged_domains` | `id`, `domain` (unique), `reason`, `source`, `date_added` |
| `url_checks` | `id`, `url`, `verdict`, `reasons`, `checked_at` |

Seeded with **10 clearly-labelled example entries** (`source = 'example'`)
— invented lookalike domains that teach the patterns (typosquats like
`paypa1-secure-login.example`, brand lookalikes, an IP-address host).
Add your own with `--add-domain`.

```bash
sqlite3 phishing.db "SELECT domain, reason FROM flagged_domains;"
sqlite3 phishing.db "SELECT url, verdict FROM url_checks;"
```

## Tests

```bash
python tests/test_tools.py
```

Tests cover password scoring and hashing, localhost scanning (including
a real open-port check and the non-localhost refusal), and the phishing
checker (safe vs suspicious vs flagged verdicts, DB creation, check
logging). Verified: **17 tests, all passing, run 3 times**.

## Requirements

None — Python 3.8+ standard library only.

```text
# requirements.txt — stdlib only, nothing to install
```

## Honest limits

- **These tools are for learning, and for scanning/checking your OWN
  computer and URLs only. Do not use them against anyone else's
  systems.**
- **The port scanner only scans localhost (127.0.0.1).** It refuses any
  other target.
- **The phishing database contains example entries only, not a live
  threat feed.** It will not catch real phishing sites you have not
  added yourself — always check the real domain in your browser too.
- The password checker runs locally; no password ever leaves your
  computer.
