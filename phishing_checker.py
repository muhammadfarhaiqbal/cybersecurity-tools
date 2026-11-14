"""Phishing URL Checker with a local SQLite database.

The database (phishing.db) has two tables:
  flagged_domains(domain, reason, source, date_added)
  url_checks(url, verdict, reasons, checked_at)

flagged_domains is seeded ONLY with clearly-labelled EXAMPLE/test
entries — made-up lookalike domains that demonstrate the patterns
phishers use. It is NOT a live threat feed and contains NO real
phishing URLs. Every URL you check is logged in url_checks.

Verdicts: SAFE / SUSPICIOUS / FLAGGED.
"""

import argparse
import ipaddress
import re
import sqlite3
import sys
from datetime import date
from urllib.parse import urlparse

DEFAULT_DB = "phishing.db"

# EXAMPLE entries only — these are invented lookalikes used to teach the
# patterns. They are not real phishing sites.
EXAMPLE_FLAGGED_DOMAINS = [
    ("paypa1-secure-login.example", "Typosquat of a payment brand (digit 1 instead of l)", "example", "2026-11-15"),
    ("amaz0n-verify.example", "Typosquat of a shopping brand (digit 0 instead of o)", "example", "2026-11-15"),
    ("g00gle-account-check.example", "Typosquat of a search brand (digits 00 instead of oo)", "example", "2026-11-15"),
    ("bank-login-free-host.example", "Bank login page on a free-hosting-style domain", "example", "2026-11-15"),
    ("secure-verify-account.example", "Suspicious keyword combination: secure + verify + account", "example", "2026-11-15"),
    ("login-secure-update.example", "Suspicious keyword combination: login + secure + update", "example", "2026-11-15"),
    ("192.168.99.99", "IP address used as the host instead of a domain name", "example", "2026-11-15"),
    ("faceb00k-login.example", "Typosquat of a social brand (digits 00 instead of oo)", "example", "2026-11-15"),
    ("micros0ft-support.example", "Typosquat of a software brand (digit 0 instead of o)", "example", "2026-11-15"),
    ("apple-id-verify-free.example", "Brand name plus verify on a lookalike domain", "example", "2026-11-15"),
]

SUSPICIOUS_KEYWORDS = [
    "verify-account", "login-secure", "secure-login", "account-verify",
    "update-payment", "confirm-identity", "urgent-action", "suspended-account",
]

BRANDS = ["paypal", "amazon", "google", "facebook", "microsoft", "apple",
          "netflix", "instagram", "whatsapp", "binance", "jazzcash", "easypaisa"]


def get_connection(db_path=DEFAULT_DB):
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(db_path=DEFAULT_DB):
    """(Re)build the database: create tables and seed example domains."""
    conn = get_connection(db_path)
    cur = conn.cursor()
    cur.execute("DROP TABLE IF EXISTS flagged_domains")
    cur.execute("DROP TABLE IF EXISTS url_checks")
    cur.execute("""CREATE TABLE flagged_domains (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT UNIQUE NOT NULL,
        reason TEXT NOT NULL,
        source TEXT NOT NULL,
        date_added TEXT NOT NULL
    )""")
    cur.execute("""CREATE TABLE url_checks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT NOT NULL,
        verdict TEXT NOT NULL,
        reasons TEXT NOT NULL,
        checked_at TEXT NOT NULL
    )""")
    cur.executemany(
        "INSERT INTO flagged_domains (domain, reason, source, date_added) "
        "VALUES (?, ?, ?, ?)", EXAMPLE_FLAGGED_DOMAINS)
    conn.commit()
    count = cur.execute("SELECT COUNT(*) FROM flagged_domains").fetchone()[0]
    conn.close()
    return count


def add_domain(domain, reason, db_path=DEFAULT_DB, source="user"):
    """Add one domain to the flagged_domains blocklist."""
    domain = domain.strip().lower()
    if not domain:
        raise ValueError("Domain must not be empty.")
    conn = get_connection(db_path)
    cur = conn.cursor()
    cur.execute("""INSERT OR REPLACE INTO flagged_domains
                   (domain, reason, source, date_added)
                   VALUES (?, ?, ?, ?)""",
                (domain, reason, source, date.today().isoformat()))
    conn.commit()
    conn.close()
    return domain


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _has_punycode(host: str) -> bool:
    return "xn--" in host.lower()


def check_url(url: str, db_path=DEFAULT_DB) -> dict:
    """Check a URL. Returns {'url', 'verdict', 'reasons'} and logs it."""
    reasons = []
    parsed = urlparse(url if "://" in url else "http://" + url)
    host = (parsed.hostname or "").lower()
    flagged = False

    # 1. Database lookup: exact domain or any parent domain flagged.
    conn = get_connection(db_path)
    cur = conn.cursor()
    try:
        rows = cur.execute("SELECT domain, reason FROM flagged_domains").fetchall()
    except sqlite3.OperationalError:
        rows = []
    for domain, reason in rows:
        if host == domain or host.endswith("." + domain):
            flagged = True
            reasons.append(f"Domain is in the flagged list: {domain} ({reason})")

    # 2. Heuristic rules.
    if not host:
        reasons.append("Could not read a host/domain from the URL")
    if _is_ip(host):
        reasons.append("Host is an IP address, not a domain name")
    if _has_punycode(host):
        reasons.append("Punycode (xn--) in domain — possible lookalike letters")
    if "@" in url:
        reasons.append("'@' in URL — can hide the real destination")
    if host.count(".") >= 3:
        reasons.append(f"Too many subdomains ({host.count('.')} dots in host)")
    if len(url) > 100:
        reasons.append(f"Very long URL ({len(url)} characters)")
    if parsed.scheme == "http" and any(
            kw in url.lower() for kw in ("login", "verify", "account", "password", "bank")):
        reasons.append("Login/verify page served over plain http, not https")
    low = url.lower()
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in low:
            reasons.append(f"Suspicious keyword in URL: '{kw}'")
    for brand in BRANDS:
        if brand in host:
            # Legitimate: the brand itself, e.g. paypal.com, www.amazon.co.uk
            legit = host == brand or any(
                host == f"{brand}.{tld}" or host.endswith(f".{brand}.{tld}")
                for tld in ("com", "co.uk", "org", "net", "pk", "com.pk"))
            if not legit:
                reasons.append(f"Brand name '{brand}' inside a lookalike domain")
                break

    if flagged:
        verdict = "FLAGGED"
    elif reasons:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"
        reasons.append("No problems found: not in flagged list, no suspicious patterns")

    # 3. Log every check.
    try:
        cur.execute("INSERT INTO url_checks (url, verdict, reasons, checked_at) "
                    "VALUES (?, ?, ?, date('now'))",
                    (url, verdict, "; ".join(reasons)))
        conn.commit()
    except sqlite3.OperationalError:
        pass  # DB missing (e.g. --init-db not run): verdict still returned
    conn.close()
    return {"url": url, "verdict": verdict, "reasons": reasons}


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Check a URL for phishing signs (local DB + heuristics).")
    parser.add_argument("--init-db", action="store_true",
                        help="Build (or rebuild) phishing.db with example entries")
    parser.add_argument("--add-domain", default=None, metavar="DOMAIN",
                        help="Add a domain to the flagged list")
    parser.add_argument("--reason", default="Added by user",
                        help="Reason for --add-domain")
    parser.add_argument("--db", default=DEFAULT_DB, help="Database file")
    parser.add_argument("url", nargs="?", help="URL to check")
    args = parser.parse_args(argv)

    if args.init_db:
        count = init_db(args.db)
        print(f"Database built: {args.db}")
        print(f"flagged_domains: {count} example entries")
        print("url_checks: empty, ready to log checks")
        return 0

    if args.add_domain:
        domain = add_domain(args.add_domain, args.reason, args.db)
        print(f"Added to flagged list: {domain}")
        return 0

    if not args.url:
        parser.print_help()
        return 2

    result = check_url(args.url, args.db)
    print(f"URL     : {result['url']}")
    print(f"Verdict : {result['verdict']}")
    print("Reasons:")
    for reason in result["reasons"]:
        print(f"  - {reason}")
    print(f"(Check saved to {args.db} -> url_checks)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
