"""Tests for all three cybersecurity tools.

Run:  python -m pytest tests/test_tools.py -v
  or: python tests/test_tools.py
Uses only synthetic/local data. No network access except localhost.
"""

import hashlib
import os
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import password_checker
import phishing_checker
import port_scanner


class TestPasswordChecker(unittest.TestCase):
    def test_weak_common_password(self):
        r = password_checker.score_password("123456")
        self.assertEqual(r["label"], "Weak")
        self.assertTrue(r["is_common"])

    def test_weak_short_password(self):
        r = password_checker.score_password("abc")
        self.assertEqual(r["label"], "Weak")

    def test_strong_password(self):
        r = password_checker.score_password("MyStr0ng!Pass#2026")
        self.assertEqual(r["label"], "Strong")
        self.assertGreaterEqual(r["score"], 70)

    def test_medium_password(self):
        # 10 chars, lower + digit, no upper/symbol: 15+10+0+10+15+10 = 60
        r = password_checker.score_password("farhan2026")
        self.assertEqual(r["label"], "Medium")
        self.assertEqual(r["score"], 60)

    def test_hash_determinism(self):
        h1 = password_checker.sha256_hash("TestPass123!")
        h2 = password_checker.sha256_hash("TestPass123!")
        self.assertEqual(h1, h2)
        self.assertEqual(h1, hashlib.sha256(b"TestPass123!").hexdigest())
        self.assertEqual(len(h1), 64)

    def test_different_passwords_different_hashes(self):
        self.assertNotEqual(password_checker.sha256_hash("abc123!"),
                            password_checker.sha256_hash("abc124!"))


class TestPortScanner(unittest.TestCase):
    def test_scan_localhost_runs(self):
        results = port_scanner.scan_ports("127.0.0.1", ports=[80, 443])
        self.assertEqual(set(results), {80, 443})
        for value in results.values():
            self.assertIn(value, ("open", "closed"))

    def test_scan_default_ports(self):
        results = port_scanner.scan_ports()
        self.assertEqual(set(results), set(port_scanner.DEFAULT_PORTS))

    def test_non_localhost_refused(self):
        with self.assertRaises(ValueError):
            port_scanner.scan_ports("8.8.8.8")
        with self.assertRaises(ValueError):
            port_scanner.scan_ports("example.com")

    def test_open_port_detected(self):
        # Open a real listener on localhost, then confirm the scan sees it.
        import socket
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        try:
            results = port_scanner.scan_ports("127.0.0.1", ports=[port])
            self.assertEqual(results[port], "open")
        finally:
            srv.close()


class TestPhishingChecker(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.tmp.name, "test_phishing.db")
        self.count = phishing_checker.init_db(self.db)

    def tearDown(self):
        self.tmp.cleanup()

    def test_db_created_with_example_entries(self):
        self.assertGreaterEqual(self.count, 5)
        conn = sqlite3.connect(self.db)
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertIn("flagged_domains", tables)
        self.assertIn("url_checks", tables)
        n = conn.execute("SELECT COUNT(*) FROM flagged_domains").fetchone()[0]
        self.assertEqual(n, self.count)
        # All seeded entries are labelled as examples.
        sources = {r[0] for r in conn.execute(
            "SELECT DISTINCT source FROM flagged_domains")}
        self.assertEqual(sources, {"example"})
        conn.close()

    def test_safe_url(self):
        r = phishing_checker.check_url("https://www.google.com", self.db)
        self.assertEqual(r["verdict"], "SAFE")

    def test_flagged_example_domain(self):
        r = phishing_checker.check_url(
            "https://paypa1-secure-login.example/login", self.db)
        self.assertEqual(r["verdict"], "FLAGGED")

    def test_suspicious_ip_url(self):
        r = phishing_checker.check_url("http://192.168.99.99/login", self.db)
        self.assertIn(r["verdict"], ("SUSPICIOUS", "FLAGGED"))

    def test_suspicious_keywords(self):
        r = phishing_checker.check_url(
            "http://some-random-site.example/verify-account", self.db)
        self.assertEqual(r["verdict"], "SUSPICIOUS")

    def test_check_is_logged(self):
        phishing_checker.check_url("https://www.google.com", self.db)
        phishing_checker.check_url("http://bad.example/verify-account", self.db)
        conn = sqlite3.connect(self.db)
        n = conn.execute("SELECT COUNT(*) FROM url_checks").fetchone()[0]
        self.assertEqual(n, 2)
        rows = conn.execute(
            "SELECT url, verdict FROM url_checks ORDER BY id").fetchall()
        self.assertEqual(rows[0][1], "SAFE")
        self.assertEqual(rows[1][1], "SUSPICIOUS")
        conn.close()

    def test_add_domain_then_flagged(self):
        phishing_checker.add_domain("evil-lookalike.example",
                                    "Test entry", self.db)
        r = phishing_checker.check_url("https://evil-lookalike.example/", self.db)
        self.assertEqual(r["verdict"], "FLAGGED")


if __name__ == "__main__":
    unittest.main(verbosity=2)
