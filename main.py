"""Main menu for the Cybersecurity Tools project.

Routes to the three tools, or just run each tool directly:
  python password_checker.py 'YourPass123!'
  python port_scanner.py
  python phishing_checker.py --init-db
  python phishing_checker.py https://www.google.com
"""

import argparse
import sys

import password_checker
import phishing_checker
import port_scanner


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Cybersecurity Tools — learning tools for your own "
                    "computer and URLs only.")
    sub = parser.add_subparsers(dest="tool")

    p = sub.add_parser("password", help="Password strength + SHA-256 demo")
    p.add_argument("password", help="Password to check (not stored)")

    s = sub.add_parser("scan", help="Scan open ports on localhost only")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--ports", default=None)

    c = sub.add_parser("phishing", help="Check a URL for phishing signs")
    c.add_argument("url", nargs="?", help="URL to check")
    c.add_argument("--init-db", action="store_true")
    c.add_argument("--add-domain", default=None)
    c.add_argument("--reason", default="Added by user")
    c.add_argument("--db", default=phishing_checker.DEFAULT_DB)

    args = parser.parse_args(argv)
    if args.tool == "password":
        return password_checker.main([args.password])
    if args.tool == "scan":
        argv2 = ["--host", args.host]
        if args.ports:
            argv2 += ["--ports", args.ports]
        return port_scanner.main(argv2)
    if args.tool == "phishing":
        argv3 = []
        if args.init_db:
            argv3.append("--init-db")
        if args.add_domain:
            argv3 += ["--add-domain", args.add_domain, "--reason", args.reason]
        argv3 += ["--db", args.db]
        if args.url:
            argv3.append(args.url)
        return phishing_checker.main(argv3)

    parser.print_help()
    print("\nExamples:")
    print("  python main.py password 'MyStr0ng!Pass'")
    print("  python main.py scan")
    print("  python main.py phishing --init-db")
    print("  python main.py phishing https://www.google.com")
    return 0


if __name__ == "__main__":
    sys.exit(main())
