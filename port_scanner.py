"""Localhost Port Scanner — learning tool.

Scans ONLY localhost (127.0.0.1) for open ports from a small default
list. Any other host is refused with a clear error. Never use this
against anyone else's computer.
"""

import argparse
import socket
import sys

DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 8080]

# Only these targets are allowed: the user's own machine.
ALLOWED_HOSTS = {"127.0.0.1", "localhost", "::1"}


def is_allowed_host(host: str) -> bool:
    return host.strip().lower() in ALLOWED_HOSTS


def scan_ports(host: str = "127.0.0.1", ports=None, timeout: float = 0.5) -> dict:
    """Scan ports on localhost only. Returns {port: 'open'|'closed'}.

    Raises ValueError for any non-localhost host.
    """
    if not is_allowed_host(host):
        raise ValueError(
            f"Refused: '{host}' is not localhost. This scanner only scans "
            "your own computer (127.0.0.1 / localhost). Scanning other "
            "people's systems is not allowed."
        )
    ports = list(ports) if ports else list(DEFAULT_PORTS)
    results = {}
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect(("127.0.0.1", port))
            results[port] = "open"
        except (socket.timeout, ConnectionRefusedError, OSError):
            results[port] = "closed"
        finally:
            sock.close()
    return results


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Scan open ports on YOUR OWN computer (localhost only).")
    parser.add_argument("--host", default="127.0.0.1",
                        help="Target host — only 127.0.0.1/localhost allowed")
    parser.add_argument("--ports", default=None,
                        help="Comma-separated ports, e.g. 80,443,8080 "
                             "(default: 21,22,23,25,53,80,110,143,443,3306,8080)")
    args = parser.parse_args(argv)

    ports = None
    if args.ports:
        try:
            ports = [int(p.strip()) for p in args.ports.split(",") if p.strip()]
        except ValueError:
            print("Error: --ports must be numbers separated by commas.", file=sys.stderr)
            return 2
        bad = [p for p in ports if not 1 <= p <= 65535]
        if bad:
            print(f"Error: invalid port numbers: {bad}", file=sys.stderr)
            return 2

    try:
        results = scan_ports(args.host, ports)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    open_ports = [p for p, s in results.items() if s == "open"]
    print(f"Target: {args.host} (localhost — your own computer)")
    for port in sorted(results):
        print(f"  Port {port:<6} {results[port]}")
    print(f"Open ports: {open_ports if open_ports else 'none'}")
    print(f"Closed ports: {len(results) - len(open_ports)} of {len(results)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
