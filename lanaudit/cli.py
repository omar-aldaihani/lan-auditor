"""Command line: lanaudit [--target RANGE] [--html report.html] [--json out.json] ..."""

import argparse
import json
import sys
import webbrowser
from pathlib import Path

from lanaudit import __version__, analysis, report, scanner


def parse_ports(text):
    ports = set()
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            low, high = (int(x) for x in part.split("-", 1))
            if not (1 <= low <= high <= 65535) or high - low > 2048:
                raise argparse.ArgumentTypeError("bad port range %r" % part)
            ports.update(range(low, high + 1))
        else:
            port = int(part)
            if not 1 <= port <= 65535:
                raise argparse.ArgumentTypeError("bad port %r" % part)
            ports.add(port)
    if not ports:
        raise argparse.ArgumentTypeError("no ports given")
    return sorted(ports)


def build_parser():
    p = argparse.ArgumentParser(
        prog="lanaudit",
        description="Find every device on your local network and flag security risks.",
        epilog="Only scan networks you own or have permission to test.")
    p.add_argument("--version", action="version", version="LAN Auditor " + __version__)
    p.add_argument("-t", "--target", help="what to scan: 192.168.1.0/24, 192.168.1.10 or "
                                         "192.168.1.10-50 (default: this computer's /24)")
    p.add_argument("-p", "--ports", type=parse_ports, help="ports to check, e.g. 22,80,443 or 1-1024 "
                                                           "(default: 27 common ports)")
    p.add_argument("--timeout", type=float, default=0.5, help="seconds to wait per connection (default 0.5)")
    p.add_argument("--no-ping", action="store_true", help="find hosts with TCP only, no ICMP ping")
    p.add_argument("--oui", metavar="FILE", help="IEEE oui.txt file to show device makers from MAC addresses")
    p.add_argument("--html", metavar="FILE", help="write an HTML report")
    p.add_argument("--json", metavar="FILE", help="write the full results as JSON")
    p.add_argument("--from-json", metavar="FILE", help="re-build reports from a saved JSON scan (no scanning)")
    p.add_argument("--open", action="store_true", help="open the HTML report in the browser when done")
    p.add_argument("--allow-public", action="store_true", help=argparse.SUPPRESS)
    p.add_argument("-q", "--quiet", action="store_true", help="no progress output")
    return p


def _progress(stage, done, total):
    if stage == "conflicts":
        sys.stderr.write("\rChecking for IP address conflicts ...   \n")
        sys.stderr.flush()
        return
    step = max(1, total // 20)
    if done != total and done % step:
        return  # update about 20 times per stage, not for every address
    label = "Finding devices" if stage == "discover" else "Checking ports"
    sys.stderr.write("\r%s: %d/%d   " % (label, done, total))
    if done == total:
        sys.stderr.write("\n")
    sys.stderr.flush()


def main(argv=None):
    args = build_parser().parse_args(argv)

    try:
        if args.from_json:
            raw = json.loads(Path(args.from_json).read_text(encoding="utf-8"))
            raw.pop("summary", None)
        else:
            if not args.quiet:
                print("Scanning %s ... (only scan networks you own or manage)"
                      % (args.target or "this computer's network"), file=sys.stderr)
            raw = scanner.scan(args.target, ports=args.ports, timeout=args.timeout,
                               use_ping=not args.no_ping, allow_public=args.allow_public,
                               oui_path=args.oui, progress=None if args.quiet else _progress)
    except (ValueError, OSError) as exc:
        print("Error: %s" % exc, file=sys.stderr)
        return 2

    result = analysis.analyse(raw)
    print(report.to_text(result))

    if args.json:
        Path(args.json).write_text(report.to_json(result), encoding="utf-8")
        print("\nJSON saved to %s" % args.json)
    if args.html:
        path = Path(args.html)
        path.write_text(report.to_html(result), encoding="utf-8")
        print("HTML report saved to %s" % path)
        if args.open:
            webbrowser.open(path.resolve().as_uri())

    return 1 if result["summary"]["findings"]["high"] else 0


if __name__ == "__main__":
    sys.exit(main())
