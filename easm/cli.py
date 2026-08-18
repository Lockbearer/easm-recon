"""Command-line interface.

  easm <host>            single-host scan (light by default; see note)
  easm <list.txt>        batch scan (parallel) — argument is auto-detected as a file
  easm <target> --full   add ports + nuclei + subdomains
  easm <target> --dry-run  estimate the network footprint without scanning

The no-flag run is LIGHT but not fully passive: only DNS + cdncheck avoid the
target; httpx/tlsx make real requests and WAF detection sends attack-like probes.
The target is treated as a LIST FILE if it exists on disk, otherwise as a host.
"""
from __future__ import annotations

import argparse
import os
import re
import shlex
import sys
from datetime import datetime

from . import __version__, batch, config, engine, estimate, tools

# Tools whose flags can be extended from the CLI via --<tool>-args "...".
CUSTOMIZABLE = ["dnsx", "httpx", "tlsx", "cdncheck", "nmap", "naabu", "nuclei", "subfinder"]


def build_parser():
    p = argparse.ArgumentParser(
        prog="easm",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Cross-platform domain reconnaissance wrapper "
                    "(dnsx, httpx, wafw00f, tlsx, cdncheck, nmap, nuclei, subfinder).",
        epilog="Customization:\n"
               "  --profile deep example.com --ports         # thorough preset\n"
               "  --nmap-args \"-p- -A\" example.com --ports    # extra nmap flags\n"
               "  --nuclei-args \"-tags cve\" ex.com --nuclei   # extra nuclei flags\n"
               "Pass-through args are appended to that tool's command (arg-list, "
               "so shell injection is impossible).")
    p.add_argument("target", help="a host (example.com) OR a path to a list file")
    p.add_argument("--ports", action="store_true", help="port scan (nmap/naabu/python) — ACTIVE")
    p.add_argument("--nuclei", action="store_true", help="nuclei vuln/exposure scan — ACTIVE")
    p.add_argument("--subs", action="store_true", help="subdomain discovery (subfinder)")
    p.add_argument("--full", action="store_true", help="= --ports --nuclei --subs")
    p.add_argument("--dry-run", action="store_true",
                   help="estimate network footprint (traffic/packets) and exit — sends nothing")
    p.add_argument("--concurrency", type=int, default=4, help="parallel hosts in list mode (default 4)")
    p.add_argument("--nuclei-timeout", type=int, default=900,
                   help="nuclei wall-clock cap in seconds (default 900)")
    p.add_argument("--profile", default="default", choices=config.profile_names(),
                   help="flag preset: %(choices)s (default: default)")
    for t in CUSTOMIZABLE:
        p.add_argument(f"--{t}-args", default=None, metavar="\"...\"",
                       help=f"extra flags appended to {t}")
    p.add_argument("--version", action="version", version=f"easm-recon {__version__}")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)

    tool_args = {}
    for t in CUSTOMIZABLE:
        raw = getattr(args, f"{t}_args", None)
        if raw:
            try:
                tool_args[t] = shlex.split(raw)
            except ValueError as e:
                print(f"Bad --{t}-args value {raw!r}: {e}", file=sys.stderr)
                return 2

    opts = {
        "ports": args.ports or args.full,
        "nuclei": args.nuclei or args.full,
        "subs": args.subs or args.full,
        "nuclei_timeout": args.nuclei_timeout,
        "profile": args.profile,
        "tool_args": tool_args,
    }

    if os.path.isfile(args.target):
        if args.dry_run:
            valid, _ = batch.read_hosts(args.target)
            if not valid:
                print("No valid hosts in list.", file=sys.stderr)
                return 2
            estimate.render(valid[0], opts, n_hosts=len(valid))
            return 0
        batch.scan_list(args.target, opts, concurrency=args.concurrency)
        return 0

    host = args.target
    if not engine.valid_host(host):
        print(f"Invalid target: {host!r} (not a valid host, and not an existing file).",
              file=sys.stderr)
        return 2

    if args.dry_run:
        estimate.render(host, opts, n_hosts=1)
        return 0

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    safe = re.sub(r"[^\w.\-]", "_", host)
    out_dir = os.path.join(tools.ROOT, "output", safe, stamp)
    engine.scan_host(host, out_dir, opts)
    rp = os.path.join(out_dir, "report.md")
    if os.path.isfile(rp):
        print("\n--- report.md ---\n" + open(rp, encoding="utf-8").read())
    return 0


if __name__ == "__main__":
    sys.exit(main())
