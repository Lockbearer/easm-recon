"""Rough network-footprint estimate for --dry-run.

Sends NOTHING. It reads the chosen parameters (stages, profile, port count,
whether nuclei is focused) and prints an order-of-magnitude guess of how much
traffic a run would generate, so you can gauge noise before committing.
The numbers are approximate by design — real counts depend on how the target
responds (redirects, filtering, open-port count).
"""
from __future__ import annotations

import re

from . import config


def _targets(target):
    t = [target]
    if not re.match(r"^(www\.|https?://)", target) and not re.search(r"[:/]", target):
        t.append("www." + target)
    return t


def _port_count(nmap_flags):
    if "-p-" in nmap_flags:
        return 65535
    if "--top-ports" in nmap_flags:
        try:
            return int(nmap_flags[nmap_flags.index("--top-ports") + 1])
        except (ValueError, IndexError):
            return 1000
    if "-p" in nmap_flags:
        try:
            spec = nmap_flags[nmap_flags.index("-p") + 1]
            n = 0
            for part in spec.split(","):
                if "-" in part:
                    a, b = part.split("-")[:2]
                    n += max(1, int(b) - int(a) + 1)
                else:
                    n += 1
            return n
        except Exception:
            return 1000
    return 1000


def estimate_host(target, opts):
    """Return a list of (stage, activeness, count, unit, note) rows."""
    profile = opts.get("profile", "default")
    targs = opts.get("tool_args") or {}
    n = len(_targets(target))
    rows = [
        ("dnsx",     "passive",      n * 5,  "query",     "DNS to a resolver, not the target"),
        ("cdncheck", "passive",      n * 1,  "query",     "IP-range lookup, never touches the target"),
        ("httpx",    "light-active", n * 3,  "request",   "a few HTTP requests (http + https + redirect)"),
        ("wafw00f",  "active-low",   n * 12, "request",   "small battery of attack-pattern probes (low volume)"),
        ("tlsx",     "light-active", n * 1,  "handshake", "TLS connection"),
    ]
    if opts.get("ports"):
        pc = _port_count(config.flags_for("nmap", profile, targs.get("nmap")))
        rows.append(("nmap", "ACTIVE", int(pc * 1.3), "packet",
                     f"{pc} ports SYN + version ({'-p- is very noisy' if pc > 60000 else 'top-%d' % pc})"))
    if opts.get("nuclei"):
        nf = config.flags_for("nuclei", profile, targs.get("nuclei"))
        focused = "-tags" in nf or "-id" in nf
        rows.append(("nuclei", "ACTIVE", 3000 if focused else 15000, "request",
                     "template HTTP probes" + (" (focused via -tags)" if focused else " (full set)")))
    if opts.get("subs"):
        rows.append(("subfinder", "passive-ext", 0, "request", "external sources; no request to the target"))
    return rows


def render(target, opts, n_hosts=1, echo=print):
    rows = estimate_host(target, opts)
    scope = f"list: {n_hosts} hosts" if n_hosts > 1 else "single host"
    echo("")
    echo(f"=== DRY-RUN - estimated network footprint ({scope}) ===")
    echo(f"  {'STAGE':10s} {'CLASS':13s} {'~COUNT':>8s} {'UNIT':10s} NOTE")
    for stage, klass, cnt, unit, note in rows:
        echo(f"  {stage:10s} {klass:13s} {cnt:>8,d} {unit:10s} {note}")
    req = sum(c for _, _, c, u, _ in rows if u == "request")
    pkt = sum(c for _, _, c, u, _ in rows if u == "packet")
    echo("  " + "-" * 64)
    echo(f"  per host  -> ~{req:,} HTTP requests" + (f" + ~{pkt:,} nmap packets" if pkt else "")
         + " to the target")
    if n_hosts > 1:
        echo(f"  {n_hosts} hosts -> ~{req * n_hosts:,} requests"
             + (f" + ~{pkt * n_hosts:,} packets" if pkt else "") + " total (run in parallel)")
    noisy = any(k == "ACTIVE" for _, k, _, _, _ in rows)
    echo("  NOTE: order-of-magnitude estimate; nuclei/nmap especially vary with the target.")
    echo("  Passive = dnsx, cdncheck. Active but low-volume = httpx, tlsx, wafw00f (they touch")
    echo("  the target but send little)." + ("  The noisy stages are --ports (esp. -p-) and --nuclei." if noisy else ""))
    echo("")
