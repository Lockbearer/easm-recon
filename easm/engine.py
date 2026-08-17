"""Single-host scan pipeline (cross-platform port of scan.ps1).

Every stage is best-effort: if a tool is missing or fails, the stage is skipped
(or a fallback runs) and the scan continues. External tools are bounded by
their own timeouts plus a subprocess wall-clock cap, so nothing hangs forever.
"""
from __future__ import annotations

import json
import os
import re

from . import config, hostscan, portscan, tools, waf
from .report import build_report

_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-]*(:\d{1,5})?$")


def valid_host(h):
    return bool(_HOST_RE.match(h))


def _safe(name):
    return re.sub(r"[^\w.\-]", "_", name)


def _write(path, text):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text if text is not None else "")


def _write_jsonl(path, records):
    with open(path, "w", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")


def scan_host(target, out_dir, opts, echo=print):
    """Run the full pipeline for one host into out_dir. Returns out_dir."""
    os.makedirs(out_dir, exist_ok=True)
    py = tools.venv_python()
    profile = opts.get("profile", "default")
    targs = opts.get("tool_args") or {}

    def flags(tool):
        return config.flags_for(tool, profile, targs.get(tool))

    if profile != "default":
        echo(f"[*] profile: {profile}")

    # Targets: apex + www (www only for a plain hostname).
    targets = [target]
    if not re.match(r"^(www\.|https?://)", target) and not re.search(r"[:/]", target):
        targets.append("www." + target)
    stdin = "\n".join(targets)

    echo(f"===== easm-recon scan: {target} =====")
    echo(f"output: {out_dir}")

    # 1) DNS
    echo("[*] DNS (A/AAAA/CNAME/NS)")
    dnsx = tools.find_tool("dnsx")
    if dnsx:
        rc, out, _, _ = tools.run(
            [dnsx] + flags("dnsx") + ["-json"],
            timeout=90, input_text=stdin)
        _write(os.path.join(out_dir, "dns.jsonl"), out)
    else:
        recs = [r for r in (hostscan.resolve(h) for h in targets) if r]
        _write_jsonl(os.path.join(out_dir, "dns.jsonl"), recs)

    # 2) CDN/WAF IP-range classification
    cdncheck = tools.find_tool("cdncheck")
    if cdncheck:
        echo("[*] cdncheck (CDN/WAF/cloud IP range)")
        ips = _resolve_ips(targets)
        if ips:
            rc, out, _, _ = tools.run([cdncheck] + flags("cdncheck") + ["-jsonl"],
                                      timeout=60, input_text="\n".join(ips))
            _write(os.path.join(out_dir, "cdncheck.jsonl"), out)

    # 3) HTTP probe / fingerprint
    echo("[*] HTTP probe / tech / TLS summary (httpx)")
    httpx = tools.find_tool("httpx")
    if httpx:
        rc, out, _, _ = tools.run(
            [httpx] + flags("httpx") + ["-json"],
            timeout=120, input_text=stdin)
        _write(os.path.join(out_dir, "httpx.jsonl"), out)
    else:
        recs = [r for r in (hostscan.http_probe(h) for h in targets) if r]
        _write_jsonl(os.path.join(out_dir, "httpx.jsonl"), recs)

    # 4) WAF detection
    echo("[*] WAF detection")
    wafok = False
    if waf.available(py):
        for h in targets:
            jf = os.path.join(out_dir, f"wafw00f_{_safe(h)}.json")
            if waf.scan(py, h, jf):
                wafok = True
    if not wafok and not any(f.startswith("wafw00f_") for f in os.listdir(out_dir)):
        echo("  (wafw00f unavailable -> built-in behavioural check)")
        _write(os.path.join(out_dir, "waf_detect.txt"),
               ">>> VERDICT: " + waf.behavioural(target))

    # 5) TLS detail
    tlsx = tools.find_tool("tlsx")
    if tlsx:
        echo("[*] TLS / certificate (tlsx)")
        rc, out, _, _ = tools.run(
            [tlsx] + flags("tlsx") + ["-json"], timeout=90, input_text=stdin)
        _write(os.path.join(out_dir, "tlsx.jsonl"), out)
    else:
        recs = [r for r in (hostscan.tls_info(h) for h in targets) if r]
        if recs:
            _write_jsonl(os.path.join(out_dir, "tlsx.jsonl"), recs)

    # 6) Ports (opt-in, active)
    if opts.get("ports"):
        _ports(target, out_dir, py, echo, flags("nmap"), flags("naabu"))

    # 7) Nuclei (opt-in, active)
    if opts.get("nuclei"):
        _nuclei(target, out_dir, opts.get("nuclei_timeout", 900), echo, flags("nuclei"))

    # 8) Subdomains (opt-in)
    if opts.get("subs"):
        subfinder = tools.find_tool("subfinder")
        if subfinder:
            echo("[*] subdomain discovery (subfinder)")
            rc, out, _, _ = tools.run([subfinder, "-d", target] + flags("subfinder"), timeout=180)
            _write(os.path.join(out_dir, "subdomains.txt"), out)
            n = len([x for x in out.splitlines() if x.strip()])
            echo(f"  {n} subdomains -> subdomains.txt")
        else:
            echo("  subfinder not available - skipped")

    # 9) Report
    echo("[*] building report")
    build_report(target, out_dir)
    echo(f"===== DONE ===== report: {os.path.join(out_dir, 'report.md')}")
    return out_dir


def _resolve_ips(targets):
    import socket
    ips = set()
    for h in targets:
        try:
            for _f, _t, _p, _c, sa in socket.getaddrinfo(h, None):
                ips.add(sa[0])
        except OSError:
            pass
    return sorted(ips)


def _host_timeout_secs(nmap_flags, default=360):
    """Derive a subprocess wall-clock cap from nmap's own --host-timeout so a
    deeper scan (e.g. -p- 10m) is not killed prematurely. Returns host-timeout
    + 120s buffer, floored at `default`."""
    try:
        i = nmap_flags.index("--host-timeout")
        v = nmap_flags[i + 1]
        mult = {"s": 1, "m": 60, "h": 3600}.get(v[-1], 1)
        secs = int(v[:-1] if v[-1] in "smh" else v) * mult
        return max(default, secs + 120)
    except (ValueError, IndexError):
        return default


def _ports(target, out_dir, py, echo, nmap_flags, naabu_flags):
    echo("[*] port scan (ACTIVE - authorized targets only)")
    nmap = tools.find_tool("nmap")
    if nmap:
        echo("  nmap " + " ".join(nmap_flags))
        nmap_txt = os.path.join(out_dir, "nmap.txt")
        tools.run([nmap] + nmap_flags + [target, "-oN", nmap_txt],
                  timeout=_host_timeout_secs(nmap_flags))
        if os.path.isfile(nmap_txt):
            for ln in open(nmap_txt, encoding="utf-8", errors="replace"):
                if re.match(r"^\d+/tcp\s+open", ln):
                    echo("  " + ln.strip())
            return
    naabu = tools.find_tool("naabu")
    if naabu:
        rc, out, _, _ = tools.run([naabu, "-host", target] + naabu_flags + ["-json"],
                                  timeout=300)
        if out.strip():
            _write(os.path.join(out_dir, "naabu.jsonl"), out)
            echo("  " + out.strip().replace("\n", " "))
            return
    echo("  (nmap/naabu unavailable -> built-in TCP connect scan)")
    open_ports = portscan.scan(target)
    lines = [f"OPEN {p} {svc}" for p, svc in open_ports]
    lines.append("OPEN PORTS: " + (",".join(str(p) for p, _ in open_ports) or "(none/filtered)"))
    _write(os.path.join(out_dir, "portscan.txt"), "\n".join(lines) + "\n")
    echo("  " + (", ".join(str(p) for p, _ in open_ports) or "(none/filtered)"))


def _nuclei(target, out_dir, timeout, echo, nuclei_flags):
    echo("[*] nuclei vulnerability/exposure scan (ACTIVE)")
    nuc = tools.find_tool("nuclei")
    if not nuc:
        echo("  nuclei not available - skipped")
        return
    jsonl = os.path.join(out_dir, "nuclei.jsonl")
    log = os.path.join(out_dir, "nuclei_run.log")
    status = os.path.join(out_dir, "nuclei_status.txt")
    echo(f"  running (max {timeout}s; progress every ~15s)...")
    cmd = [nuc, "-u", f"https://{target}"] + nuclei_flags + ["-jsonl", "-o", jsonl]
    finished = tools.run_streamed(cmd, timeout, log, progress=lambda s: echo("  … " + s) if s else None)
    if finished is None:
        reason = ""
        if os.path.isfile(log):
            tail = open(log, encoding="utf-8", errors="replace").read().strip().splitlines()
            reason = tail[-1] if tail else ""
        _write(status, "ERROR: nuclei could not be launched (blocked by AV/security "
                       "policy, or unavailable). " + reason)
        echo("  ! nuclei could NOT be launched - blocked by antivirus / security policy, or unavailable.")
        echo("    -> recorded as ERROR (NOT a clean 0-findings result); see nuclei_run.log")
        return
    if finished:
        _write(status, "COMPLETE")
    else:
        _write(status, f"TRUNCATED: wall-clock timeout ({timeout}s) - partial result")
        echo(f"  ! nuclei exceeded {timeout}s, stopped (PARTIAL result).")
    n = 0
    if os.path.isfile(jsonl):
        n = len([x for x in open(jsonl, encoding="utf-8", errors="replace") if x.strip()])
    echo(f"  nuclei findings: {n}")
