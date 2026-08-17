"""Combine per-host scan outputs into batch-level CSVs + a merged report.

`host_dirs` maps each host to the EXACT output directory produced by this batch
run, so aggregation is deterministic — it never guesses a "latest" directory.
"""
from __future__ import annotations

import csv
import glob
import json
import os
import re


def _loadl(path):
    rows = []
    if os.path.isfile(path):
        for ln in open(path, encoding="utf-8-sig", errors="replace"):
            ln = ln.strip().lstrip("﻿")
            if ln:
                try:
                    rows.append(json.loads(ln))
                except ValueError:
                    pass
    return rows


def _read(path):
    return open(path, encoding="utf-8-sig", errors="replace").read() if os.path.isfile(path) else ""


def aggregate(hosts, host_dirs, batch_dir):
    summary, nuclei_rows, sub_rows, port_rows = [], [], [], []

    for h in hosts:
        s = {"host": h, "ip": "", "status": "", "server": "", "cdn_waf": "", "waf": "",
             "tls": "", "ports": "", "vuln_count": 0, "vuln_sev": "", "sub_count": 0, "title": ""}
        nd = host_dirs.get(h)
        if nd and os.path.isdir(nd):
            _fill_http(s, h, nd)
            _fill_waf(s, nd)
            _fill_tls(s, nd)
            _fill_ports(s, h, nd, port_rows)
            _fill_nuclei(s, h, nd, nuclei_rows)
            _fill_subs(s, h, nd, sub_rows)
        summary.append(s)

    _write_csv(os.path.join(batch_dir, "summary.csv"),
               ["host", "ip", "status", "server", "cdn_waf", "waf", "tls", "ports",
                "vuln_count", "vuln_sev", "sub_count", "title"], summary)
    _write_csv(os.path.join(batch_dir, "nuclei.csv"),
               ["host", "severity", "name", "template", "matched_at"], nuclei_rows)
    _write_csv(os.path.join(batch_dir, "subdomains.csv"), ["host", "subdomain"], sub_rows)
    _write_csv(os.path.join(batch_dir, "ports.csv"), ["host", "port", "service", "version"], port_rows)

    _write_md(batch_dir, summary, nuclei_rows, sub_rows, port_rows, host_dirs, hosts)
    return {"nuclei": len(nuclei_rows), "subdomains": len(sub_rows), "ports": len(port_rows)}


def _fill_http(s, h, nd):
    for j in _loadl(os.path.join(nd, "httpx.jsonl")):
        inp = (j.get("input", "") or "").lstrip("﻿")
        match = inp == h or j.get("host", "") == h or ("//" + h) in (j.get("url", "") or "")
        if match or not s["status"]:
            s["status"] = j.get("status_code", "")
            s["server"] = j.get("webserver", "")
            s["title"] = (j.get("title", "") or "")[:50]
            s["cdn_waf"] = j.get("cdn_name", "")
            s["ip"] = ",".join((j.get("a") or [])[:3])
            if match:
                break


def _fill_waf(s, nd):
    for wf in sorted(glob.glob(os.path.join(nd, "wafw00f_*.json"))):
        try:
            data = json.load(open(wf, encoding="utf-8-sig", errors="replace"))
        except ValueError:
            continue
        det = [d for d in data if d.get("detected")]
        if det:
            s["waf"] = det[0].get("firewall", "")
            return
        if data and not s["waf"]:
            s["waf"] = "none"


def _fill_tls(s, nd):
    for j in _loadl(os.path.join(nd, "tlsx.jsonl")):
        if j.get("tls_version"):
            s["tls"] = j["tls_version"]
            return


def _fill_ports(s, h, nd, port_rows):
    plist = []
    nm = _read(os.path.join(nd, "nmap.txt"))
    if nm:
        for m in re.finditer(r"^(\d+)/tcp[ \t]+open[ \t]+(\S+)[ \t]*(.*)$", nm, re.M):
            port, svc, ver = m.group(1), m.group(2), m.group(3).strip()
            if "unrecognized despite" in ver or ver.startswith("SF:"):
                ver = ""
            plist.append(port)
            port_rows.append({"host": h, "port": port, "service": svc, "version": ver[:60]})
    if not plist:
        m = re.search(r"OPEN PORTS:\s*(.*)", _read(os.path.join(nd, "portscan.txt")))
        if m and m.group(1).strip() and "none" not in m.group(1).lower():
            for port in [p.strip() for p in m.group(1).split(",") if p.strip()]:
                plist.append(port)
                port_rows.append({"host": h, "port": port, "service": "", "version": ""})
    if not plist:
        for j in _loadl(os.path.join(nd, "naabu.jsonl")):
            if j.get("port"):
                port = str(j["port"])
                plist.append(port)
                port_rows.append({"host": h, "port": port, "service": "", "version": ""})
    s["ports"] = ",".join(plist)


def _fill_nuclei(s, h, nd, nuclei_rows):
    nu = _loadl(os.path.join(nd, "nuclei.jsonl"))
    sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for r in nu:
        info = r.get("info", {}) or {}
        se = info.get("severity", "info")
        sev[se] = sev.get(se, 0) + 1
        nuclei_rows.append({"host": h, "severity": se,
                            "name": info.get("name", r.get("template-id", "")),
                            "template": r.get("template-id", ""),
                            "matched_at": r.get("matched-at", r.get("host", ""))})
    s["vuln_count"] = len(nu)
    s["vuln_sev"] = ",".join(f"{n}{k[0].upper()}" for k, n in
                             (("critical", sev["critical"]), ("high", sev["high"]),
                              ("medium", sev["medium"]), ("low", sev["low"])) if n)
    st = _read(os.path.join(nd, "nuclei_status.txt"))
    if "TRUNCATED" in st:
        s["vuln_sev"] = (s["vuln_sev"] + "*") if s["vuln_sev"] else "*"
    elif st.startswith("ERROR"):
        # nuclei never ran (blocked/unavailable): mark so a 0 is not read as clean.
        s["vuln_sev"] = (s["vuln_sev"] + "!") if s["vuln_sev"] else "!"


def _fill_subs(s, h, nd, sub_rows):
    items = [x.strip().lstrip("﻿") for x in _read(os.path.join(nd, "subdomains.txt")).splitlines() if x.strip()]
    s["sub_count"] = len(items)
    for sd in items:
        sub_rows.append({"host": h, "subdomain": sd})


def _write_csv(path, cols, data):
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        wr = csv.DictWriter(f, fieldnames=cols)
        wr.writeheader()
        for r in data:
            wr.writerow(r)


def _vuln_cell(r):
    return f"{r['vuln_count']} ({r['vuln_sev']})" if r["vuln_sev"] else str(r["vuln_count"])


def _write_md(batch_dir, summary, nuclei_rows, sub_rows, port_rows, host_dirs, hosts):
    header = ["| Host | IP | HTTP | Server | CDN/WAF | wafw00f | TLS | Ports | Vuln | Subs |",
             "|---|---|---|---|---|---|---|---|---|---|"]
    rows = [f"| {r['host']} | {r['ip']} | {r['status']} | {r['server']} | {r['cdn_waf']} | "
            f"{r['waf']} | {r['tls']} | {r['ports']} | {_vuln_cell(r)} | {r['sub_count']} |"
            for r in summary]
    partial = any("*" in r["vuln_sev"] for r in summary)
    errored = any("!" in r["vuln_sev"] for r in summary)
    notes = []
    if partial:
        notes.append("_`*` = nuclei stopped by timeout (PARTIAL; real finding count may be higher)_")
    if errored:
        notes.append("_`!` = nuclei did NOT run (blocked/unavailable); a `0` for that host is not a clean result_")

    md = [f"# Batch scan summary ({len(summary)} hosts)", ""] + header + rows + [""]
    md.append(f"_Details: nuclei.csv ({len(nuclei_rows)}), subdomains.csv ({len(sub_rows)}), "
              f"ports.csv ({len(port_rows)}) · full reports: report.md_")
    md += notes
    open(os.path.join(batch_dir, "summary.md"), "w", encoding="utf-8").write("\n".join(md))

    rep = [f"# Batch scan report ({len(summary)} hosts)", "", "## Summary"] + header + rows
    if notes:
        rep += [""] + notes
    rep += ["", "## Per-host detail", ""]
    for h in hosts:
        nd = host_dirs.get(h)
        rep.append("<hr>")
        rep.append("")
        rp = os.path.join(nd, "report.md") if nd else None
        rep.append(_read(rp).rstrip() if (rp and os.path.isfile(rp)) else f"# {h}\n- (report not found)")
        rep.append("")
    open(os.path.join(batch_dir, "report.md"), "w", encoding="utf-8").write("\n".join(rep))
