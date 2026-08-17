"""Parallel multi-host orchestration (cross-platform port of scan-list.ps1).

Each host is scanned into its own deterministic directory; the batch passes the
exact directory map to the aggregator, so results are always the ones produced
by *this* run (no "latest directory" guessing). Per-host work runs in a thread
pool; every tool call inside the engine is time-bounded, so a slow host cannot
hang the batch.
"""
from __future__ import annotations

import os
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from . import aggregate, engine, tools

_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-]*(:\d{1,5})?$")


def _safe(name):
    return re.sub(r"[^\w.\-]", "_", name)


def read_hosts(list_file):
    """Read + validate hosts. Returns (valid_hosts, skipped_lines)."""
    valid, skipped, seen = [], [], set()
    for ln in open(list_file, encoding="utf-8-sig", errors="replace"):
        h = ln.strip().lstrip("﻿").strip()
        if not h or h.startswith("#"):
            continue
        if h in seen:
            continue
        seen.add(h)
        if _HOST_RE.match(h):
            valid.append(h)
        else:
            skipped.append(h)
    return valid, skipped


def scan_list(list_file, opts, concurrency=4, echo=print):
    hosts, skipped = read_hosts(list_file)
    if skipped:
        echo("  ! skipped invalid line(s): " + ", ".join(skipped))
    if not hosts:
        echo("No valid hosts (list empty or all invalid).")
        return None

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    output = os.path.join(tools.ROOT, "output")
    batch_dir = os.path.join(output, "_batch", stamp)
    os.makedirs(batch_dir, exist_ok=True)
    host_dirs = {h: os.path.join(output, _safe(h), stamp) for h in hosts}

    with open(os.path.join(batch_dir, "_manifest.tsv"), "w", encoding="utf-8") as f:
        for h in hosts:
            f.write(f"{h}\t{host_dirs[h]}\n")

    echo("===== BATCH SCAN =====")
    echo(f"hosts: {len(hosts)} | concurrency: {concurrency} | "
         f"flags: {' '.join(k for k in ('ports', 'nuclei', 'subs') if opts.get(k)) or '(passive)'}")
    echo(f"batch dir: {batch_dir}\n")

    def work(h):
        buf = []
        try:
            engine.scan_host(h, host_dirs[h], opts, echo=buf.append)
            status = "ok"
        except Exception as e:  # never let one host kill the batch
            buf.append(f"ERROR: {e}")
            status = f"error: {e}"
        with open(os.path.join(batch_dir, _safe(h) + ".log"), "w", encoding="utf-8") as lf:
            lf.write("\n".join(buf))
        return h, status

    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as ex:
        for h, status in ex.map(work, hosts):
            echo(f"  [done] {h} -> {status}")

    echo("\n[*] aggregating")
    counts = aggregate.aggregate(hosts, host_dirs, batch_dir)
    echo("===== DONE =====")
    echo(f"CSV : {os.path.join(batch_dir, 'summary.csv')}")
    echo(f"MD  : {os.path.join(batch_dir, 'report.md')}  (merged full reports)")
    echo(f"detail: nuclei.csv={counts['nuclei']} subdomains.csv={counts['subdomains']} ports.csv={counts['ports']}")
    sm = os.path.join(batch_dir, "summary.md")
    if os.path.isfile(sm):
        echo("\n--- summary ---\n" + open(sm, encoding="utf-8").read())
    return batch_dir
