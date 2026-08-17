"""WAF/CDN detection.

Primary: wafw00f, invoked as a Python module through the isolated venv
(`python -c "from wafw00f.main import main; main()"`). This is portable and
avoids relying on a console-script launcher on PATH.

Fallback: a small passive-signature + behavioural probe when wafw00f is not
installed.
"""
from __future__ import annotations

import os
import re
import socket
import ssl
import urllib.request

from . import tools

_UA = "Mozilla/5.0 (compatible; easm-recon)"
_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE


def available(py):
    rc, _, _, _ = tools.run([py, "-c", "import wafw00f"], timeout=30)
    return rc == 0


def scan(py, host, out_json):
    """Run wafw00f for one host, trying https then http (for http-only hosts).

    Writes a wafw00f JSON array to out_json. Returns True if a non-empty
    result was produced.
    """
    for scheme in ("https", "http"):
        cmd = [py, "-c", "from wafw00f.main import main; main()",
               f"{scheme}://{host}", "-a", "-f", "json", "-o", out_json]
        tools.run(cmd, timeout=120)
        raw = ""
        if os.path.isfile(out_json):
            try:
                raw = open(out_json, encoding="utf-8-sig").read().strip()
            except OSError:
                raw = ""
        if raw and raw != "[]":
            return True
    return os.path.isfile(out_json)


# --------------------------------------------------------------------------- #
# Behavioural fallback (used only when wafw00f is unavailable).
# --------------------------------------------------------------------------- #
_BLOCK_CODES = {403, 406, 419, 429, 451, 501, 503, 999}
_PROBES = [
    ("XSS", "/?q=%3Cscript%3Ealert(1)%3C/script%3E", None),
    ("SQLi", "/?id=1%27%20OR%20%271%27%3D%271", None),
    ("Traversal", "/?f=../../../../etc/passwd", None),
    ("BadUA", "/", {"User-Agent": "sqlmap/1.6"}),
]


def _fetch(url, extra=None):
    headers = {"User-Agent": _UA}
    if extra:
        headers.update(extra)
    try:
        req = urllib.request.Request(url, headers=headers)
        r = urllib.request.urlopen(req, timeout=12, context=_CTX)
        return r.getcode(), r.read(30000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception:
        return 0, ""


def behavioural(host):
    """Return a human-readable verdict string for the WAF fallback path."""
    base_code, body = _fetch(f"https://{host}/")
    if base_code == 0:
        base_code, body = _fetch(f"http://{host}/")
    scheme = "https" if base_code else "http"
    signatures = _passive(body)
    n_block = n_reset = 0
    for _name, path, extra in _PROBES:
        code, b = _fetch(f"{scheme}://{host}".rstrip("/") + path, extra)
        is_block = (code in _BLOCK_CODES and code != base_code) or any(
            s in b.lower() for s in ("request blocked", "access denied", "request rejected")
        )
        if is_block:
            n_block += 1
        elif code == 0:
            n_reset += 1
    base_ok = base_code in (200, 301, 302, 303, 307, 308)
    if signatures:
        return f"WAF present (passive signature: {', '.join(signatures)})"
    if n_block >= 1:
        return f"WAF present (behavioural: {n_block}/{len(_PROBES)} attack probes blocked)"
    if n_reset >= 2 and base_ok:
        return "Possible WAF/IPS (low confidence: attack probes reset; could be rate-limit)"
    if not base_ok:
        return "Inconclusive (host not reachable over HTTP/HTTPS)"
    return "No WAF detected for this host (absence is not proof; silent/monitor-mode WAFs evade)"


def _passive(body):
    b = (body or "").lower()
    hits = []
    for name, cond in [
        ("Cloudflare", "cloudflare" in b or "cf-ray" in b),
        ("Imperva Incapsula", "incapsula" in b),
        ("F5 BIG-IP", "the requested url was rejected" in b),
        ("ModSecurity", "mod_security" in b or "modsecurity" in b),
    ]:
        if cond:
            hits.append(name)
    return hits
