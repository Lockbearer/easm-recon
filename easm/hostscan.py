"""Stdlib DNS/HTTP/TLS fallback — used when dnsx/httpx/tlsx are unavailable.

Returns dicts shaped like the ProjectDiscovery JSONL records so the report and
aggregate layers can consume them uniformly.
"""
from __future__ import annotations

import re
import socket
import ssl
import urllib.request

_UA = "Mozilla/5.0 (compatible; easm-recon)"
_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE


def resolve(host):
    """dnsx-shaped record: {host, a, aaaa}."""
    a, aaaa = [], []
    try:
        for fam, _t, _p, _c, sa in socket.getaddrinfo(host, None):
            ip = sa[0]
            if fam == socket.AF_INET and ip not in a:
                a.append(ip)
            elif fam == socket.AF_INET6 and ip not in aaaa:
                aaaa.append(ip)
    except OSError:
        pass
    if not a and not aaaa:
        return None
    return {"host": host, "a": a, "aaaa": aaaa}


def http_probe(host):
    """httpx-shaped record (minimal): {url, input, status_code, webserver, title, scheme, a}."""
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}/"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": _UA})
            r = urllib.request.urlopen(req, timeout=12, context=_CTX)
            body = r.read(40000).decode("utf-8", "replace")
            title = ""
            m = re.search(r"(?is)<title>(.*?)</title>", body)
            if m:
                title = m.group(1).strip()[:120]
            rec = {
                "url": f"{scheme}://{host}",
                "input": host,
                "host": host,
                "scheme": scheme,
                "status_code": r.getcode(),
                "webserver": r.headers.get("Server", ""),
                "title": title,
            }
            try:
                rec["a"] = list({i[4][0] for i in socket.getaddrinfo(host, 443)})[:3]
            except OSError:
                rec["a"] = []
            return rec
        except urllib.error.HTTPError as e:
            return {"url": url, "input": host, "host": host, "scheme": scheme,
                    "status_code": e.code, "webserver": e.headers.get("Server", ""), "title": ""}
        except Exception:
            continue
    return None


def tls_info(host, port=443):
    """tlsx-shaped record (minimal): {host, port, tls_version, subject_cn, issuer_org, subject_an}."""
    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            with _CTX.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
                ver = ss.version()
    except Exception:
        return None

    def field(entries, key):
        for tup in entries or ():
            for k, v in tup:
                if k == key:
                    return v
        return ""

    san = [v for (t, v) in (cert.get("subjectAltName") or ()) if t == "DNS"]
    return {
        "host": host,
        "port": str(port),
        "tls_version": (ver or "").lower().replace(".", "").replace("v", "tls") if ver else "",
        "subject_cn": field(cert.get("subject"), "commonName"),
        "issuer_org": [field(cert.get("issuer"), "organizationName")],
        "subject_an": san,
    }
