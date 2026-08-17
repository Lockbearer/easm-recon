#!/usr/bin/env python3
"""Cross-platform installer for easm-recon.

Downloads the ProjectDiscovery tools (right binary for your OS/arch) from their
official GitHub releases, verifies SHA-256, and drops them in ./bin. Creates an
isolated venv and installs wafw00f into it.

  python install.py            # core tool set
  python install.py --templates  # also download nuclei templates

nmap is NOT installed automatically (platform package managers differ):
  Windows:  winget install Insecure.Nmap
  Debian/Ubuntu: sudo apt install nmap
  macOS:    brew install nmap
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import ssl
import stat
import subprocess
import sys
import urllib.request
import zipfile

ROOT = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(ROOT, "bin")
PD_TOOLS = ["httpx", "dnsx", "subfinder", "naabu", "cdncheck", "tlsx", "nuclei"]

IS_WIN = os.name == "nt"
EXE = ".exe" if IS_WIN else ""


def platform_tag():
    m = platform.machine().lower()
    arch = "arm64" if m in ("arm64", "aarch64") else "amd64"
    sysname = platform.system().lower()
    if sysname == "windows":
        return f"windows_{arch}"
    if sysname == "darwin":
        return f"macOS_{arch}"
    return f"linux_{arch}"


def _get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "easm-recon-installer"})
    return urllib.request.urlopen(req, timeout=60, context=ssl.create_default_context())


def _download(url, dest):
    with _get(url) as r, open(dest, "wb") as fh:
        shutil.copyfileobj(r, fh)


def install_pd_tool(name, tag):
    print(f"\n=== {name} ===")
    try:
        rel = json.load(_get(f"https://api.github.com/repos/projectdiscovery/{name}/releases/latest"))
    except Exception as e:
        print(f"  release lookup failed: {e}")
        return
    assets = rel.get("assets", [])
    zip_asset = next((a for a in assets if a["name"].endswith(f"{tag}.zip")), None)
    sum_asset = next((a for a in assets if a["name"].endswith("checksums.txt")), None)
    if not zip_asset:
        print(f"  no asset for {tag}, skipped")
        return
    tmpzip = os.path.join(BIN, zip_asset["name"])
    print(f"  downloading {zip_asset['name']} ({zip_asset['size'] // (1024*1024)} MB)")
    _download(zip_asset["browser_download_url"], tmpzip)

    if sum_asset:
        want = None
        for line in _get(sum_asset["browser_download_url"]).read().decode("utf-8", "replace").splitlines():
            if zip_asset["name"] in line:
                want = line.split()[0].lower()
                break
        got = hashlib.sha256(open(tmpzip, "rb").read()).hexdigest().lower()
        if want and want != got:
            print(f"  SHA256 MISMATCH — skipping ({name})")
            os.remove(tmpzip)
            return
        print("  SHA256 verified")

    with zipfile.ZipFile(tmpzip) as z:
        for member in z.namelist():
            base = os.path.basename(member)
            if base in (name, name + ".exe"):
                target = os.path.join(BIN, name + EXE)
                with z.open(member) as src, open(target, "wb") as dst:
                    shutil.copyfileobj(src, dst)
                if not IS_WIN:
                    os.chmod(target, os.stat(target).st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    os.remove(tmpzip)
    if os.path.isfile(os.path.join(BIN, name + EXE)):
        print(f"  installed -> bin/{name}{EXE}")


def install_wafw00f():
    print("\n### wafw00f (isolated venv)")
    for var in ("PYTHONHOME", "PYTHONPATH"):
        os.environ.pop(var, None)
    os.environ["PYTHONNOUSERSITE"] = "1"
    venv = os.path.join(ROOT, "venv")
    vpy = os.path.join(venv, "Scripts" if IS_WIN else "bin", "python" + EXE)
    if not os.path.isfile(vpy):
        print("  creating venv...")
        subprocess.run([sys.executable, "-m", "venv", venv])
    if not os.path.isfile(vpy):
        print("  venv creation failed"); return
    subprocess.run([vpy, "-m", "pip", "install", "--upgrade", "pip", "wafw00f"])
    rc = subprocess.run([vpy, "-c", "import wafw00f"]).returncode
    if rc == 0:
        with open(os.path.join(BIN, "python-path.txt"), "w", encoding="ascii") as f:
            f.write(vpy)
        print(f"  wafw00f installed; python pinned -> bin/python-path.txt")
    else:
        print("  wafw00f import could not be verified")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--templates", action="store_true", help="download nuclei templates")
    args = ap.parse_args()

    os.makedirs(BIN, exist_ok=True)
    tag = platform_tag()
    print(f"platform: {tag}")
    for t in PD_TOOLS:
        install_pd_tool(t, tag)
    install_wafw00f()

    if args.templates:
        nuc = os.path.join(BIN, "nuclei" + EXE)
        if os.path.isfile(nuc):
            print("\n### nuclei templates")
            subprocess.run([nuc, "-update-templates"])

    print("\n=== installed ===")
    for f in sorted(os.listdir(BIN)):
        if f.endswith(EXE) or f.endswith(".exe"):
            print(f"  bin/{f}")
    print("\nUsage:  python -m easm <host | list.txt> [--full --ports --nuclei --subs]")
    print("Tip: add a shim (see README) so you can run `easm <host>` from anywhere.")
    print("nmap (optional): winget install Insecure.Nmap  |  apt install nmap  |  brew install nmap")


if __name__ == "__main__":
    main()
