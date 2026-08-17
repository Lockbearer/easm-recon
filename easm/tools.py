"""Cross-platform tool discovery and safe subprocess execution.

Design notes:
  * Tools are invoked with an ARGUMENT LIST (never a shell string), so command
    injection is structurally impossible and hostnames are always literal.
  * External tools (nmap/nuclei/...) are direct children of our process, so a
    timeout simply kills that child — there is no orphaned-grandchild problem.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time

IS_WINDOWS = os.name == "nt"
EXE = ".exe" if IS_WINDOWS else ""

# Package/repo root and the local bin/ where install.py drops binaries.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.join(ROOT, "bin")


def find_tool(name):
    """Return an absolute path to `name`, preferring the toolkit-local bin/.

    Falls back to PATH (shutil.which), so system-installed tools (e.g. nmap
    from a package manager) are found automatically.
    """
    local = os.path.join(BIN, name + EXE)
    if os.path.isfile(local):
        return local
    return shutil.which(name)


def venv_python():
    """Path to the toolkit's isolated venv python (where wafw00f lives).

    Falls back to a recorded path (bin/python-path.txt) or the current
    interpreter. This keeps wafw00f working regardless of the shell's PATH.
    """
    sub = "Scripts" if IS_WINDOWS else "bin"
    cand = os.path.join(ROOT, "venv", sub, "python" + EXE)
    if os.path.isfile(cand):
        return cand
    cfg = os.path.join(BIN, "python-path.txt")
    if os.path.isfile(cfg):
        try:
            p = open(cfg, encoding="utf-8-sig").read().strip()
            if p and os.path.isfile(p):
                return p
        except OSError:
            pass
    return sys.executable


def _decode(b):
    if b is None:
        return ""
    return b.decode("utf-8", errors="replace")


def run(cmd, timeout=None, input_text=None):
    """Run a command (list of args). Returns (returncode, stdout, stderr, timed_out).

    Never raises for a missing tool or timeout — returns a sentinel instead so
    the pipeline can degrade gracefully.
    """
    try:
        p = subprocess.run(
            cmd,
            input=(input_text.encode("utf-8") if input_text is not None else None),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
        return p.returncode, _decode(p.stdout), _decode(p.stderr), False
    except subprocess.TimeoutExpired as e:
        return None, _decode(e.stdout), _decode(e.stderr), True
    except FileNotFoundError:
        return None, "", "tool not found", False
    except OSError as e:
        return None, "", str(e), False


def run_streamed(cmd, timeout, log_path, progress=None, interval=5, progress_every=15):
    """Run a long tool (e.g. nuclei) with a wall-clock cap and periodic progress.

    Streams combined stdout+stderr to `log_path` (UTF-8). Kills the child if it
    exceeds `timeout`. Returns True if it finished on its own, False if killed.
    """
    with open(log_path, "wb") as fh:
        try:
            p = subprocess.Popen(cmd, stdout=fh, stderr=subprocess.STDOUT)
        except (FileNotFoundError, OSError) as e:
            # Record why it could not launch (e.g. blocked by AV / Windows
            # security policy) so the report never mistakes this for a result.
            fh.write(("easm-recon: could not launch %s: %s\n" % (cmd[0], e))
                     .encode("utf-8", "replace"))
            return None  # tool unavailable / blocked
        start = time.time()
        last_tick = 0
        while p.poll() is None:
            time.sleep(interval)
            elapsed = time.time() - start
            if progress and elapsed - last_tick >= progress_every:
                last_tick = elapsed
                progress(_tail_line(log_path))
            if elapsed > timeout:
                _kill(p)
                return False
        return True


def _kill(p):
    try:
        p.kill()
        p.wait(timeout=10)
    except Exception:
        pass


def _tail_line(path):
    try:
        lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
        for ln in reversed(lines):
            if "percent" in ln or "matches found" in ln or "Templates" in ln:
                return ln.strip()
    except OSError:
        pass
    return ""


def have(name):
    return find_tool(name) is not None
