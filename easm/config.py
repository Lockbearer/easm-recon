"""Customizable per-tool flags: built-in defaults, named profiles, optional
config.json overrides, and CLI pass-through.

Resolution order (each layer overrides the previous):
    built-in DEFAULT_FLAGS  ->  config.json  ->  --profile  ->  --<tool>-args

Only the *tunable* flags live here. Fixed I/O flags (target, -o/-oN, output
format needed for parsing) are added by the engine and are NOT overridable, so
customization can never break result parsing.
"""
from __future__ import annotations

import json
import os

# Default tunable flags per tool (identical to the original defaults).
DEFAULT_FLAGS = {
    "dnsx": ["-a", "-aaaa", "-cname", "-ns", "-resp", "-silent"],
    "httpx": ["-silent", "-status-code", "-title", "-web-server", "-tech-detect",
              "-tls-grab", "-cdn", "-location", "-follow-redirects"],
    "tlsx": ["-silent", "-so", "-expired", "-self-signed", "-mismatched",
             "-tls-version", "-cipher"],
    "cdncheck": ["-silent", "-resp"],
    "nmap": ["-Pn", "-T4", "--host-timeout", "4m", "--version-light",
             "--top-ports", "1000", "-sV"],
    "naabu": ["-silent", "-s", "c", "-top-ports", "1000"],
    "nuclei": ["-severity", "low,medium,high,critical", "-no-color",
               "-timeout", "8", "-retries", "1", "-stats", "-si", "15"],
    "subfinder": ["-silent"],
}

# Named presets. A profile only lists the tools it changes; others fall back to
# DEFAULT_FLAGS. Keep the tunable flags only (no I/O flags).
PROFILES = {
    "default": {},
    "fast": {
        "nmap": ["-Pn", "-T4", "--host-timeout", "2m", "--version-light", "--top-ports", "100"],
        "nuclei": ["-severity", "high,critical", "-no-color", "-timeout", "8",
                   "-retries", "1", "-stats", "-si", "15", "-tags", "cve,exposure,misconfig"],
    },
    "deep": {
        "nmap": ["-Pn", "-T4", "--host-timeout", "10m", "--version-all", "-sC", "-p-"],
        "nuclei": ["-severity", "info,low,medium,high,critical", "-no-color",
                   "-timeout", "10", "-retries", "2", "-stats", "-si", "15"],
    },
}

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load_json_overrides():
    """Merge config.json (repo root or ~/.easm/config.json) over the built-ins.

    Shape:
        {
          "flags":    { "nmap": ["-Pn","-p-", ...], ... },
          "profiles": { "myprofile": { "nmap": [...] } }
        }
    """
    for path in (os.path.join(_ROOT, "config.json"),
                 os.path.join(os.path.expanduser("~"), ".easm", "config.json")):
        if os.path.isfile(path):
            try:
                cfg = json.load(open(path, encoding="utf-8-sig"))
            except (ValueError, OSError):
                continue
            for tool, flags in (cfg.get("flags") or {}).items():
                if isinstance(flags, list):
                    DEFAULT_FLAGS[tool] = [str(x) for x in flags]
            for name, spec in (cfg.get("profiles") or {}).items():
                PROFILES[name] = {t: [str(x) for x in f] for t, f in (spec or {}).items()
                                  if isinstance(f, list)}


_load_json_overrides()


def profile_names():
    return sorted(PROFILES.keys())


def flags_for(tool, profile="default", extra=None):
    """Resolve the tunable flag list for a tool: profile override or default,
    then append any CLI pass-through args (`extra`)."""
    prof = PROFILES.get(profile, {})
    base = list(prof.get(tool, DEFAULT_FLAGS.get(tool, [])))
    if extra:
        base += list(extra)
    return base
