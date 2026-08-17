# easm-recon

A cross-platform **domain reconnaissance wrapper**. Point it at a host (or a
list of hosts) and it runs DNS, HTTP fingerprinting, WAF/CDN detection, TLS
inspection, port scanning and template-based vulnerability scanning in **one
command**, producing a readable Markdown report plus machine-readable CSVs.

easm-recon does not scan anything itself. It orchestrates mature open-source
tools into one consistent, bounded, fail-safe workflow, so you get repeatable
results without wiring eight tools together by hand.

- **Orchestrates:** dnsx, httpx, wafw00f, tlsx, cdncheck, nmap, nuclei, subfinder
- **Runs on:** Windows, Linux and macOS (pure-Python orchestrator, no shell glue)
- **Two modes:** single host, or a parallel batch from a list file
- **Passive by default:** active/noisy stages (ports, nuclei) are strictly opt-in
- **Customizable:** per-tool flags, presets, and a config file (see [Customization](#customization))

> **Scope.** This is a **reconnaissance and automated-scanning** tool (EASM). It
> is **not** a web-pentest tool: it performs no authenticated testing, manual
> exploitation or fuzzing. Every external tool it drives is open-source and
> downloaded from its official release at install time; nothing is bundled.

---

## Requirements

- **Python 3.8+** is the only hard dependency. The installer builds an isolated
  venv for everything else.
- **Internet access** for the installer (it downloads tool binaries from official
  GitHub releases and verifies each against its published SHA-256 checksum).
- **nmap** is optional and installed separately (see below). Without it, port
  scans fall back to naabu, then to a built-in Python connect-scan.

## Install

```bash
git clone https://github.com/Lockbearer/easm-recon.git
cd easm-recon
python install.py              # OS/arch-detected binaries (SHA-256 verified) + venv + wafw00f
python install.py --templates  # optionally also pull nuclei templates
```

`install.py` detects your platform, fetches the matching binaries into `./bin`,
and creates the isolated venv used for wafw00f. nmap, if you want richer port
scans, is installed with your platform's package manager:

```bash
# Windows
winget install Insecure.Nmap
# Debian / Ubuntu
sudo apt install nmap
# macOS
brew install nmap
```

## Quick start

```bash
python -m easm example.com                          # single host, passive
python -m easm example.com --full                   # + ports + nuclei + subdomains
python -m easm targets.txt --full --concurrency 6   # batch, 6 hosts in parallel
```

The target is treated as a **list file** if a file by that name exists on disk,
otherwise as a single host. With no flags the run is **passive/light**: DNS,
cdncheck, httpx and TLS fingerprinting plus WAF detection only.

Optional launcher, so you can type `easm <host>` from anywhere:

```bash
# Linux / macOS
ln -s "$(pwd)/easm.sh" ~/.local/bin/easm
easm example.com --full
# Windows: add this folder to PATH and use easm.bat -> easm example.com
```

## Flags

| Flag | Default | Mode | What it does |
|---|---|---|---|
| `target` | required | both | a host **or** a path to a list file |
| `--ports` | off | both | port scan: nmap, else naabu, else Python connect-scan. **Active** |
| `--nuclei` | off | both | nuclei vulnerability/exposure scan. **Active** |
| `--subs` | off | both | subdomain discovery (subfinder) |
| `--full` | off | both | shorthand for `--ports --nuclei --subs` |
| `--concurrency N` | 4 | batch | number of hosts scanned in parallel |
| `--nuclei-timeout N` | 900 | both | nuclei wall-clock cap in seconds; if hit, results are flagged **partial** |
| `--profile NAME` | `default` | both | flag preset: `default` / `fast` / `deep` (see [Customization](#customization)) |
| `--<tool>-args "..."` | none | both | append extra flags to one tool, e.g. `--nmap-args "-p-"` (see [Customization](#customization)) |

## Customization

The underlying tools are highly configurable, so easm-recon exposes their flags
at **four layers**, each overriding the previous:

```
built-in default  ->  config.json  ->  --profile  ->  --<tool>-args
```

Only *tunable* flags are ever exposed. The I/O flags that results are parsed from
(the target, `-json`/`-jsonl`, `-o <file>`) are always added by the engine and
cannot be overridden, so customization can never break report parsing.

**1. Pass-through flags** for a one-off run:

```bash
python -m easm example.com --ports  --nmap-args "-p- -A"        # all ports + OS/version
python -m easm example.com --nuclei --nuclei-args "-tags cve"   # CVE templates only
python -m easm example.com --subs   --subfinder-args "-all"     # all subfinder sources
```

Available for every tool: `--dnsx-args`, `--httpx-args`, `--tlsx-args`,
`--cdncheck-args`, `--nmap-args`, `--naabu-args`, `--nuclei-args`,
`--subfinder-args`. Values are tokenized and passed as an argument list, never a
shell string, so a target can never be interpreted as a command.

**2. Profiles** via `--profile`:

| Profile | nmap | nuclei |
|---|---|---|
| `default` | top-1000 ports, `--version-light`, 4m cap | low -> critical |
| `fast` | top-100 ports, 2m cap | high/critical, tags `cve,exposure,misconfig` |
| `deep` | **all ports** `-p-`, `-sC`, `--version-all`, 10m cap | info -> critical, 2 retries |

```bash
python -m easm example.com --profile deep --full
```

The nmap subprocess cap auto-adjusts to the profile's `--host-timeout`, so a
`deep` scan is never cut off prematurely.

**3. `config.json`** for persistent defaults and your own named profiles, with no
code editing. Copy [`config.example.json`](config.example.json) to `config.json`
(in the repo root, or `~/.easm/config.json`) and edit. `config.json` is
git-ignored; the `.example` template is tracked.

## Output

**Single host** -> `output/<host>/<timestamp>/`: a `report.md` plus the raw
`*.jsonl` from each tool.

**Batch** -> `output/_batch/<timestamp>/`:

| File | Contents |
|---|---|
| `report.md` | summary table followed by every host's full report |
| `summary.csv` | one row per host: ip, status, server, waf, tls, ports, vuln/subdomain counts |
| `nuclei.csv` | one row per finding: host, severity, name, template, matched_at |
| `subdomains.csv` | host, subdomain |
| `ports.csv` | host, port, service, version |
| `_manifest.tsv` | host to its exact output directory (traceability) |

## How it works

Per host, the pipeline is:

```
dnsx -> cdncheck -> httpx -> wafw00f -> tlsx -> [nmap] -> [nuclei] -> [subfinder] -> report
```

Bracketed stages are the opt-in active ones. The design goals:

- **Graceful degradation.** If a tool is missing or blocked, its stage is skipped
  or a built-in Python fallback runs (nmap -> naabu -> Python connect-scan;
  wafw00f -> behavioural probe; dnsx/httpx/tlsx -> stdlib). One tool failing
  never stops the scan.
- **Bounded.** Every external tool is time-capped (nmap `--host-timeout`, a nuclei
  watchdog, per-subprocess wall-clock limits). Nothing hangs forever.
- **Injection-safe.** Tools are invoked with argument lists, never shell strings,
  so a hostname can never be interpreted as a command.
- **Deterministic batches.** Each host writes to its own directory and the
  aggregator reads exactly those directories (recorded in `_manifest.tsv`). It
  never guesses a "latest" folder.
- **No silent truncation.** If nuclei is cut off by its timeout, the report and
  CSV mark it (`*`) as **partial**, so a partial scan is never mistaken for a
  complete one.
- **Environment isolation.** wafw00f runs from its own venv, and
  `PYTHONHOME`/`PYTHONPATH` are cleared before Python is invoked, so a messy host
  environment cannot break it.

## Troubleshooting

**A tool binary is blocked by antivirus or Windows Smart App Control.** The
orchestrated tools are unsigned binaries from official GitHub releases, and
Windows Smart App Control or some antivirus products may block one (you will see
`WinError 4556` / "an Application Control policy blocked this file"). easm-recon
records this as an **ERROR** and the report says the stage **did NOT run** - it
is never silently reported as a clean "0 findings". Options, most-preferred
first:

- Run on **Linux, macOS, or WSL**, where this restriction does not apply. The
  orchestrator behaves identically on every platform.
- Add the `bin/` folder to your antivirus exclusions (classic Defender AV).
- Build the tool from source with Go (e.g.
  `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`) so the
  binary is locally compiled.

Smart App Control is a Windows security feature; change it only if you fully
understand the implications.

## Authorization and ethics

`--ports` and `--nuclei` are **active and noisy**. Only run them against systems
you **own or are explicitly authorized to test** (for example `scanme.nmap.org`,
`example.com`, or your own assets). Unauthorized scanning is illegal in many
jurisdictions. If you are scanning corporate infrastructure, notify your SOC
first. You are solely responsible for how this tool is used.

## License

MIT. See [LICENSE](LICENSE).

## Credits

Built on the work of [ProjectDiscovery](https://github.com/projectdiscovery)
(httpx, nuclei, dnsx, naabu, cdncheck, tlsx, subfinder),
[wafw00f](https://github.com/EnableSecurity/wafw00f) and
[nmap](https://nmap.org).

easm-recon only orchestrates these tools. Their binaries are downloaded from
official sources at install time and are not bundled in this repository.
