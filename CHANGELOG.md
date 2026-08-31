# Changelog

All notable changes to easm-recon are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and this project adheres to
[Semantic Versioning](https://semver.org/).

## [1.1.0] - 2026-08-24

### Added
- `--dry-run` flag: prints an order-of-magnitude estimate of the network
  footprint (HTTP requests + nmap packets, per stage) from the chosen
  flags/profile and exits without sending anything. Works for single host and
  batch (`easm/estimate.py`).

### Changed
- **Process-tree termination.** Long-running tools (nuclei) now run in their own
  process group/session (`start_new_session` on POSIX,
  `CREATE_NEW_PROCESS_GROUP` on Windows). On the watchdog timeout the whole tree
  is torn down (`os.killpg` on POSIX, `taskkill /F /T` on Windows) instead of
  only the parent, so a killed tool leaves no orphaned child processes; falls
  back to `Popen.kill()` if the group signal fails.

### Documentation
- Corrected the "passive by default" claim. The no-flag run is **light but not
  fully passive**: only dnsx and cdncheck avoid the target, while httpx/tlsx make
  real requests and WAF detection sends attack-pattern probes. Clarified the
  distinction between *active* (touches the target) and *noisy* (high volume) —
  only `--ports` (especially `-p-`) and `--nuclei` are noisy.

## [1.0.0] - 2026-08-17

### Added
- Initial release. Cross-platform (Windows/Linux/macOS) domain reconnaissance
  wrapper orchestrating dnsx, httpx, wafw00f, tlsx, cdncheck, nmap, nuclei and
  subfinder into one workflow.
- Single-host and parallel batch (list-file) modes.
- Flag profiles (`default` / `fast` / `deep`), per-tool pass-through
  (`--<tool>-args`), and optional `config.json` for persistent customization.
- nuclei watchdog with wall-clock cap; partial results are flagged rather than
  reported as clean. Blocked/unavailable tools are recorded as errors, never as
  "0 findings".
- Graceful fallbacks for every stage (nmap → naabu → Python connect-scan;
  wafw00f → behavioural probe; dnsx/httpx/tlsx → stdlib).
- OS/arch-detecting installer with SHA-256 verification of downloaded binaries.

[1.1.0]: https://github.com/Lockbearer/easm-recon/releases/tag/v1.1.0
[1.0.0]: https://github.com/Lockbearer/easm-recon/releases/tag/v1.0.0
