# Changelog

All notable changes to this project will be documented in this file.

## [v3.12.3] - 2026-01-22
### Changed
- **Architecture:** Complete architectural cleanup. Step functions are now strictly separated and return `None`.
- **Refactor:** Decoupled `step_asn` from `step_dns`, ensuring independent IP resolution and linear execution flow.
- **Standards:** Standardized status strings to `PASS`, `FAIL`, `WARN`, `INFO`. Removed legacy `SUCCESS`/`CLIENT_ERROR` terminology.
- **Cleanup:** Removed dead code including unused reporting functions (`save_history`, `save_metrics`, `compare_reports`), summary generation logic, and obsolete documentation.
- **Tests:** Updated test suite to align with architectural changes and adjusted coverage thresholds.

## [v2.12.0] - 2026-01-20
### Added
- **Shell Completion:** Generate bash/zsh completion scripts via `--completion`.
- **JSON Output:** `--json` now outputs full diagnostic data to stdout for automation.

## [v2.11.0] - 2026-01-20
### Added
- **Binary Distribution:** Automated build of standalone executables for Windows, Linux, and macOS via GitHub Actions.
- **Documentation:** Updated README with installation instructions for binaries.

## [v2.10.0] - 2026-01-20
### Added
- **IPv4/IPv6 Forcing:** New flags `--ipv4` and `--ipv6`.
- **Proxy Support:** New flag `--proxy` to route traffic via HTTP proxies.
### Fixed
- **Architecture:** Fixed critical logger bug in parallel execution mode.

## [v2.9.0] - 2026-01-20
### Added
- **Offline Mode:** Uses DNS (`dig`) for ASN/ISP lookup instead of external HTTP APIs.
- **Report Diffing:** Compare two diagnostic reports with `--diff`.
- **Logging:** Fixed global logger issues in threaded context.

## [v2.8.0] - 2026-01-20
### Added
- **Redirect Chain Analysis:** Trace full redirect paths and detect loops.
- **WAF Evasion Testing:** Test connection using different User-Agents.

## [v2.7.0] - 2026-01-20
### Added
- **Parallel Scanning:** Multi-threaded batch mode (`--threads`).
- **Packaging:** Added `setup.py` for PyPI distribution.

## [v2.6.0] - 2026-01-20
### Added
- **Metrics:** Prometheus OpenMetrics export via `--metrics`.
- **History:** Automatic TTFB comparison with previous runs.

## [v2.5.0] - 2026-01-20
### Changed
- **Reports:** Organized reports into per-domain subdirectories.
- **Verbosity:** Defaulted to summary-only text logs (matching console).

## [v2.4.0] - 2026-01-20
### Fixed
- **Summary:** Restored missing Diagnostic Summary in text reports.
- **Formatting:** Fixed ANSI escape codes in log files.

## [v2.0.0] - 2026-01-20
### Added
- **Core:** Initial major release with DNS, HTTP, TCP, and Traceroute.
