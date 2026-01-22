# cfdiag

A professional-grade, cross-platform (**Linux, macOS, Windows**) diagnostic CLI tool for Cloudflare Error 522, 525, 502, and general connectivity issues.

## Features

### Core Diagnostics
*   **Dual-Stack DNS Analysis:** Verifies both **IPv4** (A) and **IPv6** (AAAA) resolution.
*   **ASN/ISP Check:** Independent resolution and analysis of ASN information.
*   **SSL/TLS Handshake:** Verifies certificate validity, expiration, and handshake success.
*   **HTTP Availability:** Checks status codes, redirects, and basic connectivity.
*   **MTU Check:** Tests packet sizes to detect Path MTU Discovery issues.
*   **Direct Origin Test:** (Using `--origin <IP>`) Bypasses Cloudflare to connect directly to your server. Definitively proves if the issue is a firewall blocking Cloudflare IPs.

### Utilities
*   **Configuration Linter:** Scans web server config (`nginx.conf`) for missing Cloudflare Real IP directives (`--lint-config`).
*   **Log Analysis:** Analyzes web server access logs for common error patterns (`--analyze-logs`).
*   **MTR Mode:** Runs an interactive traceroute with real-time statistics (`--mtr`).
*   **Diagnostic Server:** Starts a local server for testing connectivity (`--serve`).
*   **Batch Mode:** Scan hundreds of domains in seconds using multi-threading (`--file`).
*   **Report Generation:** Supports JSON output (`--json`), Markdown reports (`--markdown`), and JUnit XML (`--junit`).

## Installation

### Option 1: Standalone Binary (Recommended)
Download the latest single-file executable for your OS from the [Releases Page](https://github.com/baturkacamak/cfdiag/releases). No Python installation required.

*   **Windows:** `cfdiag-windows-amd64.exe`
*   **macOS (Intel):** `cfdiag-macos-amd64`
*   **macOS (Apple Silicon/M1/M2):** `cfdiag-macos-arm64`
*   **Linux:** `cfdiag-linux-amd64`

> **macOS Gatekeeper:** If you see "Apple cannot check it for malicious software", run:
> `xattr -d com.apple.quarantine cfdiag-macos-*`

### Option 2: Pip (Python Package)
```bash
# Install from local source (requires cloning repo)
git clone https://github.com/baturkacamak/cfdiag.git
cd cfdiag
pip install .
```

### Option 3: Docker
```bash
docker build -t cfdiag .
docker run --rm cfdiag example.com
```

## Usage

### Basic Usage
```bash
cfdiag example.com
```

### Direct Origin Check
```bash
cfdiag example.com --origin 1.2.3.4
```

### Config Check
```bash
cfdiag --lint-config /etc/nginx/nginx.conf
```

### Log Analysis
```bash
cfdiag --analyze-logs /var/log/nginx/access.log
```

### Interactive MTR
```bash
cfdiag example.com --mtr
```

### Automation
```bash
cfdiag example.com --json | jq .
```

## License
MIT
