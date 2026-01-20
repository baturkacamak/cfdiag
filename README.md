# cfdiag

A professional-grade, cross-platform (**Linux, macOS, Windows**) diagnostic CLI tool for Cloudflare Error 522, 525, 502, and general connectivity issues.

It orchestrates native system tools (`curl`, `traceroute`/`tracert`, `ping`) and Python's powerful networking libraries to perform a deep-dive analysis of the connection path between you, Cloudflare, and the Origin server.

## Features

### Core Diagnostics
*   **Dual-Stack DNS Analysis:** Verifies both **IPv4** (A) and **IPv6** (AAAA) resolution.
*   **Offline ASN Detection:** Uses DNS-based lookup to identify ISPs/ASNs without external HTTP APIs (Privacy-first).
*   **DNS Propagation Check:** Checks global resolvers (Google, Cloudflare, Quad9, etc.) to see if your Nameserver changes have propagated worldwide.
*   **DNSSEC Validation:** Checks if the domain's chain of trust is intact or broken.
*   **SSL/TLS Handshake:** Verifies certificate validity, expiration, and **OCSP Stapling** status.
*   **HTTP/3 (QUIC) Check:** Verifies if UDP Port 443 is open/filtered.
*   **Security Header Audit:** Checks for HSTS, CSP, and verifies **HSTS Preload** eligibility.

### Advanced Debugging (The "Pro" Stuff)
*   **Redirect Chain Analysis:** Traces the full path of redirects (301->302->200) to detect loops instantly.
*   **WAF Evasion Test:** Retries requests with different User-Agents (Chrome, Googlebot, etc.) to detect if a block is due to Bot Protection.
*   **Direct Origin Test:** (Using `--origin <IP>`) Bypasses Cloudflare to connect directly to your server. Definitively proves if the issue is a firewall blocking Cloudflare IPs.
*   **Report Comparison:** Diff two reports (`--diff old.txt new.txt`) to spot exactly what changed (Latency, Routes, IPs).
*   **MTU/Fragmentation Check:** Tests packet sizes to detect Path MTU Discovery blackholes.
*   **SSL Key Logging:** Decrypt traffic in Wireshark by dumping session keys (`--keylog keys.log`).

### Utilities
*   **High-Speed Batch Mode:** Scan hundreds of domains in seconds using multi-threading (`--threads 50`).
*   **Proxy Support:** Run diagnostics from behind a corporate proxy (`--proxy http://...`).
*   **IP Version Forcing:** Force IPv4 (`--ipv4`) or IPv6 (`--ipv6`) to isolate stack issues.
*   **Custom Headers:** Inject custom headers (`--header "X-Debug: 1"`) to bypass caches or test WAF rules.
*   **Custom Timeouts:** Set connection timeout (`--timeout 5`) for faster scanning or slow links.
*   **Metrics Export:** Generates Prometheus-compatible metrics (`metrics.prom`) for monitoring integration.
*   **Grafana Dashboard:** Generate a JSON dashboard for visualizing metrics (`--grafana`).
*   **History & Trending:** Automatically compares latency (TTFB) with the previous run to detect performance degradation.
*   **JSON Output:** Output full results as JSON for automation (`--json`).
*   **Markdown Output:** Output report as Markdown for easy sharing (`--markdown`).
*   **JUnit XML:** Output test results for CI/CD integration (`--junit`).
*   **Shell Completion:** Generate auto-completion scripts (`--completion bash`).

## Installation

### Option 1: Standalone Binary (Recommended for Windows/Linux)
Download the latest single-file executable for your OS from the [Releases Page](https://github.com/baturkacamak/cfdiag/releases). No Python installation required.

### Option 2: Homebrew (macOS/Linux)
```bash
brew install baturkacamak/cfdiag/cfdiag
```

### Option 3: Pip (Python Package)
```bash
pip install . 
# (Once published to PyPI: pip install cfdiag)
```

### Option 4: Source (Dev)
```bash
git clone git@github.com:baturkacamak/cfdiag.git
cd cfdiag
python3 -m cfdiag example.com
```

## Usage

### Basic Usage
Run a diagnostic (summary only):
```bash
cfdiag example.com
```

### Troubleshooting
Force IPv4, use a Proxy, or set a short timeout:
```bash
cfdiag example.com --ipv4 --proxy http://10.0.0.1:8080 --timeout 5
```

### Power User Usage
Check direct origin connectivity with custom headers:
```bash
cfdiag example.com --origin 192.0.2.123 --header "X-My-Header: test"
```

### Expert Mode (Wireshark Decryption)
Dump SSL session keys to file:
```bash
cfdiag example.com --keylog ssl-keys.log
```

### Reporting
Generate reports in various formats:
```bash
cfdiag example.com --markdown > report.md
cfdiag example.com --junit > junit.xml
```

### Batch Mode (High Performance)
Check 100 domains with 20 concurrent threads:
```bash
cfdiag --file domains.txt --threads 20
```

### Compare Reports
See what changed between yesterday and today:
```bash
cfdiag --diff reports/example.com/2026-01-19.txt reports/example.com/2026-01-20.txt
```

### Automation
Pipe JSON output to jq:
```bash
cfdiag example.com --json | jq .details.http_metrics.ttfb
```

## License
MIT
