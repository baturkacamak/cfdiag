# cfdiag

A professional-grade, cross-platform (**Linux, macOS, Windows**) diagnostic CLI tool for Cloudflare Error 522, 525, 502, and general connectivity issues.

## Features

### Core Diagnostics
*   **Dual-Stack DNS Analysis:** Verifies both **IPv4** (A) and **IPv6** (AAAA) resolution.
*   **Offline ASN Detection:** Uses DNS-based lookup to identify ISPs/ASNs without external HTTP APIs (Privacy-first).
*   **DNS Propagation Check:** Checks global resolvers (Google, Cloudflare, Quad9, etc.) to see if your Nameserver changes have propagated worldwide.
*   **DNS-over-HTTPS (DoH):** Tests connectivity to Cloudflare DNS via HTTPS to detect ISP filtering.
*   **DNSSEC Validation:** Checks if the domain's chain of trust is intact or broken.
*   **SSL/TLS Handshake:** Verifies certificate validity, expiration, and **OCSP Stapling** status.
*   **HTTP/3 (QUIC) Check:** Verifies if UDP Port 443 is open/filtered.
*   **Security Header Audit:** Checks for HSTS, CSP, and verifies **HSTS Preload** eligibility.

### Advanced Debugging (The "Pro" Stuff)
*   **Redirect Chain Analysis:** Traces the full path of redirects (301->302->200) to detect loops instantly.
*   **WAF Evasion Test:** Retries requests with different User-Agents (Chrome, Googlebot, etc.) to detect if a block is due to Bot Protection.
*   **Direct Origin Test:** (Using `--origin <IP>`) Bypasses Cloudflare to connect directly to your server. Definitively proves if the issue is a firewall blocking Cloudflare IPs.
*   **Report Comparison:** Diff two reports (`--diff old.txt new.txt`) to spot exactly what changed (Latency, Routes, IPs).
*   **Real Path MTU:** Active packet size testing (`ping -f`) to detect blackholes.
*   **WebSocket Test:** Verifies connection upgrades (`101 Switching Protocols`) for real-time apps (`--ws`).
*   **SSL Key Logging:** Decrypt traffic in Wireshark by dumping session keys (`--keylog keys.log`).

### Utilities & Audit
*   **Log Analyzer:** Parses web server access logs for Cloudflare error codes 520-530 (`--analyze-logs`).
*   **Diagnostic Server:** Starts a local HTTP server to echo headers and test timeouts (`--serve`).
*   **Configuration Linter:** Scans web server config (`nginx.conf`) for missing Cloudflare Real IP directives (`--lint-config`).
*   **Security Audit:** Runs a strict Pass/Fail audit for compliance (`--audit`).
*   **Throughput/Speed Test:** Measures download speed (`--speed`).
*   **DNS Benchmark:** Races public resolvers to find the fastest one (`--benchmark-dns`).
*   **High-Speed Batch Mode:** Scan hundreds of domains in seconds using multi-threading (`--threads 50`).
*   **Proxy Support:** Run diagnostics from behind a corporate proxy (`--proxy http://...`).
*   **Metrics & Monitoring:** Supports Prometheus export, Grafana JSON generation, Webhooks, and Watch Mode.

## Installation

### Option 1: Standalone Binary (Recommended)
Download the latest single-file executable for your OS from the [Releases Page](https://github.com/baturkacamak/cfdiag/releases). No Python installation required.

### Option 2: Pip (Python Package)
```bash
pip install .
```

### Option 3: Docker
```bash
docker build -t cfdiag .
docker run --rm cfdiag example.com
```

### Option 4: Homebrew (Unofficial)
This project does not maintain an official Homebrew Tap.
A formula file is available in `contrib/homebrew/cfdiag.rb` for manual use.

## Usage

### Basic Usage
```bash
cfdiag example.com
```

### Advanced Network Debugging
```bash
# Test WebSockets, Speed, and Encrypted DNS
cfdiag example.com --ws --speed --doh
```

### Server-Side Tools
```bash
# Analyze Nginx logs for 522 errors
cfdiag --analyze-logs /var/log/nginx/access.log

# Check config for Real IP setup
cfdiag --lint-config /etc/nginx/nginx.conf

# Start a dummy origin server on port 8080 (Echoes headers)
cfdiag --serve 8080
```

### Audit Mode
```bash
cfdiag example.com --audit
```

### Automation
```bash
cfdiag example.com --json | jq .
```

## License
MIT