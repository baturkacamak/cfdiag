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

### Utilities
*   **High-Speed Batch Mode:** Scan hundreds of domains in seconds using multi-threading (`--threads 50`).
*   **Proxy Support:** Run diagnostics from behind a corporate proxy (`--proxy http://...`).
*   **IP Version Forcing:** Force IPv4 (`--ipv4`) or IPv6 (`--ipv6`) to isolate stack issues.
*   **Metrics Export:** Generates Prometheus-compatible metrics (`metrics.prom`) for monitoring integration.
*   **History & Trending:** Automatically compares latency (TTFB) with the previous run to detect performance degradation.

## Installation

### Option 1: Standalone Binary (Recommended)
Download the latest single-file executable for your OS from the [Releases Page](https://github.com/baturkacamak/cfdiag/releases). No Python installation required.

### Option 2: Pip (Python Package)
```bash
pip install . 
# (Once published to PyPI: pip install cfdiag)
```

### Option 3: Source
```bash
git clone git@github.com:baturkacamak/cfdiag.git
cd cfdiag
python3 cfdiag.py example.com
```

### Option 4: Docker
```bash
docker build -t cfdiag .
docker run --rm cfdiag example.com
```

## Usage

### Basic Usage
Run a diagnostic (summary only):
```bash
cfdiag example.com
```

### Troubleshooting
Force IPv4 or use a Proxy:
```bash
cfdiag example.com --ipv4 --proxy http://10.0.0.1:8080
```

### Power User Usage
Check direct origin connectivity, propagation, and enable metrics:
```bash
cfdiag example.com --origin 192.0.2.123 --expect ns1.digitalocean.com --metrics
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

## License
MIT