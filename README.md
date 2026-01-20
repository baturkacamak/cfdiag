# cfdiag

A professional-grade, cross-platform (**Linux, macOS, Windows**) diagnostic CLI tool for Cloudflare Error 522, 525, 502, and general connectivity issues.

It orchestrates native system tools (`curl`, `traceroute`/`tracert`, `ping`) and Python's powerful networking libraries to perform a deep-dive analysis of the connection path between you, Cloudflare, and the Origin server.

## Features

### Core Diagnostics
*   **Dual-Stack DNS Analysis:** Verifies both **IPv4** (A) and **IPv6** (AAAA) resolution.
*   **DNS Propagation Check:** Checks global resolvers (Google, Cloudflare, Quad9, etc.) to see if your Nameserver changes have propagated worldwide.
*   **DNSSEC Validation:** Checks if the domain's chain of trust is intact or broken.
*   **Domain Registration Status:** Checks RDAP data to see if the domain is active, suspended, or expired.
*   **ISP/ASN Detection:** Automatically identifies the hosting provider (e.g., AWS, DigitalOcean) of the resolved IP.
*   **HTTP Inspection:** Smarter than just `ping`. Detects specific HTTP error codes (522, 525, 502) and analyzes headers.
*   **Performance Metrics:** Measures **TTFB** (Time To First Byte) and Connect Time to identify backend slowness vs network lag.
*   **HTTP/3 (QUIC) Check:** Verifies if UDP Port 443 is open/filtered.
*   **SSL/TLS Handshake:** Verifies certificate validity and expiration dates using native Python SSL libraries.
*   **TCP Connectivity:** Checks if port 443 is actually open using native sockets (no `nc` required).

### Advanced Debugging (The "Pro" Stuff)
*   **Direct Origin Test:** (Using `--origin <IP>`) Bypasses Cloudflare to connect directly to your server. **Definitively proves** if the issue is a firewall blocking Cloudflare or if the server is down.
*   **WAF/Challenge Detection:** Analyzes response bodies to see if you are being blocked by a Cloudflare Managed Challenge (Captcha) rather than a network error.
*   **MTU/Fragmentation Check:** Tests packet sizes to detect Path MTU Discovery blackholes (a common hidden cause of timeouts).
*   **Cloudflare Trace:** Fetches debug data (`/cdn-cgi/trace`) to identify the specific Cloudflare Data Center (`Colo`) and connection status.
*   **Alternative Port Scan:** If port 443 is blocked, it automatically scans valid Cloudflare alternative ports (2053, 8443, 2083, etc.) to find a workaround.

### Utilities
*   **Batch Mode:** Scan a list of domains from a file: `cfdiag --file domains.txt`
*   **Config File:** Save your preferences (like origin IP) in `~/.cfdiag.json`.
*   **Self-Update:** Run with `--update` to automatically pull the latest version from GitHub.
*   **Reporting:** Beautiful console output and clean Markdown file logs in `reports/`.

## Installation

### Requirements
*   **Python 3.6+**
*   **System Tools:** `curl`, `traceroute` (Linux/Mac) or `tracert` (Windows), `ping`, `dig` (Optional, for DNSSEC).
    *   *Note: Windows 10/11 includes `curl` and `tracert` by default.*

### Setup
```bash
git clone git@github.com:baturkacamak/cfdiag.git
cd cfdiag
# Linux/macOS
chmod +x cfdiag.py
python3 cfdiag.py example.com

# Windows
python cfdiag.py example.com
```

### Docker
```bash
docker build -t cfdiag .
docker run --rm cfdiag example.com
```

## Usage

### Basic Usage
Run a diagnostic (summary only):
```bash
./cfdiag example.com
```

Show verbose output (all steps):
```bash
./cfdiag example.com --verbose
```

### Configuration File
Create a `.cfdiag.json` in your home directory or current folder:
```json
{
  "profiles": {
    "prod": { "domain": "example.com", "origin": "1.2.3.4" }
  }
}
```
Run with profile:
```bash
./cfdiag --profile prod
```

### Power User Usage
Check direct origin connectivity and propagation:
```bash
./cfdiag example.com --origin 192.0.2.123 --expect ns1.digitalocean.com
```

### Batch Mode
Check multiple domains at once:
```bash
./cfdiag --file my_domains.txt
```

### Update Tool
```bash
./cfdiag --update
```

## License
MIT