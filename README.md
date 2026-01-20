# cfdiag

A professional-grade, cross-platform (**Linux, macOS, Windows**) diagnostic CLI tool for Cloudflare Error 522, 525, 502, and general connectivity issues.

It orchestrates native system tools (`curl`, `traceroute`/`tracert`, `ping`) and Python's powerful networking libraries to perform a deep-dive analysis of the connection path between you, Cloudflare, and the Origin server.

## Features

### Core Diagnostics
*   **DNS Analysis:** Verifies resolution and compares local results vs. Google (8.8.8.8) and Cloudflare (1.1.1.1) to detect propagation issues.
*   **ISP/ASN Detection:** Automatically identifies the hosting provider (e.g., AWS, DigitalOcean) of the resolved IP.
*   **HTTP Inspection:** Smarter than just `ping`. Detects specific HTTP error codes (522, 525, 502) and analyzes headers.
*   **SSL/TLS Handshake:** Verifies certificate validity and expiration dates using native Python SSL libraries.
*   **TCP Connectivity:** Checks if port 443 is actually open using native sockets (no `nc` required).

### Advanced Debugging (The "Pro" Stuff)
*   **Direct Origin Test:** (Using `--origin <IP>`) Bypasses Cloudflare to connect directly to your server. **Definitively proves** if the issue is a firewall blocking Cloudflare or if the server is down.
*   **WAF/Challenge Detection:** Analyzes response bodies to see if you are being blocked by a Cloudflare Managed Challenge (Captcha) rather than a network error.
*   **MTU/Fragmentation Check:** Tests packet sizes to detect Path MTU Discovery blackholes (a common hidden cause of timeouts).
*   **Cloudflare Trace:** Fetches debug data (`/cdn-cgi/trace`) to identify the specific Cloudflare Data Center (`Colo`) and connection status.
*   **Alternative Port Scan:** If port 443 is blocked, it automatically scans valid Cloudflare alternative ports (2053, 8443, 2083, etc.) to find a workaround.

### Reporting
*   **Console Output:** Beautiful, colored, human-readable output (ANSI colors supported on Windows 10+).
*   **File Reports:** Automatically saves a clean, Markdown-formatted report to `reports/domain_timestamp.txt` for easy sharing with support teams.

## Installation

### Requirements
*   **Python 3.6+**
*   **System Tools:** `curl`, `traceroute` (Linux/Mac) or `tracert` (Windows), `ping`.
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

## Usage

### Basic Usage
Run a full diagnostic on a domain:
```bash
./cfdiag example.com
```

### Power User Usage (Direct Origin Test)
If you know your server's real IP address, use the `--origin` flag. This allows the tool to attempt a direct connection, bypassing Cloudflare's proxy.

```bash
./cfdiag example.com --origin 192.0.2.123
```

**Why is this important?**
*   If `cfdiag` to domain **FAILS** (522 Timeout)...
*   BUT `cfdiag` to `--origin` **SUCCEEDS**...
*   **Conclusion:** Your server is UP, but your firewall is blocking Cloudflare's IPs. Whitelist them!

## Output Example

```text
DIAGNOSTIC SUMMARY
------------------------------
[PASS] DNS is resolving correctly.
[PASS] SSL Certificate is valid.
[PASS] TCP (Port 443) is open.
[PASS] Network path supports standard MTU (1500).
[CRITICAL] Server returned Error (Code 522).
[ALERT] Cloudflare 522: Connection Timed Out to Origin.
[PASS] Cloudflare Edge Network is reachable.
  -> Connected to Data Center: MAD
```

## License
MIT