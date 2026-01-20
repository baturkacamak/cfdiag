# cfdiag

A cross-platform (Linux/macOS) diagnostic CLI tool for Cloudflare Error 522 and connectivity issues.

## Requirements

- Python 3
- System tools: `dig`, `curl`, `nc` (netcat), `traceroute`

### Installation (Debian/Ubuntu)
```bash
sudo apt update
sudo apt install dnsutils curl netcat traceroute python3
```

### Installation (macOS)
```bash
brew install bind curl netcat traceroute
```
(Note: macOS comes with most of these, but `bind` provides `dig`)

## Usage

```bash
./cfdiag example.com
```

## Features

1. **DNS Resolution**: Verifies domain resolves to an IP.
2. **HTTP Check**: Checks if the site is reachable and returns headers.
3. **TCP Connectivity**: Verifies port 443 connectivity to the edge.
4. **Traceroute**: Maps the network path.
5. **Forced Resolution**: Tests connectivity to Cloudflare's 1.1.1.1 to rule out local routing issues.
6. **Smart Summary**: Analyzes results to suggest the root cause (e.g., Origin Timeout vs. Network Block).


