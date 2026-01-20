# Usage Guide

## Core Commands

### Single Domain
Scan a single domain. Default output is a concise summary.
```bash
cfdiag example.com
```

### Batch Mode
Scan multiple domains from a file using parallel threads.
```bash
cfdiag --file list.txt --threads 20
```

## Advanced Options

### Direct Origin Test
Bypass Cloudflare and DNS to connect directly to an IP address. Essential for verifying if your server firewall is blocking Cloudflare.
```bash
cfdiag example.com --origin 1.2.3.4
```

### DNS Propagation
Check if your Nameserver changes have propagated globally.
```bash
cfdiag example.com --expect ns1.digitalocean.com
```

### WAF Testing
Test if the site is blocking specific User-Agents (like curl).
```bash
cfdiag example.com --verbose
```
*(This runs automatically in verbose mode)*

## Automation

### JSON Output
Get the full internal state as a JSON object.
```bash
cfdiag example.com --json | jq .
```

### Report Diffing
Compare two previous reports to see what changed.
```bash
cfdiag --diff reports/a.txt reports/b.txt
```
