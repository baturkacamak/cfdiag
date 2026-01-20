# cfdiag

**cfdiag** is a professional-grade, cross-platform diagnostic CLI tool for Cloudflare and general networking issues.

It helps you identify:
*   Cloudflare Errors (522, 525, 502)
*   DNS Propagation issues
*   SSL/TLS Handshake failures
*   Direct Origin connectivity problems

## Installation

### Binary (Recommended)
Download from [Releases](https://github.com/baturkacamak/cfdiag/releases).

### Homebrew
```bash
brew install baturkacamak/cfdiag/cfdiag
```

### Pip
```bash
pip install cfdiag
```

## Quick Start

```bash
# Basic Scan
cfdiag example.com

# Detailed Scan
cfdiag example.com --verbose

# JSON Output
cfdiag example.com --json
```
