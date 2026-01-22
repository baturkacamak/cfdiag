# Comprehensive Decision Trees

This document specifies the exact logic used in `cfdiag/analysis.py` to classify probe results.

## 1. DNS Decision Tree

**Function:** `analyze_dns`
**Input:** `ProbeDNSResult`

| Evaluation Order | Condition | Classification | Severity | Human Reason |
| :--- | :--- | :--- | :--- | :--- |
| 1 | `error` is present OR (`A` empty AND `AAAA` empty) | `DNS_FAIL` | **CRITICAL** | DNS Resolution failed: {error} |
| 2 | `A` present AND `AAAA` present | `DNS_PASS` | **PASS** | Resolved both IPv4 and IPv6. |
| 3 | `A` present AND `AAAA` empty | `DNS_IPV4_ONLY` | **INFO** | IPv4 only (No AAAA records). |
| 4 | `AAAA` present AND `A` empty | `DNS_IPV6_ONLY` | **INFO** | IPv6 only (No A records). |
| 5 | *Default* | `DNS_PASS` | **PASS** | Resolved. |

*Note: Resolver inconsistencies are currently handled by the probe returning a unified set or error.*

## 2. HTTP Decision Tree

**Function:** `analyze_http`
**Input:** `ProbeHTTPResult`

| Evaluation Order | Condition | Classification | Severity | Human Reason |
| :--- | :--- | :--- | :--- | :--- |
| 1 | `error` contains "Timeout" | `HTTP_TIMEOUT` | **CRITICAL** | Request timed out: {error} |
| 2 | `error` present OR `code` == 0 | `HTTP_CONNECT_FAIL` | **CRITICAL** | Connection failed: {error} |
| 3 | `code` in [301, 302, 303, 307, 308] | `HTTP_REDIRECT` | **WARNING** | Redirect limit reached or loop detected. |
| 4 | `code` == 429 | `HTTP_RATE_LIMIT` | **INFO** | Rate Limited (HTTP 429). |
| 5 | 200 <= `code` < 400 | `HTTP_PASS` | **PASS** | HTTP {code} OK. |
| 6 | `is_waf_challenge` == True | `HTTP_WAF_BLOCK` | **INFO** | Request challenged/blocked by WAF. |
| 7 | 400 <= `code` < 500 | `HTTP_CLIENT_ERROR` | **WARNING** | Client Error (HTTP {code}). |
| 8 | 500 <= `code` < 600 | `HTTP_SERVER_ERROR` | **ERROR** | Server Error (HTTP {code}). |
| 9 | *Default* | `UNKNOWN` | **WARNING** | Unexpected status: {code} |

## 3. TLS Decision Tree

**Function:** `analyze_tls`
**Input:** `ProbeTLSResult`

| Evaluation Order | Condition | Classification | Severity | Human Reason |
| :--- | :--- | :--- | :--- | :--- |
| 1 | `handshake_success` == False | `TLS_FAIL_HANDSHAKE` | **CRITICAL** | TLS Handshake Failed: {error} |
| 2 | `cert_valid` == False AND ("expired" in errors) | `TLS_EXPIRED` | **ERROR** | Certificate Expired/Not Valid: {errors} |
| 3 | `cert_valid` == False | `TLS_WARN_CERT_INVALID` | **ERROR** | Certificate Invalid: {errors} |
| 4 | `protocol_version` < "TLSv1.2" | `TLS_OLD_PROTOCOL` | **WARNING** | Deprecated Protocol: {version} |
| 5 | *Default* | `TLS_PASS` | **PASS** | TLS Handshake Success. |

## 4. MTU Decision Tree

**Function:** `analyze_mtu`
**Input:** `ProbeMTUResult`

| Evaluation Order | Condition | Classification | Severity | Human Reason |
| :--- | :--- | :--- | :--- | :--- |
| 1 | `path_mtu` == 0 | `MTU_WARNING` | **WARNING** | Could not determine MTU (ICMP blocked?). |
| 2 | `path_mtu` < 1280 | `MTU_CRITICAL` | **CRITICAL** | Path MTU {mtu} < 1280 (IPv6 Min). |
| 3 | 1280 <= `path_mtu` < 1500 | `MTU_WARNING` | **WARNING** | Path MTU {mtu} < 1500. |
| 4 | `path_mtu` >= 1500 | `MTU_PASS` | **PASS** | MTU 1500 OK. |

## 5. Origin Decision Tree

**Function:** `analyze_origin_reachability`
**Input:** Edge `ProbeHTTPResult`, Origin `ProbeHTTPResult`

| Evaluation Order | Condition | Classification | Severity | Human Reason |
| :--- | :--- | :--- | :--- | :--- |
| 1 | Origin `error` contains "Timeout" | `ORIGIN_522` | **ERROR** | Origin Timed Out (Direct). |
| 2 | Origin `error` present OR `code` == 0 | `ORIGIN_UNREACHABLE` | **CRITICAL** | Origin Unreachable: {error} |
| 3 | Edge in [502, 504, 521, 522] AND Origin OK (2xx/3xx) | `ORIGIN_FIREWALL_BLOCK` | **WARNING** | Origin is UP, but Cloudflare cannot reach it. |
| 4 | Origin OK AND Edge OK | `ORIGIN_REACHABLE` | **PASS** | Origin and Edge both reachable. |
| 5 | *Default* | `ORIGIN_REACHABLE` | **INFO** | Status match (non-success). |
