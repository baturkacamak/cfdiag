from typing import List, Optional, Any
from datetime import datetime
from .types import (
    ProbeDNSResult, ProbeHTTPResult, ProbeTLSResult, ProbeMTUResult, ProbeOriginResult,
    AnalysisResult, Severity
)

def _res(
    status: Severity, 
    classification: str, 
    reason: str, 
    meta: dict, 
    recs: Optional[List[str]] = None
) -> AnalysisResult:
    return {
        "status": status,
        "classification": classification,
        "human_reason": reason,
        "meta": meta,
        "recommendations": recs or []
    }

def analyze_dns(probe: ProbeDNSResult) -> AnalysisResult:
    meta = {
        "records": probe["records"], 
        "dnssec": probe["dnssec_valid"],
        "error": probe["error"]
    }
    
    if probe["error"] or (not probe["records"]["A"] and not probe["records"]["AAAA"]):
        return _res(Severity.CRITICAL, "DNS_FAIL", 
                   f"DNS Resolution failed: {probe['error'] or 'No records'}", meta,
                   ["Check domain registration", "Check authoritative nameservers"])

    has_a = len(probe["records"]["A"]) > 0
    has_aaaa = len(probe["records"]["AAAA"]) > 0
    
    # If resolver consistency check was in probe, we would use DNS_INCONSISTENT here.
    # Current probe doesn't explicitly check multiple resolvers against each other in detail,
    # but if records exist we pass.
    
    if has_a and has_aaaa:
        return _res(Severity.PASS, "DNS_PASS", "Resolved both IPv4 and IPv6.", meta)
    elif has_a and not has_aaaa:
        return _res(Severity.INFO, "DNS_IPV4_ONLY", "IPv4 only (No AAAA records).", meta,
                   ["Consider enabling IPv6 for better connectivity"])
    elif has_aaaa and not has_a:
        return _res(Severity.INFO, "DNS_IPV6_ONLY", "IPv6 only (No A records).", meta,
                   ["Ensure legacy IPv4 clients can connect"])
                   
    return _res(Severity.PASS, "DNS_PASS", "Resolved.", meta)

def analyze_http(probe: ProbeHTTPResult) -> AnalysisResult:
    code = probe["status_code"]
    meta = {
        "code": code, 
        "timings": probe["timings"], 
        "version": probe["http_version"]
    }
    
    # 1. Critical Errors
    if probe["error"]:
        err = probe["error"]
        if "Timeout" in err or "TimeOut" in err:
            return _res(Severity.CRITICAL, "HTTP_TIMEOUT", 
                       f"Request timed out: {err}", meta, ["Check firewall", "Check upstream"])
        return _res(Severity.CRITICAL, "HTTP_CONNECT_FAIL", 
                   f"Connection failed: {err}", meta, ["Check server status", "Check network"])
                   
    if code == 0:
        return _res(Severity.CRITICAL, "HTTP_CONNECT_FAIL", "Connection returned status 0.", meta)

    # 2. Redirects
    # Spec: >5 hops -> HTTP_REDIRECT (WARNING)
    # Actually, redirect chain tracking in probe_http is currently limited by curl logic unless we parse headers extensively.
    # But if code is 3xx, it means we stopped at a redirect (or loop limit).
    # Since we use curl -L, we follow redirects. If we ended up at 3xx, loop detected or max reached.
    # If probe['redirect_chain'] is populated (stubbed currently), we'd check length.
    # We can check if code is 3xx after curl -L, it usually means limit reached.
    if code in [301, 302, 303, 307, 308]:
         return _res(Severity.WARNING, "HTTP_REDIRECT", "Redirect limit reached or loop detected.", meta,
                    ["Check for redirect loops"])

    # 3. Rate Limits
    if code == 429:
        return _res(Severity.INFO, "HTTP_RATE_LIMIT", "Rate Limited (HTTP 429).", meta)

    # 4. WAF - But prioritize 200 OK
    # If code is 200, it is PASS, even if WAF headers exist (passive mode or passed challenge)
    if 200 <= code < 400:
        return _res(Severity.PASS, "HTTP_PASS", f"HTTP {code} OK.", meta)

    # If not 200, check WAF
    if probe["is_waf_challenge"]:
        return _res(Severity.INFO, "HTTP_WAF_BLOCK", "Request challenged/blocked by WAF.", meta,
                   ["Check WAF rules if this is unexpected", "Allowlist test IP"])
    
    # 5. Client Errors
    if 400 <= code < 500:
        return _res(Severity.WARNING, "HTTP_CLIENT_ERROR", f"Client Error (HTTP {code}).", meta,
                   ["Check URL path", "Check permissions"])
                   
    # 6. Server Errors
    if 500 <= code < 600:
        return _res(Severity.ERROR, "HTTP_SERVER_ERROR", f"Server Error (HTTP {code}).", meta,
                   ["Check server logs", "Check upstream"])

    return _res(Severity.WARNING, "UNKNOWN", f"Unexpected status: {code}", meta)

def analyze_tls(probe: ProbeTLSResult) -> AnalysisResult:
    meta = {
        "version": probe["protocol_version"], 
        "expiry": probe["cert_expiry"],
        "cipher": probe["cipher"]
    }
    
    if not probe["handshake_success"]:
        return _res(Severity.CRITICAL, "TLS_FAIL_HANDSHAKE", 
                   f"TLS Handshake Failed: {probe['error']}", meta,
                   ["Check SSL configuration", "Check port 443 connectivity"])
                   
    # Check Expiry explicitly for TLS_EXPIRED
    # probe['cert_expiry'] is string e.g. "May 20 12:00:00 2025 GMT" (from Python ssl lib default)
    # We need parsing to compare dates. For robustness without strict date parsing dep here,
    # we rely on 'cert_valid' which Python SSL lib sets to False if expired.
    # But spec wants TLS_EXPIRED vs TLS_WARN_CERT_INVALID.
    # We can check verification errors string for "expired".
    
    if not probe["cert_valid"]:
        errors = "; ".join(probe["verification_errors"]).lower()
        if "expired" in errors or "not yet valid" in errors:
             return _res(Severity.ERROR, "TLS_EXPIRED", 
                   f"Certificate Expired/Not Valid: {errors}", meta,
                   ["Renew certificate"])
        
        return _res(Severity.ERROR, "TLS_WARN_CERT_INVALID", 
                   f"Certificate Invalid: {errors}", meta,
                   ["Renew certificate", "Fix chain of trust"])
                   
    if probe["protocol_version"] and probe["protocol_version"] < "TLSv1.2":
        return _res(Severity.WARNING, "TLS_OLD_PROTOCOL", 
                   f"Deprecated Protocol: {probe['protocol_version']}", meta,
                   ["Upgrade to TLS 1.2 or 1.3"])
                   
    return _res(Severity.PASS, "TLS_PASS", "TLS Handshake Success.", meta)

def analyze_mtu(probe: ProbeMTUResult) -> AnalysisResult:
    mtu = probe["path_mtu"]
    meta = {"mtu": mtu, "lost": probe["packets_lost"]}
    
    if mtu == 0:
        # If all lost, we treat as Warning/Fail depending on context, spec says MTU_PASS if >= 1500
        # If 0, it means blocked.
        return _res(Severity.WARNING, "MTU_WARNING", "Could not determine MTU (ICMP blocked?).", meta)
        
    if mtu < 1280:
        return _res(Severity.CRITICAL, "MTU_CRITICAL", f"Path MTU {mtu} < 1280 (IPv6 Min).", meta,
                   ["Check VPN/Tunnels", "Fix fragmentation issues"])
                   
    if mtu < 1500:
        return _res(Severity.WARNING, "MTU_WARNING", f"Path MTU {mtu} < 1500.", meta,
                   ["Check for MSS clamping", "Check overhead"])
                   
    return _res(Severity.PASS, "MTU_PASS", "MTU 1500 OK.", meta)

def analyze_origin_reachability(edge: ProbeHTTPResult, origin: ProbeHTTPResult) -> AnalysisResult:
    meta = {
        "edge_code": edge["status_code"],
        "origin_code": origin["status_code"]
    }
    
    origin_ok = 200 <= origin["status_code"] < 400
    edge_cf_error = edge["status_code"] in [502, 504, 521, 522, 523, 524]
    
    # 1. Origin completely down/unreachable
    if origin["error"] or origin["status_code"] == 0:
        err = origin["error"] or ""
        if "Timeout" in err:
             return _res(Severity.ERROR, "ORIGIN_522", "Origin Timed Out (Direct).", meta,
                        ["Check Origin Firewall", "Verify Origin IP is correct"])
        return _res(Severity.CRITICAL, "ORIGIN_UNREACHABLE", f"Origin Unreachable: {err}", meta)

    # 2. Origin OK, but Edge 522/etc -> Firewall or config issue
    if edge_cf_error and origin_ok:
        return _res(Severity.WARNING, "ORIGIN_FIREWALL_BLOCK", 
                   "Origin is UP, but Cloudflare cannot reach it (Firewall likely).", meta,
                   ["Whitelist Cloudflare IPs"])
                   
    # 3. Both OK
    if origin_ok and 200 <= edge["status_code"] < 400:
         return _res(Severity.PASS, "ORIGIN_REACHABLE", "Origin and Edge both reachable.", meta)

    # 4. Fallback (e.g. Origin 500, Edge 500 -> both failing)
    return _res(Severity.INFO, "ORIGIN_REACHABLE", "Status match (non-success).", meta)
