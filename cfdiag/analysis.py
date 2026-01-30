from typing import List, Optional, Any
from datetime import datetime
from .types import (
    ProbeDNSResult, ProbeHTTPResult, ProbeTLSResult, ProbeMTUResult, 
    ProbeOriginResult, ProbeASNResult, ProbeCDNReachabilityResult, AnalysisResult, Severity
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

    if probe["dnssec_valid"] is False:
        return _res(Severity.ERROR, "DNS_DNSSEC_FAIL", "DNSSEC Validation Failed.", meta,
                   ["Check DS record configuration", "Check DNSKEY signing"])

    has_a = len(probe["records"]["A"]) > 0
    has_aaaa = len(probe["records"]["AAAA"]) > 0
    
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
    if code in [301, 302, 303, 307, 308]:
         return _res(Severity.WARN, "HTTP_REDIRECT", "Redirect limit reached or loop detected.", meta,
                    ["Check for redirect loops"])

    # 3. Rate Limits
    if code == 429:
        return _res(Severity.INFO, "HTTP_RATE_LIMIT", "Rate Limited (HTTP 429).", meta)

    # 4. WAF - But prioritize 200 OK
    if 200 <= code < 400:
        return _res(Severity.PASS, "HTTP_PASS", f"HTTP {code} OK.", meta)

    if probe["is_waf_challenge"]:
        return _res(Severity.INFO, "HTTP_WAF_BLOCK", "Request challenged/blocked by WAF.", meta,
                   ["Check WAF rules if this is unexpected", "Allowlist test IP"])
    
    # 5. Client Errors
    if 400 <= code < 500:
        return _res(Severity.WARN, "HTTP_CLIENT_ERROR", f"Client Error (HTTP {code}).", meta,
                   ["Check URL path", "Check permissions"])
                   
    # 6. Server Errors
    if 500 <= code < 600:
        return _res(Severity.ERROR, "HTTP_SERVER_ERROR", f"Server Error (HTTP {code}).", meta,
                   ["Check server logs", "Check upstream"])

    return _res(Severity.WARN, "UNKNOWN", f"Unexpected status: {code}", meta)

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
                   
    if not probe["cert_valid"]:
        errors = "; ".join(probe["verification_errors"]).lower()
        if "expired" in errors or "not yet valid" in errors:
             return _res(Severity.ERROR, "TLS_EXPIRED", 
                   f"Certificate Expired/Not Valid: {errors}", meta,
                   ["Renew certificate"])
        if "mismatch" in errors or "hostname" in errors:
             return _res(Severity.ERROR, "TLS_WARN_HOST_MISMATCH",
                   f"Hostname Mismatch: {errors}", meta,
                   ["Ensure certificate SANs match the domain"])
        return _res(Severity.ERROR, "TLS_WARN_CERT_INVALID", 
                   f"Certificate Invalid: {errors}", meta,
                   ["Renew certificate", "Fix chain of trust"])
                   
    if probe["protocol_version"] and probe["protocol_version"] < "TLSv1.2":
        return _res(Severity.WARN, "TLS_OLD_PROTOCOL", 
                   f"Deprecated Protocol: {probe['protocol_version']}", meta,
                   ["Upgrade to TLS 1.2 or 1.3"])
                   
    return _res(Severity.PASS, "TLS_PASS", "TLS Handshake Success.", meta)

def analyze_mtu(probe: ProbeMTUResult) -> AnalysisResult:
    mtu = probe["path_mtu"]
    meta = {"mtu": mtu, "lost": probe["packets_lost"]}
    
    if mtu == 0:
        return _res(Severity.WARN, "MTU_WARNING", "Could not determine MTU (ICMP blocked?).", meta)
        
    if mtu < 1280:
        return _res(Severity.CRITICAL, "MTU_CRITICAL", f"Path MTU {mtu} < 1280 (IPv6 Min).", meta,
                   ["Check VPN/Tunnels", "Fix fragmentation issues"])
                   
    if mtu < 1500:
        return _res(Severity.WARN, "MTU_WARNING", f"Path MTU {mtu} < 1500.", meta,
                   ["Check for MSS clamping", "Check overhead"])
                   
    return _res(Severity.PASS, "MTU_PASS", "MTU 1500 OK.", meta)

def analyze_origin_reachability(edge: ProbeHTTPResult, origin: ProbeHTTPResult) -> AnalysisResult:
    meta = {
        "edge_code": edge["status_code"],
        "origin_code": origin["status_code"]
    }
    
    origin_ok = 200 <= origin["status_code"] < 400
    edge_cf_error = edge["status_code"] in [502, 504, 521, 522, 523, 524]
    
    if origin["error"] or origin["status_code"] == 0:
        err = origin["error"] or ""
        if "Timeout" in err:
             return _res(Severity.ERROR, "ORIGIN_522", "Origin Timed Out (Direct).", meta,
                        ["Check Origin Firewall", "Verify Origin IP is correct"])
        return _res(Severity.CRITICAL, "ORIGIN_UNREACHABLE", f"Origin Unreachable: {err}", meta)

    if edge_cf_error and origin_ok:
        return _res(Severity.WARN, "ORIGIN_FIREWALL_BLOCK", 
                   "Origin is UP, but Cloudflare cannot reach it (Firewall likely).", meta,
                   ["Whitelist Cloudflare IPs"])
                   
    if origin_ok and 200 <= edge["status_code"] < 400:
         return _res(Severity.PASS, "ORIGIN_REACHABLE", "Origin and Edge both reachable.", meta)

    return _res(Severity.INFO, "ORIGIN_REACHABLE", "Status match (non-success).", meta)

def analyze_asn(probe: ProbeASNResult) -> AnalysisResult:
    meta = {"asn": probe["asn"], "country": probe["country"]}
    
    if probe["error"]:
        return _res(Severity.WARN, "ASN_LOOKUP_FAIL", f"ASN Lookup failed: {probe['error']}", meta)
        
    if probe["asn"]:
        return _res(Severity.PASS, "ASN_FOUND", f"AS{probe['asn']} ({probe['country']})", meta)
        
    return _res(Severity.INFO, "ASN_NOT_FOUND", "No ASN info found.", meta)

def analyze_cdn_reachability(probe: ProbeCDNReachabilityResult) -> AnalysisResult:
    edge = probe.get("edge", {})
    origin = probe.get("origin")
    meta = {"confidence": "Low", "signals": [], "limitations": "CDN internal state not verified"}
    signals = []
    
    # Requirement 2: Null/Type Safety for HTTP Headers
    # Ensure edge is a dict and has status_code
    if not isinstance(edge, dict):
        edge = {"status_code": 0, "headers": {}}
        
    edge_code = edge.get("status_code", 0)
    raw_headers = edge.get("headers")
    # Normalize with safe fallback: (headers or {})
    edge_headers = {k.lower(): v for k, v in (raw_headers or {}).items()}
    
    # 1. Identify CDN presence (Focus on Cloudflare as primary example, but generic signals too)
    server = edge_headers.get("server", "").lower()
    is_cloudflare = "cloudflare" in server or "cf-ray" in edge_headers
    
    # 2. Check for 52x/504 signals on Edge
    if edge_code in [520, 521, 522, 523, 524, 525, 526, 527, 530, 504]:
        signals.append(f"Edge returned HTTP {edge_code} (Timeout/Connection Error)")
        meta["confidence"] = "Medium"
        
        reason = f"Possible CDN → origin connectivity issue detected (HTTP {edge_code})."
        recs = [
            "Check firewall/allowlist (Origin might be blocking CDN IPs)",
            "Check if Origin web server is running and reachable",
            "Verify Origin IP in CDN DNS settings"
        ]
        
        if edge_code == 522:
            reason += " (Connection Timed Out)"
        elif edge_code == 521:
            reason += " (Web Server Is Down)"
        elif edge_code == 525:
            reason += " (SSL Handshake Failed)"
            recs.append("Check Origin SSL certificate validity/configuration")
            
        if origin:
            # Requirement 8: Avoid duplication & Requirement 4: Origin Reachability Logic
            origin_code = origin.get("status_code")
            origin_error = origin.get("error")
            origin_reachable = not ((origin_code is None or origin_code == 0) or origin_error)

            if origin_reachable and 200 <= origin_code < 400:
                signals.append(f"Origin is reachable directly (HTTP {origin_code})")
                meta["confidence"] = "High"
                reason = "High Confidence: CDN → Origin connectivity issue. Origin is UP but CDN is failing."
            elif not origin_reachable:
                 signals.append("Origin also unreachable directly")
                 reason = "Both CDN and Direct Origin are unreachable."
        
        meta["signals"] = signals
        # Requirement 5: Max severity WARN
        return _res(Severity.WARN, "CDN_ORIGIN_ISSUE", reason, meta, recs)

    # 3. Compare Edge vs Origin (if Origin available)
    if origin:
        # Requirement 8 & 4 again
        origin_code = origin.get("status_code")
        origin_error = origin.get("error")
        is_origin_unreachable = (origin_code is None or origin_code == 0) or bool(origin_error)
        edge_ok = 200 <= edge_code < 400
        
        if edge_ok and is_origin_unreachable:
             # Requirement 3: Edge OK / Origin Unreachable Ambiguity
             signals.append("Edge is UP, but Direct Origin is unreachable from this client.")
             
             cf_cache = edge_headers.get("cf-cache-status", "")
             if cf_cache in ["hit", "stale"]:
                  signals.append(f"Edge response was CACHED ({cf_cache}).")
             
             meta["signals"] = signals
             # Requirement 3: Explicit messaging mentioning both possibilities
             reason = (
                 "Edge is serving content successfully, but direct origin access failed. "
                 "The origin may be intentionally restricted to CDN IPs (common), "
                 "or it could be down/unreachable."
             )
             # Requirement 5: Severity Guarantee (INFO)
             return _res(Severity.INFO, "CDN_EDGE_OK_ORIGIN_AMBIGUOUS", reason, meta)
    
    # 4. Header consistency
    if is_cloudflare:
        required_headers = ["cf-ray"]
        missing = [h for h in required_headers if h not in edge_headers]
        if missing:
            signals.append(f"Expected CDN headers missing: {', '.join(missing)}")
            return _res(Severity.INFO, "CDN_HEADER_MISSING", 
                "CDN headers missing despite Server: Cloudflare.", 
                {**meta, "signals": signals})

    if signals:
         meta["signals"] = signals
         return _res(Severity.INFO, "CDN_SIGNALS", "Detected signals of interest.", meta)

    return _res(Severity.PASS, "CDN_OK", "No significant CDN-Origin reachability issues detected.", meta)
        
    