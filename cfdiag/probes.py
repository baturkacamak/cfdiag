import socket
import ssl
import subprocess
import shutil
import sys
import re
import platform
import time
from typing import List, Dict, Tuple, Optional, Any, Union
from datetime import datetime

from .types import (
    ProbeDNSResult, ProbeHTTPResult, ProbeTLSResult, ProbeMTUResult, ProbeOriginResult
)

def _run_cmd(cmd: str, timeout: int = 10) -> Tuple[int, str, str]:
    try:
        proc = subprocess.Popen(
            cmd, 
            shell=True, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            text=True
        )
        stdout, stderr = proc.communicate(timeout=timeout)
        return proc.returncode, stdout, stderr
    except subprocess.TimeoutExpired:
        proc.kill()
        return -1, "", "Timeout"
    except Exception as e:
        return -1, "", str(e)

def probe_dns(domain: str) -> ProbeDNSResult:
    records: Dict[str, List[str]] = {"A": [], "AAAA": [], "CNAME": [], "NS": []}
    error = None
    raw = ""
    
    try:
        # 1. Basic Resolution (A/AAAA) via socket
        info = socket.getaddrinfo(domain, 443, proto=socket.IPPROTO_TCP)
        seen = set()
        for _, family, _, _, sockaddr in info:
            ip = sockaddr[0]
            if ip in seen: continue
            seen.add(ip)
            if ':' in ip: records["AAAA"].append(ip)
            else: records["A"].append(ip)
        
        raw = f"Resolved: {records}"
    except socket.gaierror as e:
        error = str(e)
        raw = str(e)
    except Exception as e:
        error = f"Unexpected: {e}"
        raw = str(e)

    # 2. Try Dig for DNSSEC/CNAME if available
    dnssec_valid = None
    if shutil.which("dig"):
        # Check DNSSEC
        code, out, _ = _run_cmd(f"dig +short +dnssec {domain}")
        if "RRSIG" in out:
            dnssec_valid = True
        elif out.strip():
            dnssec_valid = False # Got answer but no RRSIG
            
    return {
        "domain": domain,
        "records": records,
        "resolvers_used": [], # System resolver
        "dnssec_valid": dnssec_valid,
        "raw_output": raw,
        "error": error
    }

def probe_http(url: str, timeout: int = 10, resolve: Optional[Dict[str, str]] = None) -> ProbeHTTPResult:
    if not url.startswith("http"):
        url = f"https://{url}"

    fmt = (
        "code=%{http_code};;"
        "ver=%{http_version};;"
        "dns=%{time_namelookup};;"
        "conn=%{time_connect};;"
        "ttfb=%{time_starttransfer};;"
        "total=%{time_total}"
    )
    
    cmd_parts = ["curl", "-i", "-s", "-L", "--max-time", str(timeout), "-w", f"\"{fmt}\"" ]
    
    if resolve:
        for domain, ip in resolve.items():
            cmd_parts.extend(["--resolve", f"{domain}:443:{ip}"])
            cmd_parts.extend(["--resolve", f"{domain}:80:{ip}"])
    
    cmd_parts.append(f"'{url}'")
    cmd = " ".join(cmd_parts)
    
    code, stdout, stderr = _run_cmd(cmd, timeout=timeout + 2)
    
    result: ProbeHTTPResult = {
        "url": url,
        "status_code": 0,
        "headers": {},
        "redirect_chain": [],
        "timings": {"connect": 0.0, "ttfb": 0.0, "total": 0.0, "namelookup": 0.0},
        "body_snippet": "",
        "is_waf_challenge": False,
        "http_version": "",
        "error": None
    }
    
    if code != 0:
        # Curl exit codes: 28 = Timeout, 7 = Connect fail, 35 = SSL connect error
        if code == 28:
            result["error"] = "ReadTimeout"
        elif code == 7:
            result["error"] = "ConnectionRefused" 
        elif code == 35:
            result["error"] = "SSLConnectError"
        else:
            result["error"] = f"Curl failed (code {code}): {stderr or 'Unknown'}"
        return result
        
    metrics_pattern = r"code=(\\d+);;ver=(.*?);;dns=([\\d\\.]+);;conn=([\\d\\.]+);;ttfb=([\\d\\.]+);;total=([\\d\\.]+)"
    match = re.search(metrics_pattern, stdout)
    
    content = stdout
    if match:
        result["status_code"] = int(match.group(1))
        result["http_version"] = match.group(2)
        try:
            result["timings"]["namelookup"] = float(match.group(3))
            result["timings"]["connect"] = float(match.group(4))
            result["timings"]["ttfb"] = float(match.group(5))
            result["timings"]["total"] = float(match.group(6))
        except ValueError: pass
        content = stdout[:match.start()]
    else:
        # If no match, maybe curl failed silently or format mismatch
        if not result["error"]:
            result["error"] = "Metrics parsing failed"

    # Parse Headers & Body
    parts = content.split("\r\n\r\n")
    header_blocks = [p for p in parts if p.strip().startswith("HTTP/")]
    body_parts = [p for p in parts if not p.strip().startswith("HTTP/") and p.strip()]
    
    if header_blocks:
        last_headers = header_blocks[-1].splitlines()
        for line in last_headers[1:]:
            if ':' in line:
                k, v = line.split(':', 1)
                result["headers"][k.strip().lower()] = v.strip()

    if body_parts:
        result["body_snippet"] = body_parts[-1][:1024]
        
    # WAF Logic
    server = result["headers"].get("server", "").lower()
    is_cloudflare = "cloudflare" in server
    cf_headers = any(k.startswith("cf-") for k in result["headers"].keys())
    
    waf_sigs = ["captcha", "challenge", "attention required", "security check", "please turn javascript on"]
    body_lower = result["body_snippet"].lower()
    
    # 503 is common for CF Interstitial (Under Attack Mode)
    if (result["status_code"] in [403, 401, 429, 503]) and (is_cloudflare or cf_headers):
        if any(sig in body_lower for sig in waf_sigs) or "cf-mitigated" in result["headers"]:
            result["is_waf_challenge"] = True

    return result

def probe_tls(domain: str, port: int = 443, timeout: int = 5, keylog_file: Optional[str] = None) -> ProbeTLSResult:
    context = ssl.create_default_context()
    if keylog_file:
        context.keylog_filename = keylog_file # type: ignore
        
    result: ProbeTLSResult = {
        "handshake_success": False,
        "protocol_version": None,
        "cipher": None,
        "cert_valid": False,
        "cert_subject": None,
        "cert_issuer": None,
        "cert_expiry": None,
        "cert_start": None,
        "verification_errors": [],
        "ocsp_stapled": False,
        "error": None
    }
    
    try:
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                result["handshake_success"] = True
                result["cert_valid"] = True
                result["protocol_version"] = ssock.version()
                cipher = ssock.cipher()
                if cipher: result["cipher"] = cipher[0]
                
                cert = ssock.getpeercert()
                if cert:
                    result["cert_expiry"] = cert.get("notAfter")
                    result["cert_start"] = cert.get("notBefore")
                    
                    for item in cert.get("subject", []):
                        for k, v in item:
                            if k == 'commonName': result["cert_subject"] = v
                    for item in cert.get("issuer", []):
                        for k, v in item:
                            if k == 'commonName': result["cert_issuer"] = v

    except ssl.SSLCertVerificationError as e:
        result["handshake_success"] = True
        result["cert_valid"] = False
        result["error"] = str(e)
        result["verification_errors"].append(e.verify_message)
    except Exception as e:
        result["error"] = str(e)

    # CLI fallback for OCSP
    if result["handshake_success"] and shutil.which("openssl"):
        cmd = f"echo Q | openssl s_client -servername {domain} -connect {domain}:{port} -status"
        c, out, _ = _run_cmd(cmd, timeout=5)
        if "OCSP Response Status: successful" in out:
            result["ocsp_stapled"] = True

    return result

def probe_mtu(domain: str) -> ProbeMTUResult:
    sizes = [1500, 1492, 1472, 1400, 1280]
    overhead = 28
    
    passed_mtu = 0
    fail_point = 0
    packets_sent = 0
    packets_lost = 0
    
    system = platform.system().lower()
    
    for mtu in sizes:
        payload = mtu - overhead
        if payload < 0: continue
        
        cmd = ""
        if system == "windows":
            cmd = f"ping -n 1 -f -l {payload} {domain}"
        elif system == "darwin":
             cmd = f"ping -c 1 -D -s {payload} {domain}"
        else:
             cmd = f"ping -c 1 -M do -s {payload} {domain}"
        
        packets_sent += 1
        code, _, _ = _run_cmd(cmd, timeout=2)
        if code == 0:
            if mtu > passed_mtu: passed_mtu = mtu
        else:
            packets_lost += 1
            if fail_point == 0 or mtu < fail_point: fail_point = mtu
            
    return {
        "path_mtu": passed_mtu,
        "fragmentation_point": fail_point if fail_point > 0 else None,
        "packets_sent": packets_sent,
        "packets_lost": packets_lost,
        "error": "All pings failed" if passed_mtu == 0 else None
    }

def probe_origin(domain: str, origin_ip: str) -> ProbeOriginResult:
    edge = probe_http(domain)
    origin = probe_http(domain, resolve={domain: origin_ip})
    
    error = None
    if edge["error"] and origin["error"]:
        error = "Both Edge and Origin probes failed"
        
    return {
        "edge_probe": edge,
        "origin_probe": origin,
        "origin_ip_used": origin_ip,
        "error": error
    }
