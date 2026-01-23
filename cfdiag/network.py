import shutil
import socket
import ssl
import sys
import subprocess
import textwrap
import re
import json
import os
import time
import ipaddress
from typing import Tuple, List, Dict, Optional

import certifi

from .utils import get_curl_flags, PUBLIC_RESOLVERS, DNSBL_LIST, USER_AGENTS, console_lock, Colors, CLOUDFLARE_IPS
from .reporting import (
    get_logger, print_header, print_subheader, print_success, 
    print_fail, print_info, print_warning, print_cmd
)

def check_dependencies() -> None:
    missing = []
    if not shutil.which("curl"): missing.append("curl")
    if not shutil.which("openssl"): missing.append("openssl")
    trace_cmd = "tracert" if os.name == 'nt' else "traceroute"
    if not shutil.which(trace_cmd) and os.name != 'nt' and not os.path.exists("/usr/sbin/traceroute"):
         missing.append("traceroute")
    if missing:
        print(f"Missing required system tools: {', '.join(missing)}")
        sys.exit(1)

def run_command(command: str, timeout: int = 30, show_output: bool = True, log_output_to_file: bool = True) -> Tuple[Optional[int], str]:
    from .utils import get_context
    ctx = get_context()
    if ctx.get('timeout'):
        if timeout == 30:
            timeout = int(ctx.get('timeout'))

    l = get_logger()
    try:
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        output_lines = []
        while True:
            line = process.stdout.readline() # type: ignore
            if not line and process.poll() is not None: break
            if line:
                if show_output and l and l.verbose and not l.silent: 
                    with console_lock:
                        sys.stdout.write(line) 
                output_lines.append(line)
        
        full_output = "".join(output_lines)
        exit_code = process.poll()

        if log_output_to_file and l:
             if full_output.strip():
                 l.log_file("Output:")
                 l.log_file(textwrap.indent(full_output, '    '))
             if exit_code != 0:
                 l.log_file(f"[ERROR] Command failed with exit code {exit_code}")

        return exit_code, full_output
    except Exception as e:
        if l: l.log_file(f"[EXCEPTION] {e}")
        return -1, str(e)

def check_internet_connection() -> bool:
    targets = [("1.1.1.1", 53), ("8.8.8.8", 53)]
    for host, port in targets:
        try:
            with socket.create_connection((host, port), timeout=3): return True
        except: continue
    return False

def _ip_in_cidr_ranges(ip: str, ranges: List[str]) -> bool:
    """
    Check if a given IP address (v4 or v6) falls within any CIDR range in `ranges`.
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return False
    
    for cidr in ranges:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if ip_obj in network:
            return True
    return False

def detect_cloudflare_usage(domain: str, ipv4: List[str], ipv6: List[str]) -> bool:
    """
    Determine whether the target is using Cloudflare based on:
      1) Resolved A/AAAA records falling into known Cloudflare IP ranges.
      2) NS records containing 'cloudflare.com'.
    """
    # 1. IP range check (A/AAAA records)
    for ip in ipv4 + ipv6:
        # Skip obvious private / loopback ranges – they are never Cloudflare edges.
        if ip.startswith(("192.168.", "10.", "127.", "::1")):
            continue
        if _ip_in_cidr_ranges(ip, CLOUDFLARE_IPS):
            return True

    # 2. NS record check for "cloudflare.com"
    ns_output = ""
    cmd = ""
    if shutil.which("dig"):
        cmd = f"dig NS {domain} +short"
    elif os.name == 'nt':
        cmd = f"nslookup -type=NS {domain}"

    if cmd:
        code, out = run_command(cmd, show_output=False, log_output_to_file=True)
        if code == 0:
            ns_output = out.lower()

    if "cloudflare.com" in ns_output:
        return True

    return False

def step_dns(domain: str) -> Tuple[bool, List[str], List[str]]:
    print_subheader("1. DNS Resolution & ASN/ISP Check")
    ips: List[str] = []
    ipv4: List[str] = []
    ipv6: List[str] = []
    
    from .utils import get_context
    ctx = get_context()
    family = socket.AF_UNSPEC
    if ctx.get('ipv4'): family = socket.AF_INET
    if ctx.get('ipv6'): family = socket.AF_INET6
    
    print_cmd(f"socket.getaddrinfo('{domain}', 443, family={family})")
    l = get_logger()
    try:
        info = socket.getaddrinfo(domain, 443, family=family, proto=socket.IPPROTO_TCP)
        for _, _, _, _, sockaddr in info:
            ip = sockaddr[0]
            if ip not in ips:
                ips.append(ip)
                (ipv6 if ':' in ip else ipv4).append(ip)
        
        if l: l.log_file(f"Output:\n    IPv4: {ipv4}\n    IPv6: {ipv6}")
        
        if ipv4: print_success(f"IPv4 Resolved: {Colors.WHITE}{', '.join(ipv4)}{Colors.ENDC}")
        else: 
            if ctx.get('ipv6'): pass
            else: print_warning("No IPv4 records found.")
            
        if ipv6: print_success(f"IPv6 Resolved: {Colors.WHITE}{', '.join(ipv6)}{Colors.ENDC}")
        else: 
            if ctx.get('ipv4'): pass
            else: print_info("No IPv6 records found.")
        
        if not ips:
            print_fail("DNS returned empty result.")
            return False, [], []

        target_ip = ipv4[0] if ipv4 else (ipv6[0] if ipv6 else None)
        if target_ip and not target_ip.startswith(("192.168.", "10.", "127.", "::1")):
            if '.' in target_ip:
                rev_ip = '.'.join(reversed(target_ip.split('.')))
                cmd = f"dig +short -t TXT {rev_ip}.origin.asn.cymru.com"
                c, out = run_command(cmd, show_output=False, log_output_to_file=True)
                if c == 0 and out.strip():
                    parts = out.replace('"', '').split('|')
                    if len(parts) >= 3:
                        asn = parts[0].strip()
                        country = parts[2].strip()
                        print_success(f"ASN Info: {Colors.WHITE}AS{asn} ({country}){Colors.ENDC}")
                        if l: l.log_file(f"ASN: AS{asn}, {country}")
            
        if l: l.add_html_step("DNS", "PASS" if ips else "FAIL", f"IPv4: {ipv4}\nIPv6: {ipv6}")
        return True, ipv4, ipv6
    except Exception as e:
        print_fail(f"DNS resolution failed: {e}")
        if l: l.add_html_step("DNS", "FAIL", str(e))
        return False, [], []

def step_doh(domain: str) -> bool:
    print_subheader("1.5 DNS-over-HTTPS (DoH) Check")
    l = get_logger()
    url = f"https://cloudflare-dns.com/dns-query?name={domain}&type=A"
    cmd = f'curl -s -H "Accept: application/dns-json" "{url}"'
    c, out = run_command(cmd, show_output=False, log_output_to_file=True)
    
    if c == 0:
        try:
            data = json.loads(out)
            if data.get('Status') == 0:
                answers = data.get('Answer', [])
                ips = [a['data'] for a in answers if a['type'] == 1]
                if ips:
                    print_success(f"DoH Resolution: {', '.join(ips)}")
                    if l: l.add_html_step("DoH", "PASS", f"IPs: {ips}")
                    return True
        except: pass
    
    print_warning("DoH Resolution Failed.")
    if l: l.add_html_step("DoH", "FAIL", "Failed")
    return False

def step_blacklist(domain: str, ip: str) -> None:
    print_subheader("2. Blacklist/Reputation Check (DNSBL)")
    if not ip: return
    l = get_logger()
    try:
        if ':' in ip: return
        rev_ip = '.'.join(reversed(ip.split('.')))
        listed = False
        details = ""
        for name, dnsbl in DNSBL_LIST:
            query = f"{rev_ip}.{dnsbl}"
            try:
                socket.gethostbyname(query)
                print_fail(f"Listed on {name}!")
                details += f"Listed on {name}\n"
                listed = True
            except: 
                details += f"Clean on {name}\n"
        if l: l.add_html_step("Blacklist Check", "FAIL" if listed else "PASS", details)
    except Exception as e:
        print_warning(f"Blacklist check failed: {e}")

def step_dns_trace(domain: str) -> None:
    print_subheader("3. Recursive DNS Trace")
    if not shutil.which("dig"): return
    
    from .utils import get_context
    ctx = get_context()
    flags = ""
    if ctx.get('ipv4'): flags += " -4"
    if ctx.get('ipv6'): flags += " -6"
    
    c, out = run_command(f"dig +trace{flags} {domain}", timeout=15, log_output_to_file=True)
    status = "PASS" if c==0 and "NOERROR" in out else "WARN"
    l = get_logger()
    if l: l.add_html_step("DNS Trace", status, out)

def step_propagation(domain: str, expected_ns: str) -> str:
    print_subheader(f"4. Global Propagation Check")
    if not shutil.which("dig") and os.name != 'nt': return "ERROR"
    matches = 0
    details = ""
    l = get_logger()
    if l: l.log_file(f"Target Nameserver Substring: {expected_ns}")

    for name, ip in PUBLIC_RESOLVERS:
        if shutil.which("dig"): cmd = f"dig @{ip} NS {domain} +short"
        elif os.name == 'nt': cmd = f"nslookup -type=NS {domain} {ip}"
        else: continue
        c, out = run_command(cmd, show_output=False)
        found = expected_ns.lower() in out.lower()
        if found: matches += 1
        res_str = "MATCH" if found else "MISMATCH"
        print_info(f"{name}: {res_str}")
        details += f"{name}: {res_str}\n"
    
    status = "MATCH" if matches == len(PUBLIC_RESOLVERS) else "PARTIAL"
    if l: l.add_html_step("Propagation", status, details)
    return status

def step_dnssec(domain: str) -> Optional[str]:
    print_subheader("5. DNSSEC Validation")
    if not shutil.which("dig"): return None
    c, out = run_command(f"dig DS {domain} +short", log_output_to_file=True)
    if not out.strip(): return "DISABLED"
    c, out = run_command(f"dig A {domain} +dnssec +short", log_output_to_file=True)
    status = "SIGNED" if "RRSIG" in out else "BROKEN"
    l = get_logger()
    if l: l.add_html_step("DNSSEC", "PASS" if status=="SIGNED" else "FAIL", f"Status: {status}")
    return status

def step_domain_status(domain: str) -> None:
    print_subheader("6. Domain Registration Status (RDAP)")
    flags = get_curl_flags()
    code, output = run_command(f"curl{flags} -s --connect-timeout 5 https://rdap.org/domain/{domain}", show_output=False)
    detail = ""
    if code == 0:
        try:
            data = json.loads(output)
            statuses = [s for s in data.get("status", []) if "transfer" not in s]
            if statuses: 
                print_success(f"Status: {', '.join(statuses)}")
                detail += f"Status: {statuses}\n"
            for event in data.get("events", []):
                if event.get("eventAction") == "expiration":
                    print_success(f"Expires: {event.get('eventDate')}")
                    detail += f"Expires: {event.get('eventDate')}"
                    break
        except: pass
    l = get_logger()
    if l: l.add_html_step("RDAP", "INFO", detail)

def step_http(domain: str) -> Tuple[str, int, bool, Dict[str, float]]:
    print_subheader("7. HTTP/HTTPS Availability")
    fmt = "code=%{http_code};;connect=%{time_connect};;start=%{time_starttransfer};;total=%{time_total}"
    flags = get_curl_flags()
    # Use -I for headers but also fetch body for WAF detection
    cmd = f"curl{flags} -I -w \"{fmt}\" --connect-timeout 10 https://{domain}"
    print_cmd(cmd)
    
    code, output = run_command(cmd, log_output_to_file=True)
    
    # Also fetch body for WAF detection (separate request)
    body_cmd = f"curl{flags} -s --connect-timeout 10 --max-time 5 https://{domain}"
    body_code, body_output = run_command(body_cmd, show_output=False, log_output_to_file=False)
    
    # HTTP status code from server (0 means "not set"/unknown).
    status = 0
    waf = False
    waf_name: Optional[str] = None
    waf_reason = ""
    # Always provide a metrics dictionary with required keys to avoid template crashes.
    metrics: Dict[str, float] = {
        "connect": 0.0,
        "start": 0.0,
        "total": 0.0,
        "ttfb": 0.0,
    }
    
    error_label: Optional[str] = None
    headers: Dict[str, str] = {}
    
    if code == 0:
        # Curl completed; try to parse the metrics trailer.
        lines = output.splitlines()
        metrics_line = ""
        for l in reversed(lines):
            if l.startswith("code="):
                metrics_line = l
                break
        
        # Parse headers from output (skip HTTP status line and metrics line)
        for line in lines:
            if ':' in line and not line.startswith("HTTP/") and not line.startswith("code="):
                k, v = line.split(':', 1)
                headers[k.strip()] = v.strip()
        
        if metrics_line:
            try:
                parts = dict(p.split('=') for p in metrics_line.split(';;'))
                status = int(parts.get('code', 0))  # type: ignore
                # Update metrics but keep all required keys present.
                parsed_metrics = {k: float(v) for k, v in parts.items() if k != 'code'}
                metrics.update(parsed_metrics)
            except Exception:
                # Metrics parsing failed; keep defaults but mark as error.
                error_label = "MetricsParseError"
        
        # Perform WAF detection using headers and body
        body_text = body_output if body_code == 0 else ""
        waf_detected, waf_name, waf_reason = detect_waf_from_response(status, headers, body_text)
        waf = waf_detected
        # Store waf_name and waf_reason for later use in status reporting
    else:
        # Non-zero curl exit code. Derive a human-friendly error label.
        lower_out = output.lower()
        if code == 28 or "timed out" in lower_out:
            error_label = "ConnectTimeout"
        elif "connection refused" in lower_out:
            error_label = "ConnectionError"
        elif "ssl" in lower_out or "certificate" in lower_out:
            error_label = "SSLError"
        else:
            error_label = f"CurlError({code})"
        # Use a dedicated sentinel status code instead of 0.
        status = -1
    
    l = get_logger()
    # Determine high-level status string and detailed status line for reporting.
    if error_label:
        status_str = "FAIL"
        status_line = f"Status: ERROR ({error_label})"
    elif waf and waf_name:
        # WAF detected (regardless of status code)
        status_str = "FAIL" if status >= 400 else "WARN"
        if status in [403, 406]:
            status_line = f"Status: {status} Forbidden (WAF Detected: {waf_name})"
        else:
            status_line = f"Status: {status} (WAF Detected: {waf_name})"
    elif status in [403, 406]:
        if waf_reason == "Unconfirmed (No WAF signatures found)":
            status_str = "FAIL"
            status_line = f"Status: {status} Forbidden (Server Config / Access Denied)"
        else:
            status_str = "FAIL"
            status_line = f"Status: {status} Forbidden"
    else:
        status_str = "PASS" if 200 <= status < 400 else "FAIL"
        status_line = f"Status: {status}"
    
    if l:
        l.add_html_step("HTTP", status_str, f"{status_line}\nMetrics: {metrics}")
    
    if not error_label and 200 <= status < 400:
        print_success(f"Response: {Colors.WHITE}HTTP {status}{Colors.ENDC}")
    elif not error_label and status >= 400:
        if waf and waf_name:
            print_warning(f"WAF Detected ({waf_name}): HTTP {status}")
        elif waf_reason == "Unconfirmed (No WAF signatures found)":
            print_warning(f"HTTP {status} Forbidden (Server Config / Access Denied - WAF Unconfirmed)")
        elif status < 500:
            print_warning(f"Client Error: HTTP {status}")
        else:
            print_fail(f"Server Error: HTTP {status}")
    elif error_label:
        print_warning(f"HTTP Request Error: {error_label}")
    
    if metrics:
        ttfb_ms = int(metrics.get("ttfb", 0) * 1000)
        conn_ms = int(metrics.get("connect", 0) * 1000)
        print_info(f"Latency: Connect={conn_ms}ms, TTFB={ttfb_ms}ms")
    
    step_cache_headers(output)
    
    res_str = "FAIL"
    if not error_label and 200 <= status < 400:
        res_str = "SUCCESS"
    elif not error_label and 400 <= status < 500:
        res_str = "CLIENT_ERROR"
    elif not error_label and 500 <= status < 600:
        res_str = "SERVER_ERROR"
    elif error_label == "ConnectTimeout":
        res_str = "TIMEOUT"
    elif error_label is not None:
        res_str = "ERROR"
    
    return res_str, status, waf, metrics

def detect_waf_from_response(status_code: int, headers: Dict[str, str], body: str = "") -> Tuple[bool, Optional[str], str]:
    """
    Detect WAF presence from HTTP response headers and body.
    
    Returns:
        Tuple of (is_waf_detected, waf_name_or_none, detection_reason)
    """
    headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
    body_lower = body.lower()
    
    # Known WAF header signatures (key: value patterns or just header keys)
    waf_header_signatures = {
        'cloudflare': [
            ('server', 'cloudflare'),
            ('cf-ray', None),
            ('cf-cache-status', None),
            ('cf-request-id', None),
        ],
        'sucuri': [
            ('x-sucuri-id', None),
            ('x-sucuri-cache', None),
        ],
        'aws': [
            ('x-amzn-requestid', None),
            ('x-amzn-trace-id', None),
            ('server', 'awsalb'),
        ],
        'incapsula': [
            ('x-iinfo', None),
            ('x-cdn', None),
        ],
        'akamai': [
            ('x-akamai-transformed', None),
            ('server', 'akamai'),
        ],
        'fastly': [
            ('x-fastly-request-id', None),
            ('server', 'fastly'),
        ],
        'imperva': [
            ('x-imforwards', None),
            ('x-cdn-srv', None),
        ],
    }
    
    # Known WAF body signatures
    waf_body_signatures = [
        'captcha',
        'challenge',
        'attention required',
        'security check',
        'please turn javascript on',
        'access denied by security policy',
        'cloudflare',
        'sucuri',
        'incapsula',
        'imperva',
    ]
    
    detected_waf = None
    detection_reason = ""
    
    # Check headers for WAF signatures
    for waf_name, sigs in waf_header_signatures.items():
        for key_pattern, value_pattern in sigs:
            header_key_lower = key_pattern.lower()
            if header_key_lower in headers_lower:
                header_value_lower = headers_lower[header_key_lower]
                # If value pattern is specified, check it matches
                if value_pattern is None or value_pattern.lower() in header_value_lower:
                    detected_waf = waf_name.capitalize()
                    detection_reason = f"Header signature: {key_pattern}"
                    return True, detected_waf, detection_reason
    
    # Check body for WAF signatures
    # First check for specific WAF names in body (more specific)
    if 'cloudflare' in body_lower:
        detected_waf = "Cloudflare"
        detection_reason = "Body signature: cloudflare"
        return True, detected_waf, detection_reason
    elif 'sucuri' in body_lower:
        detected_waf = "Sucuri"
        detection_reason = "Body signature: sucuri"
        return True, detected_waf, detection_reason
    elif 'incapsula' in body_lower:
        detected_waf = "Incapsula"
        detection_reason = "Body signature: incapsula"
        return True, detected_waf, detection_reason
    elif 'imperva' in body_lower:
        detected_waf = "Imperva"
        detection_reason = "Body signature: imperva"
        return True, detected_waf, detection_reason
    
    # Then check for generic WAF signatures
    for sig in waf_body_signatures:
        if sig in body_lower and sig not in ['cloudflare', 'sucuri', 'incapsula', 'imperva']:
            detected_waf = "Generic"
            detection_reason = f"Body signature: {sig}"
            return True, detected_waf, detection_reason
    
    # If status is 403/406 but no WAF signatures found, mark as unconfirmed
    if status_code in [403, 406]:
        return False, None, "Unconfirmed (No WAF signatures found)"
    
    return False, None, "None"


def step_cache_headers(http_output: str) -> None:
    headers = {}
    for line in http_output.splitlines():
        if ':' in line:
            k, v = line.split(':', 1)
            headers[k.lower().strip()] = v.strip()
    
    cache_status = headers.get('cf-cache-status', 'MISSING')
    server = headers.get('server', '').lower()
    
    l = get_logger()
    if 'cloudflare' in server:
        if cache_status in ['HIT', 'DYNAMIC', 'BYPASS', 'EXPIRED', 'MISS']:
            print_info(f"Cache Status: {Colors.WHITE}{cache_status}{Colors.ENDC}")
        elif cache_status == 'MISSING':
            print_warning("Cloudflare active but 'cf-cache-status' header missing.")
        
        if l: l.add_html_step("Cache Analysis", "INFO", f"Status: {cache_status}")

def step_security_headers(domain: str) -> None:
    print_subheader("7.5. Security Header Audit")
    flags = get_curl_flags()
    cmd = f"curl{flags} -I --connect-timeout 5 https://{domain}"
    code, output = run_command(cmd, show_output=False, log_output_to_file=True)
    
    headers = {}
    if code == 0:
        for line in output.splitlines():
            if ':' in line:
                k, v = line.split(':', 1)
                headers[k.lower().strip()] = v.strip()
    
    checks = {
        'strict-transport-security': 'HSTS',
        'content-security-policy': 'CSP',
        'x-frame-options': 'X-Frame',
        'x-content-type-options': 'NoSniff',
        'referrer-policy': 'Referrer'
    }
    
    details = ""
    passed = 0
    for header, name in checks.items():
        if header in headers:
            print_success(f"{name}: Found")
            details += f"{name}: PASS\n"
            passed += 1
        else:
            print_warning(f"{name}: Missing")
            details += f"{name}: MISSING\n"
    l = get_logger()
    if l: l.add_html_step("Security Headers", f"{passed}/{len(checks)}", details)

    if 'strict-transport-security' in headers:
        val = headers['strict-transport-security']
        if 'preload' in val and 'includesubdomains' in val and 'max-age=' in val:
            age = int(re.search(r'max-age=(\d+)', val).group(1)) # type: ignore
            if age >= 31536000:
                print_success("HSTS: Ready for Preload.")
    
    if shutil.which("curl"):
        c2, out2 = run_command(f"curl{flags} -s https://hstspreload.org/api/v2/status?domain={domain}", show_output=False)
        if c2 == 0:
            if '"status": "preloaded"' in out2: print_success("HSTS Preload Status: Preloaded")
            elif '"status": "pending"' in out2: print_info("HSTS Preload Status: Pending")

def step_http3_udp(domain: str) -> bool:
    print_subheader("8. HTTP/3 (QUIC) Check")
    l = get_logger()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        sock.sendto(b"PING", (domain, 443))
        print_success("UDP 443 Open.")
        if l: l.add_html_step("HTTP/3", "PASS", "UDP 443 Open")
        return True
    except Exception as e:
        if l: l.add_html_step("HTTP/3", "FAIL", str(e))
        return False

def step_ssl(domain: str) -> bool:
    print_subheader("9. SSL/TLS Check")
    # Use certifi CA bundle explicitly to avoid false negative verification failures.
    context = ssl.create_default_context(cafile=certifi.where())
    
    from .utils import get_context
    ctx = get_context()
    timeout = int(ctx.get('timeout', 5))
    if ctx.get('keylog_file'):
        context.keylog_filename = ctx.get('keylog_file') # type: ignore
        
    l = get_logger()
    try:
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                print_success(f"Expiry: {ssock.getpeercert().get('notAfter')}") # type: ignore
                if l: l.add_html_step("SSL", "PASS", f"Expiry: {ssock.getpeercert().get('notAfter')}") # type: ignore
                return True
    except Exception as e:
        print_fail(f"SSL Failed: {e}")
        if l: l.add_html_step("SSL", "FAIL", str(e))
        return False

def step_ocsp(domain: str) -> None:
    print_subheader("9.5 OCSP Stapling Check")
    if not shutil.which("openssl"): return
    cmd = f"openssl s_client -servername {domain} -connect {domain}:443 -status"
    c, out = run_command(f"echo Q | {cmd}", log_output_to_file=True, show_output=False)
    l = get_logger()
    if c == 0:
        if "OCSP Response Status: successful" in out:
            print_success("OCSP Stapling: Active (Successful Response)")
            if l: l.add_html_step("OCSP Stapling", "PASS", "Active")
        elif "OCSP Response: no response sent" in out:
            print_warning("OCSP Stapling: Not Active")
            if l: l.add_html_step("OCSP Stapling", "WARN", "Not Active")

def step_tcp(domain: str) -> bool:
    print_subheader("10. TCP Connectivity")
    l = get_logger()
    from .utils import get_context
    ctx = get_context()
    timeout = int(ctx.get('timeout', 5))
    try:
        with socket.create_connection((domain, 443), timeout=timeout):
            print_success("Connected.")
            if l: l.add_html_step("TCP", "PASS", "Connected")
            return True
    except Exception as e:
        if l: l.add_html_step("TCP", "FAIL", str(e))
        return False

def step_mtu(domain: str) -> bool:
    # Feature: Real MTU Discovery
    print_subheader("11. MTU Check")
    l = get_logger()
    
    # Determine ping command style
    is_windows = os.name == 'nt'
    
    # Sizes to test (Packet size, not payload. Payload = Size - 28)
    # We set payload size.
    # Max standard MTU 1500. Headers 28. Max payload 1472.
    test_sizes = [1472, 1464, 1452, 1432, 1372, 1272] 
    # Corresponds to MTU: 1500, 1492 (PPPoE), 1480, 1460, 1400, 1300
    
    found_mtu = 0
    
    for size in test_sizes:
        # Construct command
        if is_windows:
            cmd = f"ping -n 1 -f -l {size} {domain}"
        else:
            # Linux/Mac. Mac uses -D for DF? Linux uses -M do.
            if sys.platform == "darwin":
                cmd = f"ping -c 1 -D -s {size} {domain}"
            else:
                cmd = f"ping -c 1 -M do -s {size} {domain}"
        
        c, out = run_command(cmd, show_output=False, log_output_to_file=False)
        
        if c == 0:
            found_mtu = size + 28
            print_success(f"Packet size {size} (MTU {found_mtu}): OK")
            break # Found highest working
        else:
            print_info(f"Packet size {size} (MTU {size+28}): Fragmented/Dropped")
    
    if found_mtu:
        print_success(f"Estimated Max MTU: {found_mtu}")
        if l: l.add_html_step("MTU", "PASS", f"MTU: {found_mtu}")
        return True
    else:
        print_warning("MTU Check failed or blocked.")
        if l: l.add_html_step("MTU", "WARN", "Failed")
        return False

def step_traceroute(domain: str) -> None:
    print_subheader("12. Traceroute")
    cmd = f"tracert -h 15 {domain}" if os.name == 'nt' else f"traceroute -m 15 -w 2 {domain}"
    
    from .utils import get_context
    ctx = get_context()
    flags = ""
    if ctx.get('ipv4'): flags = " -4"
    if ctx.get('ipv6'): flags = " -6"
    
    if "traceroute" in cmd:
        cmd = cmd.replace("traceroute", f"traceroute{flags}")
    
    c, out = run_command(cmd, timeout=60, log_output_to_file=True)
    l = get_logger()
    if l: l.add_html_step("Traceroute", "INFO", out)

def step_cf_trace(domain: str) -> Tuple[bool, Dict[str, str]]:
    print_subheader("13. CF Trace")
    flags = get_curl_flags()
    c, out = run_command(f"curl{flags} -s --connect-timeout 5 https://{domain}/cdn-cgi/trace", log_output_to_file=True)
    if c == 0 and "colo=" in out:
        d = dict(l.split('=', 1) for l in out.splitlines() if '=' in l)
        print_success(f"Edge: {Colors.WHITE}{d.get('colo')} / {d.get('ip')}{Colors.ENDC}")
        return True, d
    print_warning("No CF trace found.")
    return False, {}

def step_cf_forced(domain: str) -> bool:
    print_subheader("14. CF Forced")
    return True

def step_origin(domain: str, ip: str) -> Tuple[bool, str]:
    print_subheader("15. Direct Origin")
    return True, "SUCCESS"

def step_alt_ports(domain: str) -> Tuple[bool, List[int]]:
    print_subheader("16. Alt Ports")
    return False, []

def step_redirects(domain: str) -> None:
    print_subheader("17. Redirect Chain Analysis")
    current_url = f"http://{domain}"
    hops = []
    flags = get_curl_flags()
    
    for i in range(5): 
        hops.append(current_url)
        cmd = f'curl{flags} -I -s -w "%{{redirect_url}}" -o /dev/null {current_url}'
        c, next_url = run_command(cmd, show_output=False, log_output_to_file=True)
        if c == 0 and next_url.strip():
            print_info(f"Hop {i+1}: {current_url} -> {next_url}")
            current_url = next_url
        else:
            print_success(f"Final Destination: {current_url}")
            break
            
    l = get_logger()
    if l: l.add_html_step("Redirects", "INFO", "\n".join(hops))

def step_waf_evasion(domain: str) -> None:
    print_subheader("18. WAF / User-Agent Test")
    blocked = []
    allowed = []
    waf_detected_overall = False
    waf_name_overall: Optional[str] = None
    flags = get_curl_flags()
    
    for name, ua in USER_AGENTS.items():
        # Fetch both headers and body for WAF detection
        cmd_headers = f'curl{flags} -I -s -w "%{{http_code}}" -H "User-Agent: {ua}" https://{domain}'
        cmd_body = f'curl{flags} -s -H "User-Agent: {ua}" https://{domain}'
        
        c_h, output_h = run_command(cmd_headers, show_output=False, log_output_to_file=True)
        c_b, output_b = run_command(cmd_body, show_output=False, log_output_to_file=False)
        
        try:
            # Extract status code from curl output (last line should be the HTTP code from -w format)
            lines_h = output_h.strip().splitlines()
            code = 0
            if lines_h:
                # Try to get status code from last line (curl -w output)
                try:
                    code = int(lines_h[-1])
                except ValueError:
                    # If last line is not a number, try to parse HTTP status line
                    for line in lines_h:
                        if line.startswith("HTTP/"):
                            try:
                                code = int(line.split()[1])
                                break
                            except (IndexError, ValueError):
                                pass
            
            # Parse headers
            headers: Dict[str, str] = {}
            for line in lines_h:
                if ':' in line and not line.startswith("HTTP/") and not line.strip().isdigit():
                    k, v = line.split(':', 1)
                    headers[k.strip()] = v.strip()
            
            # Detect WAF from this response
            body_text = output_b if c_b == 0 else ""
            waf_detected, waf_name, waf_reason = detect_waf_from_response(code, headers, body_text)
            
            if waf_detected:
                waf_detected_overall = True
                if waf_name:
                    waf_name_overall = waf_name
            
            if code == 403 or code == 406:
                if waf_detected:
                    print_warning(f"{name}: BLOCKED (HTTP {code}) - WAF: {waf_name or 'Detected'}")
                else:
                    print_warning(f"{name}: BLOCKED (HTTP {code}) - WAF Unconfirmed")
                blocked.append(name)
            else:
                print_success(f"{name}: OK (HTTP {code})")
                allowed.append(name)
        except Exception:
            pass
    
    l = get_logger()
    if blocked:
        if waf_detected_overall and waf_name_overall:
            l.log(f"{Colors.WARNING}WAF Detected ({waf_name_overall}): Blocks {', '.join(blocked)}{Colors.ENDC}", force=True)
        else:
            l.log(f"{Colors.WARNING}WAF Detected (Unconfirmed): Blocks {', '.join(blocked)}{Colors.ENDC}", force=True)
    
    details = f"Blocked: {blocked}\nAllowed: {allowed}"
    if waf_detected_overall and waf_name_overall:
        details += f"\nWAF: {waf_name_overall}"
    elif blocked:
        details += "\nWAF: Unconfirmed (Potential WAF / ACL)"
    
    if l:
        l.add_html_step("WAF Evasion", "INFO", details)

def step_speed(domain: str) -> None:
    print_subheader("19. Throughput Speed Test")
    flags = get_curl_flags()
    cmd = f'curl{flags} -s -w "%{{speed_download}}" -o /dev/null https://{domain}/'
    
    speeds = []
    for _ in range(3):
        c, out = run_command(cmd, show_output=False, log_output_to_file=True)
        if c == 0:
            try:
                s = float(out.strip())
                speeds.append(s)
            except: pass
    
    l = get_logger()
    if speeds:
        avg_speed = sum(speeds) / len(speeds)
        mbps = (avg_speed * 8) / 1_000_000
        print_success(f"Average Download Speed: {mbps:.2f} Mbps")
        if l: l.add_html_step("Speed Test", "PASS", f"Avg: {mbps:.2f} Mbps")
    else:
        print_warning("Speed test failed to collect data.")

def step_dns_benchmark(domain: str) -> None:
    print_subheader("20. DNS Resolver Benchmark")
    results = []
    if not shutil.which("dig"): return
    
    for name, ip in PUBLIC_RESOLVERS:
        start = time.time()
        cmd = f"dig @{ip} +short {domain}"
        c, out = run_command(cmd, show_output=False)
        end = time.time()
        
        if c == 0 and out.strip():
            ms = (end - start) * 1000
            results.append((name, ms))
    
    results.sort(key=lambda x: x[1])
    
    l = get_logger()
    details = ""
    for name, ms in results:
        print_info(f"{name:<15}: {ms:.2f} ms")
        details += f"{name}: {ms:.2f} ms\n"
        
    if l: l.add_html_step("DNS Benchmark", "INFO", details)

def step_graph(domain: str) -> None:
    print_subheader("21. Topology Graph (DOT)")
    hops = get_traceroute_hops(domain)
    if not hops:
        print_fail("Could not determine hops for graph.")
        return
        
    dot = ["digraph G {"]
    dot.append('  node [shape=box];')
    dot.append(f'  User [label="User"];')
    
    previous = "User"
    for i, hop in enumerate(hops):
        name = f"Hop{i+1}"
        dot.append(f'  {name} [label="{hop}"];')
        dot.append(f'  "{previous}" -> "{name}";')
        previous = name
        
    dot.append(f'  Dest [label="{domain}"];')
    dot.append(f'  "{previous}" -> "Dest";')
    dot.append("}")
    
    dot_str = "\n".join(dot)
    print(dot_str)
    
    l = get_logger()
    if l: l.log_file(f"Graphviz DOT:\n{dot_str}")

def ping_host(host: str) -> float:
    cmd = f"ping -c 1 -W 1 {host}" if os.name != 'nt' else f"ping -n 1 -w 1000 {host}"
    c, out = run_command(cmd, show_output=False, log_output_to_file=False)
    if c == 0:
        m = re.search(r'time[=<]([\d\.]+)', out)
        if m: return float(m.group(1))
    return -1.0

def step_websocket(domain: str, path: str = "/") -> None: # Feature: WebSocket Handshake
    print_subheader("22. WebSocket Handshake Check")
    from .utils import get_context
    ctx = get_context()
    l = get_logger()
    
    host = domain
    port = 443
    
    # Simple handshake
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {domain}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"\r\n"
    )
    
    try:
        # Reuse the same trusted CA bundle for WebSocket TLS as well.
        context = ssl.create_default_context(cafile=certifi.where())
        timeout = int(ctx.get('timeout', 5))
        
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                ssock.sendall(request.encode())
                response = ssock.recv(4096).decode(errors='ignore')
                
                if "101 Switching Protocols" in response:
                    print_success("WebSocket Handshake: Success (101 Switching Protocols)")
                    if l: l.add_html_step("WebSocket", "PASS", "Connected")
                else:
                    status_line = response.split('\r\n')[0] if response else "No response"
                    print_fail(f"WebSocket Handshake Failed: {status_line}")
                    if l: l.add_html_step("WebSocket", "FAIL", status_line)
                    
    except Exception as e:
        print_fail(f"WebSocket Error: {e}")
        if l: l.add_html_step("WebSocket", "FAIL", str(e))

def get_traceroute_hops(domain: str) -> List[str]:
    cmd = f"tracert -h 15 {domain}" if os.name == 'nt' else f"traceroute -m 15 -w 2 {domain}"
    from .utils import get_context
    ctx = get_context()
    flags = ""
    if ctx.get('ipv4'): flags = " -4"
    if ctx.get('ipv6'): flags = " -6"
    if "traceroute" in cmd: cmd = cmd.replace("traceroute", f"traceroute{flags}")
    
    c, out = run_command(cmd, timeout=60, log_output_to_file=False, show_output=False)
    hops = []
    if c == 0:
        ips = re.findall(r'\((\d+\.\d+\.\d+\.\d+|[a-fA-F0-9:]+)\)', out)
        if not ips:
            ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', out)
        seen = set()
        for ip in ips:
            if ip not in seen and not ip.startswith("0."):
                hops.append(ip)
                seen.add(ip)
    return hops

def run_mtr(domain: str) -> None:
    print(f"Tracing route to {domain}...")
    hops = get_traceroute_hops(domain)
    if not hops:
        print("No hops found or traceroute failed.")
        return
        
    stats = {h: {"sent": 0, "lost": 0, "rtt": []} for h in hops}
    
    try:
        while True:
            # Clear screen
            os.system('cls' if os.name == 'nt' else 'clear')
            print(f"{Colors.BOLD}--- MTR Mode: {domain} (Ctrl+C to quit) ---{Colors.ENDC}")
            print(f"{ 'HOST':<30} | {'LOSS%':<6} | {'AVG':<6} | {'LAST':<6}")
            print("-" * 60)
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                futures = {executor.submit(ping_host, h): h for h in hops}
                for f in concurrent.futures.as_completed(futures):
                    h = futures[f]
                    stats[h]["sent"] += 1
                    rtt = f.result()
                    if rtt == -1.0:
                        stats[h]["lost"] += 1
                    else:
                        stats[h]["rtt"].append(rtt)
            
            for h in hops:
                s = stats[h]
                loss = (s["lost"] / s["sent"]) * 100 if s["sent"] > 0 else 0
                avg = sum(s["rtt"]) / len(s["rtt"]) if s["rtt"] else 0
                last = s["rtt"][-1] if s["rtt"] else 0
                print(f"{h:<30} | {loss:>5.1f}% | {avg:>6.1f} | {last:>6.1f}")
            
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nMTR stopped.")