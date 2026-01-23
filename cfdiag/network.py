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
from typing import Tuple, List, Dict, Optional, Any

import certifi

from .utils import get_curl_flags, PUBLIC_RESOLVERS, DNSBL_LIST, USER_AGENTS, console_lock, Colors, CLOUDFLARE_IPS
from .reporting import (
    get_logger, print_header, print_subheader, print_success, 
    print_fail, print_info, print_warning, print_cmd
)

from .probes import probe_dns, probe_http, probe_tls, probe_mtu, probe_origin, probe_asn
from .analysis import analyze_dns, analyze_http, analyze_tls, analyze_mtu, analyze_origin_reachability, analyze_asn
from .types import Severity

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
                 # Check if output is HTML from remote domain (don't log full HTML content)
                 output_lower = full_output.strip().lower()
                 is_html = (
                     output_lower.startswith('<!doctype html') or
                     output_lower.startswith('<html') or
                     (output_lower.startswith('<!') and '<html' in output_lower[:500])
                 )
                 
                 # If it's HTML and comes from a curl command to remote domain, don't log the full HTML
                 # Exclude localhost, 127.0.0.1, and local IPs from filtering
                 command_lower = command.lower()
                 is_remote_curl = (
                     'curl' in command_lower and 
                     ('http://' in command_lower or 'https://' in command_lower) and
                     'localhost' not in command_lower and
                     '127.0.0.1' not in command_lower and
                     '::1' not in command_lower
                 )
                 
                 if is_html and is_remote_curl:
                     # Log a summary instead of full HTML
                     html_size = len(full_output)
                     l.log_file("Output:")
                     l.log_file(f"    [HTML Response from remote domain - {html_size} bytes - content excluded from report]")
                 else:
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
    
    # Independent IP resolution
    ip = None
    try:
        ip = socket.gethostbyname(domain)
    except:
        pass

    if not ip or ip.startswith(("192.168.", "10.", "127.", "::1")):
        print_info("Skipping ASN check (Private or Unresolved IP)")
        return

    probe_res = probe_asn(ip)
    analysis = analyze_asn(probe_res)
    
    if analysis["status"] == Severity.PASS:
        print_success(f"ASN Info: {Colors.WHITE}{analysis['human_reason']}{Colors.ENDC}")
        if l: l.log_file(f"ASN: {analysis['human_reason']}")
    elif analysis["status"] == Severity.WARN:
        if l: l.log_file(f"ASN Check: {analysis['human_reason']}")
    
    status_str = "PASS" if analysis["status"] == Severity.PASS else "WARN"
    if l: l.add_html_step("ASN", status_str, analysis["human_reason"])

def step_dns(domain: str) -> None: 
    print_subheader("1. DNS Resolution")
    l = get_logger()
    
    probe_res = probe_dns(domain)
    analysis = analyze_dns(probe_res)
    
    ipv4 = probe_res.get("records", {}).get("A", [])
    ipv6 = probe_res.get("records", {}).get("AAAA", [])
    
    if l: l.log_file(f"Probe Output: {probe_res.get('raw_output', '')}")
    
    if analysis["status"] in [Severity.PASS, Severity.INFO]:
        if ipv4: print_success(f"IPv4 Resolved: {Colors.WHITE}{', '.join(ipv4)}{Colors.ENDC}")
        else: print_warning("No IPv4 records found.")
        
        if ipv6: print_success(f"IPv6 Resolved: {Colors.WHITE}{', '.join(ipv6)}{Colors.ENDC}")
        else: print_info("No IPv6 records found.")

    else:
        print_fail(f"{analysis['classification']}: {analysis['human_reason']}")
    
    status_str = "PASS" if analysis["status"] in [Severity.PASS, Severity.INFO] else "FAIL"
    if l: l.add_html_step("DNS", status_str, analysis["human_reason"])

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
    
    # Parse DNS trace output for real errors only
    # Only treat these as errors: SERVFAIL, NXDOMAIN, REFUSED, communications error, connection timed out
    # Ignore harmless warnings like "Warning: multiple addresses"
    status = "PASS"
    error_message = None
    
    out_lower = out.lower()
    
    # Check for real DNS errors
    if "servfail" in out_lower:
        status = "FAIL"
        error_message = "SERVFAIL: DNS server failure"
    elif "nxdomain" in out_lower:
        status = "FAIL"
        error_message = "NXDOMAIN: Domain not found"
    elif "refused" in out_lower and "status:" in out_lower:
        # Only treat REFUSED as error if it's in the status line, not in warning messages
        status = "WARN"
        error_message = "REFUSED: DNS query refused"
    elif "communications error" in out_lower:
        status = "FAIL"
        error_message = "Communications error: DNS server unreachable"
    elif "connection timed out" in out_lower or "connection timeout" in out_lower:
        status = "FAIL"
        error_message = "Connection timed out: DNS server timeout"
    elif "no servers could be reached" in out_lower:
        status = "FAIL"
        error_message = "No DNS servers could be reached"
    elif c != 0:
        # Non-zero exit code but no specific error pattern matched
        status = "WARN"
        error_message = f"Dig command exited with code {c}"
    elif "noerror" in out_lower or "status: noerror" in out_lower:
        # Successful query - ensure PASS status
        status = "PASS"
    
    # Print appropriate message
    if status == "PASS":
        print_success("DNS Trace completed successfully")
    elif status == "WARN":
        print_warning(f"DNS Trace: {error_message or 'Warning detected'}")
    else:  # FAIL
        print_fail(f"DNS Trace: {error_message or 'Error detected'}")
    
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
    # Use longer timeout for RDAP servers (they can be slow)
    # Also capture HTTP status code
    cmd = f"curl{flags} -s -w \"\\nHTTP_CODE:%{{http_code}}\" --connect-timeout 10 --max-time 15 https://rdap.org/domain/{domain}"
    code, output = run_command(cmd, show_output=False, log_output_to_file=True)
    
    l = get_logger()
    detail = ""
    status = "INFO"
    error_message = None
    
    # Extract HTTP status code from output
    http_code = None
    if "HTTP_CODE:" in output:
        parts = output.split("HTTP_CODE:")
        json_output = parts[0].strip()
        try:
            http_code = int(parts[1].strip())
        except (ValueError, IndexError):
            pass
    else:
        json_output = output
    
    # Log the raw response for debugging
    if l:
        l.log_file(f"RDAP Query URL: https://rdap.org/domain/{domain}")
        l.log_file(f"RDAP Response Code: {code}, HTTP Code: {http_code}")
        if output:
            l.log_file(f"RDAP Raw Output (first 500 chars): {output[:500]}")
    
    # Handle curl errors (timeout, connection errors)
    if code != 0:
        if code == 28:
            error_message = "Request Timed Out: RDAP server did not respond within timeout period"
            status = "WARN"
        elif code == 7:
            error_message = "Connection Error: Could not connect to RDAP server"
            status = "WARN"
        else:
            error_message = f"Query Failed: curl exit code {code}"
            status = "WARN"
        detail = error_message
        print_warning(f"RDAP: {error_message}")
    # Handle HTTP error codes
    elif http_code and http_code >= 400:
        if http_code == 404:
            error_message = "Query Failed: 404 (Domain not found in RDAP database)"
        elif http_code == 429:
            error_message = "Query Failed: 429 (Too Many Requests - Rate limited)"
        elif http_code >= 500:
            error_message = f"Query Failed: {http_code} (RDAP server error)"
        else:
            error_message = f"Query Failed: {http_code}"
        status = "WARN"
        detail = error_message
        print_warning(f"RDAP: {error_message}")
    # Handle successful response
    elif code == 0 and json_output:
        try:
            data = json.loads(json_output)
            
            # Check if data is empty or invalid
            if not data or not isinstance(data, dict):
                error_message = "RDAP Data Not Available: Empty or invalid response"
                status = "WARN"
                detail = error_message
                print_warning(f"RDAP: {error_message}")
            else:
                # Parse successful data
                statuses = [s for s in data.get("status", []) if "transfer" not in s]
                if statuses: 
                    print_success(f"Status: {', '.join(statuses)}")
                    detail += f"Status: {statuses}\n"
                else:
                    detail += "Status: No status information available\n"
                
                # Extract expiration date
                expiration_found = False
                for event in data.get("events", []):
                    if event.get("eventAction") == "expiration":
                        exp_date = event.get("eventDate", "")
                        if exp_date:
                            print_success(f"Expires: {exp_date}")
                            detail += f"Expires: {exp_date}"
                            expiration_found = True
                            break
                
                # Extract handle if available
                handle = data.get("handle")
                if handle:
                    detail = f"Handle: {handle}\n" + detail
                
                if not statuses and not expiration_found:
                    detail = "No RDAP records found: Domain exists but no detailed information available"
                    status = "INFO"
        except json.JSONDecodeError as e:
            error_message = f"Data parsing failed: Invalid JSON response - {str(e)}"
            status = "WARN"
            detail = error_message
            print_warning(f"RDAP: {error_message}")
        except Exception as e:
            error_message = f"Unexpected error processing RDAP data: {str(e)}"
            status = "WARN"
            detail = error_message
            if l:
                l.log_file(f"RDAP Processing Error: {str(e)}")
            print_warning(f"RDAP: {error_message}")
    else:
        # No output or empty response
        error_message = "RDAP Data Not Available: No response from server"
        status = "WARN"
        detail = error_message
        print_warning(f"RDAP: {error_message}")
    
    # Always add HTML step with meaningful content (never empty)
    if not detail:
        detail = "RDAP Data Not Available"
    
    if l:
        l.add_html_step("RDAP", status, detail)

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
    if 'cloudflare' in server:
        if cache_status in ['HIT', 'DYNAMIC', 'BYPASS', 'EXPIRED', 'MISS']:
            print_info(f"Cache Status: {Colors.WHITE}{cache_status}{Colors.ENDC}")
        elif cache_status == 'MISSING':
            print_warning("Cloudflare active but 'cf-cache-status' header missing.")

def step_ssl(domain: str) -> None: 
    print_subheader("9. SSL/TLS Check")
    # Use certifi CA bundle explicitly to avoid false negative verification failures.
    context = ssl.create_default_context(cafile=certifi.where())
    
    from .utils import get_context
    ctx = get_context()
    timeout = int(ctx.get('timeout', 5))
    keylog = ctx.get('keylog_file')
    
    probe_res = probe_tls(domain, timeout=timeout, keylog_file=keylog)
    analysis = analyze_tls(probe_res)
    
    l = get_logger()
    if l: l.log_file(f"Probe TLS: {probe_res}")
    
    if analysis["status"] == Severity.PASS:
        expiry = probe_res.get("cert_expiry", "Unknown")
        print_success(f"Expiry: {expiry}")
        if l: l.add_html_step("SSL", "PASS", f"Expiry: {expiry}")
    else:
        print_fail(f"SSL Failed: {analysis['human_reason']}")
        if l: l.add_html_step("SSL", "FAIL", analysis['human_reason'])

def step_mtu(domain: str) -> None:
    print_subheader("11. MTU Check")
    l = get_logger()
    
    probe_res = probe_mtu(domain)
    analysis = analyze_mtu(probe_res)
    
    if analysis["status"] == Severity.PASS:
        print_success(f"{analysis['human_reason']}")
        if l: l.add_html_step("MTU", "PASS", analysis['human_reason'])
    elif analysis["status"] in [Severity.WARN, Severity.CRITICAL]:
        print_warning(f"{analysis['human_reason']}")
        if l: l.add_html_step("MTU", "WARN", analysis["human_reason"])
    else:
        print_warning("MTU Check failed or blocked.")
        if l: l.add_html_step("MTU", "WARN", "MTU Check failed or blocked.")

def step_origin(domain: str, ip: str) -> None:
    print_subheader(f"15. Direct Origin Check ({ip})")
    l = get_logger()
    
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
    
    if l: 
        l.log_file(f"Probe Origin: {origin_res}")
        l.log_file(f"Analysis: {analysis}")

    if analysis["status"] == Severity.PASS:
        print_success(f"{analysis['human_reason']}")
        if l: l.add_html_step("Origin", "PASS", analysis['human_reason'])
        
    elif analysis["classification"] == "ORIGIN_FIREWALL_BLOCK":
        print_warning(f"{analysis['human_reason']}")
        if l: l.add_html_step("Origin", "WARN", analysis["human_reason"])
        
    elif analysis["classification"] == "ORIGIN_522":
        print_fail(f"{analysis['human_reason']}")
        if l: l.add_html_step("Origin", "FAIL", analysis["human_reason"])
        
    else:
        print_fail(f"{analysis['human_reason']}")
        if l: l.add_html_step("Origin", "FAIL", analysis["human_reason"])
def _ping_host(host: str) -> float:
    cmd = f"ping -c 1 -W 1 {host}" if os.name != 'nt' else f"ping -n 1 -w 1000 {host}"
    c, out = run_command(cmd, show_output=False, log_output_to_file=False)
    if c == 0:
        m = re.search(r'time[=<]([\d\.]+)', out)
        if m: return float(m.group(1))
    return -1.0

def step_security_headers(domain: str) -> None:
    """Check security headers (CSP, HSTS, etc.)"""
    print_subheader("7.5. Security Header Audit")
    l = get_logger()
    flags = get_curl_flags()
    cmd = f"curl{flags} -I -s --connect-timeout 10 https://{domain}"
    code, output = run_command(cmd, show_output=False, log_output_to_file=True)
    
    headers = {}
    for line in output.splitlines():
        if ':' in line:
            k, v = line.split(':', 1)
            headers[k.strip().lower()] = v.strip()
    
    security_headers = {
        'strict-transport-security': 'HSTS',
        'content-security-policy': 'CSP',
        'x-frame-options': 'X-Frame-Options',
        'x-content-type-options': 'X-Content-Type-Options',
        'referrer-policy': 'Referrer-Policy'
    }
    
    found = []
    for header, name in security_headers.items():
        if header in headers:
            found.append(name)
    
    if found:
        print_success(f"Security Headers: {', '.join(found)}")
        if l: l.add_html_step("Security Headers", "PASS", f"Found: {', '.join(found)}")
    else:
        print_warning("No security headers found")
        if l: l.add_html_step("Security Headers", "WARN", "No security headers detected")

def step_http3_udp(domain: str) -> None:
    """Check HTTP/3 (QUIC) support"""
    print_subheader("8. HTTP/3 (QUIC) Check")
    print_info("HTTP/3 check not yet fully implemented")
    l = get_logger()
    if l: l.add_html_step("HTTP/3", "INFO", "Check not implemented")

def step_ocsp(domain: str) -> None:
    """Check OCSP stapling"""
    print_subheader("9.5 OCSP Stapling Check")
    l = get_logger()
    probe_res = probe_tls(domain)
    if probe_res.get("ocsp_stapled"):
        print_success("OCSP Stapling: Enabled")
        if l: l.add_html_step("OCSP", "PASS", "OCSP Stapling enabled")
    else:
        print_info("OCSP Stapling: Not enabled")
        if l: l.add_html_step("OCSP", "INFO", "OCSP Stapling not enabled")

def step_tcp(domain: str) -> bool:
    """Check TCP connectivity"""
    print_subheader("10. TCP Connectivity")
    l = get_logger()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((domain, 443))
        sock.close()
        if result == 0:
            print_success("TCP Port 443: Open")
            if l: l.add_html_step("TCP", "PASS", "Port 443 open")
            return True
        else:
            print_fail("TCP Port 443: Closed or filtered")
            if l: l.add_html_step("TCP", "FAIL", "Port 443 closed")
            return False
    except Exception as e:
        print_fail(f"TCP Check failed: {e}")
        if l: l.add_html_step("TCP", "FAIL", str(e))
        return False

def step_traceroute(domain: str) -> None:
    """Run traceroute"""
    print_subheader("12. Traceroute")
    l = get_logger()
    trace_cmd = "tracert" if os.name == 'nt' else "traceroute"
    if not shutil.which(trace_cmd):
        print_info("Traceroute not available")
        return
    
    flags = get_curl_flags()
    from .utils import get_context
    ctx = get_context()
    if ctx.get('ipv4'): flags += " -4"
    if ctx.get('ipv6'): flags += " -6"
    
    cmd = f"{trace_cmd} {domain}"
    code, output = run_command(cmd, timeout=30, log_output_to_file=True)
    if l: l.log_file(f"Traceroute output:\n{output}")

def step_cf_trace(domain: str) -> Tuple[bool, Dict[str, Any]]:
    """Check Cloudflare trace endpoint"""
    print_subheader("13. CF Trace")
    l = get_logger()
    flags = get_curl_flags()
    cmd = f"curl{flags} -s --connect-timeout 5 https://{domain}/cdn-cgi/trace"
    code, output = run_command(cmd, show_output=False, log_output_to_file=True)
    
    if code == 0 and output.strip():
        print_success("CF Trace: Available")
        if l: l.add_html_step("CF Trace", "PASS", "Trace endpoint accessible")
        return True, {}
    else:
        print_info("CF Trace: Not available (not using Cloudflare or endpoint blocked)")
        if l: l.add_html_step("CF Trace", "INFO", "Trace endpoint not accessible")
        return False, {}

def step_cf_forced(domain: str) -> bool:
    """Check if forced to use Cloudflare"""
    print_subheader("14. CF Forced Check")
    # This is an environment check, not a network check
    return False

def step_alt_ports(domain: str) -> Tuple[bool, List[int]]:
    """Check alternative ports"""
    print_subheader("16. Alternative Ports")
    l = get_logger()
    alt_ports = [8080, 8443, 8081]
    open_ports = []
    
    for port in alt_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((domain, port))
            sock.close()
            if result == 0:
                open_ports.append(port)
        except:
            pass
    
    if open_ports:
        print_success(f"Alternative ports open: {', '.join(map(str, open_ports))}")
        if l: l.add_html_step("Alt Ports", "PASS", f"Open: {open_ports}")
        return True, open_ports
    else:
        print_info("No alternative ports open")
        if l: l.add_html_step("Alt Ports", "INFO", "No alternative ports")
        return False, []

def step_doh(domain: str) -> None:
    """Check DNS over HTTPS"""
    print_subheader("DNS over HTTPS Check")
    l = get_logger()
    print_info("DoH check not yet fully implemented")
    if l: l.add_html_step("DoH", "INFO", "Check not implemented")

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
    hops = _get_hops(domain)
    if not hops:
        print("No hops found or traceroute failed.")
        return
        
    stats = {h: {"sent": 0, "lost": 0, "rtt": []} for h in hops}
    
    try:
        while True:
            os.system('cls' if os.name == 'nt' else 'clear')
            print(f"{Colors.BOLD}--- MTR Mode: {domain} (Ctrl+C to quit) ---")
            print(f"{ 'HOST':<30} | {'LOSS%':<6} | {'AVG':<6} | {'LAST':<6}")
            print("-" * 60)
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                futures = {executor.submit(_ping_host, h): h for h in hops}
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
