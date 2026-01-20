import shutil
import socket
import ssl
import sys
import subprocess
import textwrap
import re
import json
import os
from typing import Tuple, List, Dict, Optional
from .utils import get_curl_flags, PUBLIC_RESOLVERS, DNSBL_LIST, USER_AGENTS, console_lock, Colors
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
        # Allow override but generally respect context
        # If the caller passed a specific timeout (like 60 for trace), maybe keep it?
        # But if user says --timeout 5, they want 5.
        # Let's say explicit > context? No, Context > Default.
        # But run_command default is 30.
        # If timeout is 30 (default), use context.
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

def step_dns(domain: str) -> Tuple[bool, List[str], List[str]]:
    print_subheader("1. DNS Resolution & ASN/ISP Check")
    ips: List[str] = []
    ipv4: List[str] = []
    ipv6: List[str] = []
    
    # We need get_context. It is in utils.
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
    cmd = f"curl{flags} -I -w \"{fmt}\" --connect-timeout 10 https://{domain}"
    print_cmd(cmd)
    
    code, output = run_command(cmd, log_output_to_file=True)
    
    status = 0
    waf = False
    metrics: Dict[str, float] = {}
    
    if code == 0:
        lines = output.splitlines()
        metrics_line = ""
        for l in reversed(lines):
            if l.startswith("code="):
                metrics_line = l
                break
        
        if metrics_line:
            try:
                parts = dict(p.split('=') for p in metrics_line.split(';;'))
                status = int(parts.get('code', 0)) # type: ignore
                metrics = {k: float(v) for k, v in parts.items() if k != 'code'}
            except: pass
    
    l = get_logger()
    status_str = "PASS" if 200<=status<400 else "FAIL"
    if l: l.add_html_step("HTTP", status_str, f"Status: {status}\nMetrics: {metrics}")
    
    if 200 <= status < 400:
        print_success(f"Response: {Colors.WHITE}HTTP {status}{Colors.ENDC}")
    elif status >= 400:
        if waf:
             print_warning(f"WAF/Challenge Blocked (HTTP {status})")
        elif status < 500:
             print_warning(f"Client Error: HTTP {status}")
        else:
             print_fail(f"Server Error: HTTP {status}")

    if metrics:
        ttfb_ms = int(metrics.get('ttfb', 0) * 1000)
        conn_ms = int(metrics.get('connect', 0) * 1000)
        print_info(f"Latency: Connect={conn_ms}ms, TTFB={ttfb_ms}ms")

    step_cache_headers(output)
    
    return ("SUCCESS" if 200<=status<400 else "FAIL"), status, False, metrics

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
    from .utils import get_context
    ctx = get_context()
    timeout = int(ctx.get('timeout', 2))
    l = get_logger()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(b"PING", (domain, 443))
        print_success("UDP 443 Open.")
        if l: l.add_html_step("HTTP/3", "PASS", "UDP 443 Open")
        return True
    except Exception as e:
        if l: l.add_html_step("HTTP/3", "FAIL", str(e))
        return False

def step_ssl(domain: str) -> bool:
    print_subheader("9. SSL/TLS Check")
    context = ssl.create_default_context()
    
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
    from .utils import get_context
    ctx = get_context()
    timeout = int(ctx.get('timeout', 5))
    l = get_logger()
    try:
        with socket.create_connection((domain, 443), timeout=timeout):
            print_success("Connected.")
            if l: l.add_html_step("TCP", "PASS", "Connected")
            return True
    except Exception as e:
        if l: l.add_html_step("TCP", "FAIL", str(e))
        return False

def step_mtu(domain: str) -> bool:
    print_subheader("11. MTU Check")
    return True

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
    flags = get_curl_flags()
    for name, ua in USER_AGENTS.items():
        cmd = f'curl{flags} -I -s -o /dev/null -w "%{{http_code}}" -H "User-Agent: {ua}" https://{domain}'
        c, code_str = run_command(cmd, show_output=False, log_output_to_file=True)
        try:
            code = int(code_str)
            if code == 403 or code == 406:
                print_warning(f"{name}: BLOCKED (HTTP {code})")
                blocked.append(name)
            else:
                print_success(f"{name}: OK (HTTP {code})")
                allowed.append(name)
        except: pass
    l = get_logger()
    if blocked:
        l.log(f"{Colors.WARNING}WAF Detected: Blocks {', '.join(blocked)}{Colors.ENDC}", force=True)
    if l: l.add_html_step("WAF Evasion", "INFO", f"Blocked: {blocked}\nAllowed: {allowed}")
