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
from typing import Tuple, List, Dict, Optional

from .utils import get_curl_flags, PUBLIC_RESOLVERS, DNSBL_LIST, USER_AGENTS, console_lock, Colors
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

def step_asn(domain: str) -> None: 
    print_subheader("17. ASN/ISP Check")
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
    elif analysis["status"] == Severity.WARNING:
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

def step_http(domain: str) -> None: 
    print_subheader("7. HTTP/HTTPS Availability")
    l = get_logger()
    
    probe_res = probe_http(domain)
    analysis = analyze_http(probe_res)
    
    code = probe_res.get("status_code", 0)
    metrics = probe_res.get("timings", {})
    
    if l: l.log_file(f"Probe HTTP: {probe_res}")

    if analysis["status"] == Severity.PASS:
        print_success(f"Response: {Colors.WHITE}HTTP {code}{Colors.ENDC}")
    elif analysis["status"] == Severity.INFO:
        print_warning(f"{analysis['human_reason']} (HTTP {code})")
    elif analysis["status"] == Severity.WARNING:
        print_warning(f"{analysis['human_reason']}")
    elif analysis["status"] in [Severity.ERROR, Severity.CRITICAL]:
        print_fail(f"{analysis['human_reason']}")

    if metrics:
        ttfb_ms = int(metrics.get('ttfb', 0) * 1000)
        conn_ms = int(metrics.get('connect', 0) * 1000)
        print_info(f"Latency: Connect={conn_ms}ms, TTFB={ttfb_ms}ms")
    
    headers = probe_res.get("headers", {})
    cache_status = headers.get('cf-cache-status', 'MISSING')
    server = headers.get('server', '').lower()
    if 'cloudflare' in server:
        if cache_status in ['HIT', 'DYNAMIC', 'BYPASS', 'EXPIRED', 'MISS']:
            print_info(f"Cache Status: {Colors.WHITE}{cache_status}{Colors.ENDC}")
        elif cache_status == 'MISSING':
            print_warning("Cloudflare active but 'cf-cache-status' header missing.")
    
    # Standardize Status Strings for HTML
    res_str = "FAIL"
    if analysis["status"] == Severity.PASS: res_str = "PASS"
    elif analysis["status"] == Severity.INFO: res_str = "INFO"
    elif analysis["status"] == Severity.WARNING: res_str = "WARN"
    
    if l: l.add_html_step("HTTP", res_str, analysis["human_reason"])

def step_ssl(domain: str) -> None: 
    print_subheader("9. SSL/TLS Check")
    l = get_logger()
    
    from .utils import get_context
    ctx = get_context()
    timeout = int(ctx.get('timeout', 5))
    keylog = ctx.get('keylog_file')
    
    probe_res = probe_tls(domain, timeout=timeout, keylog_file=keylog)
    analysis = analyze_tls(probe_res)
    
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
    elif analysis["status"] in [Severity.WARNING, Severity.CRITICAL]:
        print_warning(f"{analysis['human_reason']}")
        if l: l.add_html_step("MTU", "WARN", analysis["human_reason"])
    else:
        print_warning("MTU Check failed or blocked.")

def step_origin(domain: str, ip: str) -> None:
    print_subheader(f"15. Direct Origin Check ({ip})")
    l = get_logger()
    
    origin_res = probe_origin(domain, ip)
    analysis = analyze_origin_reachability(origin_res.get("edge_probe", {}), origin_res.get("origin_probe", {}))
    
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

def _get_hops(domain: str) -> List[str]:
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
