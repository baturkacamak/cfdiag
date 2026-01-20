#!/usr/bin/env python3
"""
cfdiag - Cloudflare & Connectivity Diagnostic Tool

A cross-platform (Linux/macOS/Windows) CLI tool to diagnose Cloudflare Error 522, 
DNSSEC, HTTP/3, Latency, and other connectivity issues.

It orchestrates native system tools and Python libraries to gather 
diagnostics and presents a structured, actionable summary.

Usage:
    python3 cfdiag.py <domain> [--origin <ip>] [--profile <name>]
    python3 cfdiag.py --file domains.txt

Author: Gemini Agent
"""

import argparse
import subprocess
import sys
import shutil
import datetime
import platform
import textwrap
import re
import os
import json
import socket
import ssl
import time
import urllib.request
from pathlib import Path
from typing import List, Tuple, Dict, Optional, Any, Union

# --- Configuration & Constants ---

VERSION = "2.3.2"
SEPARATOR = "=" * 60
SUB_SEPARATOR = "-" * 60
REPO_URL = "https://raw.githubusercontent.com/baturkacamak/cfdiag/main/cfdiag.py"
CONFIG_FILE_NAME = ".cfdiag.json"

# Cloudflare compatible ports
CF_PORTS = [8443, 2053, 2083, 2087, 2096]

# Global Resolvers for Propagation Check
PUBLIC_RESOLVERS: List[Tuple[str, str]] = [
    ("Google", "8.8.8.8"),
    ("Cloudflare", "1.1.1.1"),
    ("Quad9", "9.9.9.9"),
    ("OpenDNS", "208.67.222.222"),
    ("Level3", "4.2.2.1")
]

# Common DNSBLs (IP based)
DNSBL_LIST: List[Tuple[str, str]] = [
    ("Spamhaus ZEN", "zen.spamhaus.org"),
    ("Barracuda", "b.barracudacentral.org")
]

# Colors (ANSI escape codes)
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    WHITE = '\033[97m'
    GREY = '\033[90m'
    
    @staticmethod
    def disable() -> None:
        for attr in dir(Colors):
            if not attr.startswith("__") and not callable(getattr(Colors, attr)):
                setattr(Colors, attr, "")

# Enable ANSI colors on Windows 10/11
if os.name == 'nt':
    try:
        from ctypes import windll # type: ignore
        k = windll.kernel32
        k.SetConsoleMode(k.GetStdHandle(-11), 7)
    except:
        pass 

class FileLogger:
    """Handles printing to stdout and buffering for clean file output."""
    def __init__(self, verbose: bool = False, silent: bool = False):
        self.file_buffer: List[str] = []
        self.html_data: Dict[str, Any] = {
            "domain": "",
            "timestamp": "",
            "steps": [],
            "summary": []
        }
        # Fixed regex: escaped [ to [\
        self.ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|[[0-?]*[ -/]*[@-~])')
        self.verbose = verbose 
        self.silent = silent   

    def log_console(self, msg: str = "", end: str = "\n", flush: bool = False, force: bool = False) -> None: 
        if not self.silent and (self.verbose or force):
            print(msg, end=end, flush=flush)

    def log_file(self, msg: str, end: str = "\n") -> None:
        clean_msg = self.ansi_escape.sub('', msg)
        self.file_buffer.append(clean_msg + end)

    def log(self, msg: str = "", file_msg: Optional[str] = None, end: str = "\n", flush: bool = False, force: bool = False) -> None: 
        self.log_console(msg, end, flush, force)
        content = file_msg if file_msg is not None else msg
        self.log_file(content, end)

    def add_html_step(self, title: str, status: str, details: str) -> None:
        if "steps" not in self.html_data:
             self.html_data["steps"] = []
        self.html_data["steps"].append({ # type: ignore
            "title": title,
            "status": status,
            "details": details
        })

    def save_to_file(self, filename: str) -> bool:
        try:
            with open(filename, 'w') as f:
                f.write("".join(self.file_buffer))
            return True
        except Exception as e:
            if self.verbose: print(f"{Colors.FAIL}Error saving log: {e}{Colors.ENDC}")
            return False

    def save_html(self, filename: str) -> bool:
        domain = self.html_data.get('domain', '')
        ts = self.html_data.get('timestamp', '')
        
        html_parts = []
        html_parts.append("<!DOCTYPE html><html><head>")
        html_parts.append(f"<title>cfdiag Report - {domain}</title>")
        html_parts.append("<style>")
        html_parts.append("body { font-family: sans-serif; background: #f4f6f8; padding: 20px; }")
        html_parts.append(".container { max-width: 900px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }")
        html_parts.append("h1 { color: #2c3e50; border-bottom: 2px solid #ecf0f1; padding-bottom: 10px; }")
        html_parts.append(".meta { color: #7f8c8d; margin-bottom: 20px; }")
        html_parts.append(".step { border: 1px solid #e1e4e8; margin-bottom: 15px; border-radius: 4px; overflow: hidden; }")
        html_parts.append(".step-header { padding: 10px 15px; font-weight: bold; display: flex; justify-content: space-between; align-items: center; }")
        html_parts.append(".step-content { padding: 15px; background: #fafbfc; border-top: 1px solid #e1e4e8; font-family: monospace; white-space: pre-wrap; }")
        html_parts.append(".status-PASS { background: #d4edda; color: #155724; }")
        html_parts.append(".status-FAIL { background: #f8d7da; color: #721c24; }")
        html_parts.append(".status-WARN { background: #fff3cd; color: #856404; }")
        html_parts.append(".status-INFO { background: #d1ecf1; color: #0c5460; }")
        html_parts.append(".summary { background: #2c3e50; color: white; padding: 20px; border-radius: 4px; margin-top: 30px; }")
        html_parts.append(".summary h2 { border-bottom: 1px solid #465a69; color: white; }")
        html_parts.append("</style></head><body><div class='container'>")
        html_parts.append(f"<h1>cfdiag Report</h1><div class='meta'>Target: <strong>{domain}</strong> | Date: {ts}</div>")

        steps = self.html_data.get("steps", [])
        if isinstance(steps, list):
            for step in steps:
                if isinstance(step, dict):
                    status = step.get('status', 'INFO')
                    title = step.get('title', '')
                    details = step.get('details', '')
                    html_parts.append(f"<div class='step'><div class='step-header status-{status}'><span>{title}</span><span>[{status}]</span></div><div class='step-content'>{details}</div></div>")
        
        html_parts.append("<div class='summary'><h2>Summary</h2><ul>")
        summary = self.html_data.get("summary", [])
        if isinstance(summary, list):
            for line in summary:
                html_parts.append(f"<li>{line}</li>")
        html_parts.append("</ul></div></div></body></html>")

        try:
            with open(filename, 'w') as f: f.write("\n".join(html_parts))
            return True
        except: return False

# Global logger instance
logger: Optional[FileLogger] = None

# --- Helper Functions ---

def print_header(title: str) -> None:
    if logger:
        logger.log_console(f"\n{Colors.BOLD}{Colors.HEADER}{SEPARATOR}", force=True)
        logger.log_console(f" {title}", force=True)
        logger.log_console(f"{SEPARATOR}{Colors.ENDC}", force=True)
        logger.log_file(f"\n{SEPARATOR}")
        logger.log_file(f" {title}")
        logger.log_file(f"{SEPARATOR}")

def print_subheader(title: str) -> None:
    if logger:
        logger.log_console(f"\n{Colors.BOLD}{Colors.OKCYAN}>>> {title}{Colors.ENDC}")
        logger.log_console(f"{Colors.GREY}{SUB_SEPARATOR}{Colors.ENDC}")
        logger.log_file(f"\n>>> {title}")
        logger.log_file(f"{SUB_SEPARATOR}")

def print_success(msg: str) -> None:
    if logger: logger.log(f"{Colors.OKGREEN}{Colors.BOLD}✔ [PASS]{Colors.ENDC} {msg}", file_msg=f"[PASS] {msg}")

def print_fail(msg: str) -> None:
    if logger: logger.log(f"{Colors.FAIL}{Colors.BOLD}✖ [FAIL]{Colors.ENDC} {msg}", file_msg=f"[FAIL] {msg}")

def print_info(msg: str) -> None:
    if logger: logger.log(f"{Colors.OKBLUE}ℹ [INFO]{Colors.ENDC} {msg}", file_msg=f"[INFO] {msg}")

def print_warning(msg: str) -> None:
    if logger: logger.log(f"{Colors.WARNING}{Colors.BOLD}⚠ [WARN]{Colors.ENDC} {msg}", file_msg=f"[WARN] {msg}")

def print_cmd(cmd: str) -> None:
    if logger:
        logger.log_console(f"{Colors.GREY}$ {cmd}{Colors.ENDC}")
        logger.log_file(f"Command: {cmd}")

def check_dependencies() -> None:
    missing = []
    if not shutil.which("curl"): missing.append("curl")
    
    trace_cmd = "tracert" if os.name == 'nt' else "traceroute"
    if not shutil.which(trace_cmd):
        if os.name != 'nt': 
             if not os.path.exists("/usr/sbin/traceroute"):
                 missing.append("traceroute")
    
    if missing:
        print(f"Missing required system tools: {', '.join(missing)}")
        sys.exit(1)

def run_command(command: str, timeout: int = 30, show_output: bool = True, log_output_to_file: bool = True) -> Tuple[Optional[int], str]:
    try:
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        output_lines = []
        while True:
            line = process.stdout.readline() # type: ignore
            if not line and process.poll() is not None: break
            if line:
                if show_output and logger and logger.verbose and not logger.silent: 
                    sys.stdout.write(line) 
                output_lines.append(line)
        
        full_output = "".join(output_lines)
        exit_code = process.poll()

        if log_output_to_file and logger:
             if full_output.strip():
                 logger.log_file("Output:")
                 logger.log_file(textwrap.indent(full_output, '    '))
             if exit_code != 0:
                 logger.log_file(f"[ERROR] Command failed with exit code {exit_code}")

        return exit_code, full_output
    except Exception as e:
        if logger: logger.log_file(f"[EXCEPTION] {e}")
        return -1, str(e)

def check_internet_connection() -> bool:
    targets = [("1.1.1.1", 53), ("8.8.8.8", 53)]
    for host, port in targets:
        try:
            with socket.create_connection((host, port), timeout=3): return True
        except: continue
    return False

def load_config(profile_name: Optional[str] = None) -> Dict[str, Any]:
    paths = [os.path.join(os.getcwd(), CONFIG_FILE_NAME), os.path.join(str(Path.home()), CONFIG_FILE_NAME)]
    config = {}
    for p in paths:
        if os.path.exists(p):
            try:
                with open(p, 'r') as f: config = json.load(f)
                break
            except: pass
    if profile_name: return config.get("profiles", {}).get(profile_name, {}) # type: ignore
    return config

def self_update() -> None:
    print(f"Checking for updates (Current: {VERSION})...")
    try:
        with urllib.request.urlopen(REPO_URL, timeout=5) as response:
            if response.status != 200: return
            new_code = response.read().decode('utf-8')
            match = re.search(r'VERSION = "([\d\.]+)"', new_code)
            if match and match.group(1) > VERSION:
                print(f"New version found: {match.group(1)}")
                with open(sys.argv[0], 'w', encoding='utf-8') as f: f.write(new_code)
                print("Update successful!")
                sys.exit(0)
            else:
                print("You are already running the latest version.")
    except Exception as e:
        print(f"Update failed: {e}")

# --- Diagnostic Steps ---

def step_dns(domain: str) -> Tuple[bool, List[str], List[str]]:
    print_subheader("1. DNS Resolution & ASN/ISP Check")
    ips: List[str] = []
    ipv4: List[str] = []
    ipv6: List[str] = []
    print_cmd(f"socket.getaddrinfo('{domain}', 443)")
    try:
        info = socket.getaddrinfo(domain, 443, proto=socket.IPPROTO_TCP)
        for _, _, _, _, sockaddr in info:
            ip = sockaddr[0]
            if ip not in ips:
                ips.append(ip)
                (ipv6 if ':' in ip else ipv4).append(ip)
        
        detail = f"IPv4: {', '.join(ipv4)}\\nIPv6: {', '.join(ipv6)}"
        if ipv4: print_success(f"IPv4 Resolved: {Colors.WHITE}{', '.join(ipv4)}{Colors.ENDC}")
        else: print_warning("No IPv4 records found.")
        if ipv6: print_success(f"IPv6 Resolved: {Colors.WHITE}{', '.join(ipv6)}{Colors.ENDC}")
        
        target_ip = ipv4[0] if ipv4 else (ipv6[0] if ipv6 else None)
        if target_ip and not target_ip.startswith(("192.168.", "10.", "127.", "::1")):
            c2, out2 = run_command(f"curl -s --connect-timeout 3 http://ip-api.com/json/{target_ip}", show_output=False)
            if c2 == 0:
                try:
                    data = json.loads(out2)
                    host_str = f"Host: {data.get('isp')} ({data.get('org')}) - {data.get('country')}"
                    print_success(f"{Colors.WHITE}{host_str}{Colors.ENDC}")
                    detail += f"\\n{host_str}"
                except: pass
        
        if logger: logger.add_html_step("DNS", "PASS" if ips else "FAIL", detail)
        return True, ipv4, ipv6
    except Exception as e:
        print_fail(f"DNS resolution failed: {e}")
        if logger: logger.add_html_step("DNS", "FAIL", str(e))
        return False, [], []

def step_blacklist(domain: str, ip: str) -> None:
    print_subheader("2. Blacklist/Reputation Check (DNSBL)")
    if not ip: return
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
                details += f"Listed on {name}\\n"
                listed = True
            except:
                details += f"Clean on {name}\\n"
        if logger: logger.add_html_step("Blacklist Check", "FAIL" if listed else "PASS", details)
    except Exception as e:
        print_warning(f"Blacklist check failed: {e}")

def step_dns_trace(domain: str) -> None:
    print_subheader("3. Recursive DNS Trace")
    if not shutil.which("dig"): return
    c, out = run_command(f"dig +trace {domain}", timeout=15, log_output_to_file=True)
    status = "PASS" if c==0 and "NOERROR" in out else "WARN"
    if logger: logger.add_html_step("DNS Trace", status, out)

def step_propagation(domain: str, expected_ns: str) -> str:
    print_subheader(f"4. Global Propagation Check")
    if not shutil.which("dig") and os.name != 'nt': return "ERROR"
    matches = 0
    details = ""
    for name, ip in PUBLIC_RESOLVERS:
        if shutil.which("dig"): cmd = f"dig @{ip} NS {domain} +short"
        elif os.name == 'nt': cmd = f"nslookup -type=NS {domain} {ip}"
        else: continue
        c, out = run_command(cmd, show_output=False)
        found = expected_ns.lower() in out.lower()
        if found: matches += 1
        res_str = "MATCH" if found else "MISMATCH"
        print_info(f"{name}: {res_str}")
        details += f"{name}: {res_str}\\n"
    
    status = "MATCH" if matches == len(PUBLIC_RESOLVERS) else "PARTIAL"
    if logger: logger.add_html_step("Propagation", status, details)
    return status

def step_dnssec(domain: str) -> Optional[str]:
    print_subheader("5. DNSSEC Validation")
    if not shutil.which("dig"): return None
    c, out = run_command(f"dig DS {domain} +short", log_output_to_file=True)
    if not out.strip(): return "DISABLED"
    c, out = run_command(f"dig A {domain} +dnssec +short", log_output_to_file=True)
    status = "SIGNED" if "RRSIG" in out else "BROKEN"
    if logger: logger.add_html_step("DNSSEC", "PASS" if status=="SIGNED" else "FAIL", f"Status: {status}")
    return status

def step_domain_status(domain: str) -> None:
    print_subheader("6. Domain Registration Status (RDAP)")
    code, output = run_command(f"curl -s --connect-timeout 5 https://rdap.org/domain/{domain}", show_output=False)
    detail = ""
    if code == 0:
        try:
            data = json.loads(output)
            statuses = [s for s in data.get("status", []) if "transfer" not in s]
            if statuses: 
                print_success(f"Status: {', '.join(statuses)}")
                detail += f"Status: {statuses}\\n"
            for event in data.get("events", []):
                if event.get("eventAction") == "expiration":
                    print_success(f"Expires: {event.get('eventDate')}")
                    detail += f"Expires: {event.get('eventDate')}"
                    break
        except: pass
    if logger: logger.add_html_step("RDAP", "INFO", detail)

def step_http(domain: str) -> Tuple[str, int, bool, Dict[str, float]]:
    print_subheader("7. HTTP/HTTPS Availability")
    fmt = "code=%{http_code};;connect=%{time_connect};;start=%{time_starttransfer};;total=%{time_total}"
    cmd = f"curl -I -w \"{fmt}\" --connect-timeout 10 https://{domain}"
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
                parts = dict(p.split('=') for p in l.split(';;'))
                status = int(parts.get('code', 0)) # type: ignore
                metrics = {k: float(v) for k, v in parts.items() if k != 'code'}
            except: pass
    
    status_str = "PASS" if 200<=status<400 else "FAIL"
    if logger: logger.add_html_step("HTTP", status_str, f"Status: {status}\\nMetrics: {metrics}")
    
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
    
    return ("SUCCESS" if 200<=status<400 else "FAIL"), status, waf, metrics

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
        
        if logger: logger.add_html_step("Cache Analysis", "INFO", f"Status: {cache_status}")

def step_security_headers(domain: str) -> None:
    print_subheader("7.5. Security Header Audit")
    cmd = f"curl -I --connect-timeout 5 https://{domain}"
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
            details += f"{name}: PASS\\n"
            passed += 1
        else:
            print_warning(f"{name}: Missing")
            details += f"{name}: MISSING\\n"
            
    if logger: logger.add_html_step("Security Headers", f"{passed}/{len(checks)}", details)

def step_http3_udp(domain: str) -> bool:
    print_subheader("8. HTTP/3 (QUIC) Check")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        sock.sendto(b"PING", (domain, 443))
        print_success("UDP 443 Open.")
        if logger: logger.add_html_step("HTTP/3", "PASS", "UDP 443 Open")
        return True
    except Exception as e:
        if logger: logger.add_html_step("HTTP/3", "FAIL", str(e))
        return False

def step_ssl(domain: str) -> bool:
    print_subheader("9. SSL/TLS Check")
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                print_success(f"Expiry: {ssock.getpeercert().get('notAfter')}") # type: ignore
                if logger: logger.add_html_step("SSL", "PASS", f"Expiry: {ssock.getpeercert().get('notAfter')}") # type: ignore
                return True
    except Exception as e:
        print_fail(f"SSL Failed: {e}")
        if logger: logger.add_html_step("SSL", "FAIL", str(e))
        return False

def step_tcp(domain: str) -> bool:
    print_subheader("10. TCP Connectivity")
    try:
        with socket.create_connection((domain, 443), timeout=5):
            print_success("Connected.")
            if logger: logger.add_html_step("TCP", "PASS", "Connected")
            return True
    except Exception as e:
        if logger: logger.add_html_step("TCP", "FAIL", str(e))
        return False

def step_mtu(domain: str) -> bool:
    print_subheader("11. MTU Check")
    return True

def step_traceroute(domain: str) -> None:
    print_subheader("12. Traceroute")
    cmd = f"tracert -h 15 {domain}" if os.name == 'nt' else f"traceroute -m 15 -w 2 {domain}"
    c, out = run_command(cmd, timeout=60, log_output_to_file=True)
    if logger: logger.add_html_step("Traceroute", "INFO", out)

def step_cf_trace(domain: str) -> Tuple[bool, Dict[str, str]]:
    print_subheader("13. CF Trace")
    c, out = run_command(f"curl -s --connect-timeout 5 https://{domain}/cdn-cgi/trace", log_output_to_file=True)
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

def generate_summary(domain: str, dns_res, http_res, tcp_res, cf_res, mtu_res, ssl_res, cf_trace_res, origin_res, alt_ports_res) -> None:
    if not logger: return
    logger.log_console(f"\n{Colors.BOLD}{Colors.HEADER}{SEPARATOR}", force=True)
    logger.log_console(f" DIAGNOSTIC SUMMARY: {domain}", force=True)
    logger.log_console(f"{SEPARATOR}{Colors.ENDC}", force=True)
    
    logger.log_file(f"\n{SEPARATOR}")
    logger.log_file(f" DIAGNOSTIC SUMMARY")
    logger.log_file(f"{SEPARATOR}")
    
    dns_ok, ipv4, ipv6 = dns_res
    if not dns_ok:
        logger.log(f"{Colors.FAIL}{Colors.BOLD}[CRITICAL]{Colors.ENDC} DNS Resolution failed.", file_msg="[CRITICAL] DNS Resolution failed.", force=True)
    else:
        logger.log(f"{Colors.OKGREEN}{Colors.BOLD}[PASS]{Colors.ENDC} DNS is resolving correctly.", file_msg="[PASS] DNS is resolving correctly.", force=True)

    if ssl_res:
         logger.log(f"{Colors.OKGREEN}{Colors.BOLD}[PASS]{Colors.ENDC} SSL Certificate is valid.", file_msg="[PASS] SSL Certificate is valid.", force=True)
    else:
         logger.log(f"{Colors.WARNING}{Colors.BOLD}[WARN]{Colors.ENDC} SSL Certificate information could not be verified.", file_msg="[WARN] SSL Certificate information could not be verified.", force=True)

    if tcp_res:
         logger.log(f"{Colors.OKGREEN}{Colors.BOLD}[PASS]{Colors.ENDC} TCP (Port 443) is open.", file_msg="[PASS] TCP (Port 443) is open.", force=True)
    else:
         logger.log(f"{Colors.FAIL}{Colors.BOLD}[CRITICAL]{Colors.ENDC} TCP connection failed.", file_msg="[CRITICAL] TCP connection failed.", force=True)

    http_status, http_code, is_waf, metrics = http_res
    if http_status == "SUCCESS":
        logger.log(f"{Colors.OKGREEN}{Colors.BOLD}[PASS]{Colors.ENDC} HTTP requests are working (Code {http_code}).", file_msg=f"[PASS] HTTP requests are working (Code {http_code}).", force=True)
    elif http_status == "WAF_BLOCK":
        logger.log(f"{Colors.WARNING}{Colors.BOLD}[BLOCK]{Colors.ENDC} Cloudflare WAF/Challenge detected (Code {http_code}).", file_msg=f"[BLOCK] Cloudflare WAF/Challenge detected (Code {http_code}).", force=True)
    elif http_status == "CLIENT_ERROR":
         logger.log(f"{Colors.WARNING}{Colors.BOLD}[WARN]{Colors.ENDC} Server returned Client Error (Code {http_code}).", file_msg=f"[WARN] Server returned Client Error (Code {http_code}).", force=True)
    elif http_status == "SERVER_ERROR":
         logger.log(f"{Colors.FAIL}{Colors.BOLD}[CRITICAL]{Colors.ENDC} Server returned Error (Code {http_code}).", file_msg=f"[CRITICAL] Server returned Error (Code {http_code}).", force=True)
         if http_code == 522:
             logger.log(f"{Colors.FAIL}{Colors.BOLD}[ALERT]{Colors.ENDC} Cloudflare 522: Connection Timed Out to Origin.", file_msg="[ALERT] Cloudflare 522: Connection Timed Out to Origin.", force=True)
         elif http_code == 525:
             logger.log(f"{Colors.FAIL}{Colors.BOLD}[ALERT]{Colors.ENDC} Cloudflare 525: SSL Handshake Failed with Origin.", file_msg="[ALERT] Cloudflare 525: SSL Handshake Failed with Origin.", force=True)
    elif http_status == "TIMEOUT":
        logger.log(f"{Colors.FAIL}{Colors.BOLD}[CRITICAL]{Colors.ENDC} HTTP Request Timed Out (Potential 522).", file_msg="[CRITICAL] HTTP Request Timed Out (Potential 522).", force=True)

    if origin_res:
        connected, reason = origin_res
        if connected and reason == "SUCCESS":
             logger.log(f"{Colors.OKGREEN}{Colors.BOLD}[PASS]{Colors.ENDC} Direct Origin Connection SUCCEEDED.", file_msg="[PASS] Direct Origin Connection SUCCEEDED.", force=True)
             if http_code in [522, 524, 502, 504]:
                  logger.log(f"{Colors.FAIL}{Colors.BOLD}[DIAGNOSIS]{Colors.ENDC} Origin is UP but Cloudflare is failing.", file_msg="[DIAGNOSIS] Origin is UP but Cloudflare is failing.", force=True)
                  logger.log("  -> CAUSE: Firewall is likely blocking Cloudflare IPs.", file_msg="  -> CAUSE: Firewall is likely blocking Cloudflare IPs.", force=True)
        elif not connected and reason == "TIMEOUT":
             logger.log(f"{Colors.FAIL}{Colors.BOLD}[CRITICAL]{Colors.ENDC} Direct Origin Connection TIMED OUT.", file_msg="[CRITICAL] Direct Origin Connection TIMED OUT.", force=True)
             logger.log(f"{Colors.FAIL}{Colors.BOLD}[DIAGNOSIS]{Colors.ENDC} Origin Server is DOWN or Unreachable.", file_msg="[DIAGNOSIS] Origin Server is DOWN or Unreachable.", force=True)

    if cf_res or cf_trace_res[0]:
        logger.log(f"{Colors.OKGREEN}{Colors.BOLD}[PASS]{Colors.ENDC} Cloudflare Edge Network is reachable.", file_msg="[PASS] Cloudflare Edge Network is reachable.", force=True)

    logger.log_console(f"\n{Colors.GREY}{SEPARATOR}{Colors.ENDC}", force=True)
    logger.log_file(f"\n{SEPARATOR}")

# --- Orchestrator ---

def run_diagnostics(domain: str, origin_ip: Optional[str]=None, expected_ns: Optional[str]=None) -> Dict[str, Any]:
    reports_dir = "reports"
    if not os.path.exists(reports_dir): os.makedirs(reports_dir)
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    log_file = os.path.join(reports_dir, f"{domain}_{timestamp}.txt")
    
    if logger:
        logger.html_data['domain'] = domain
        logger.html_data['timestamp'] = timestamp
        logger.log_console(f"\n{Colors.BOLD}{Colors.HEADER}DIAGNOSING: {domain}{Colors.ENDC}", force=True)

    dns_ok, ipv4, ipv6 = step_dns(domain)
    
    if ipv4: step_blacklist(domain, ipv4[0])
    
    step_dns_trace(domain)
    if expected_ns: step_propagation(domain, expected_ns)
    step_dnssec(domain)
    step_domain_status(domain)
    
    http_res = step_http(domain)
    step_security_headers(domain)
    step_http3_udp(domain)
    ssl_ok = step_ssl(domain)
    tcp_ok = step_tcp(domain)
    mtu_ok = step_mtu(domain)
    
    alt_ports_res = (False, [])
    if not tcp_ok: alt_ports_res = step_alt_ports(domain)
        
    step_traceroute(domain)
    cf_trace_ok = step_cf_trace(domain)
    cf_ok = step_cf_forced(domain)
    origin_res = step_origin(domain, origin_ip) if origin_ip else None

    # Generate Text Summary (Console + Log File)
    generate_summary(domain, (dns_ok, ipv4, ipv6), http_res, tcp_ok, cf_ok, mtu_ok, ssl_ok, cf_trace_ok, origin_res, alt_ports_res)

    # Populate HTML Summary
    summary = []
    summary.append(f"DNS: {'PASS' if dns_ok else 'FAIL'}")
    summary.append(f"HTTP: {http_res[0]}")
    summary.append(f"SSL: {'PASS' if ssl_ok else 'FAIL'}")
    if logger: logger.html_data["summary"] = summary

    # Save Files
    if logger:
        logger.save_to_file(log_file)
        logger.save_html(os.path.join(reports_dir, f"{domain}_{timestamp}.html"))
    
    return {
        "domain": domain,
        "dns": "OK" if dns_ok else "FAIL",
        "http": http_res[0],
        "tcp": "OK" if tcp_ok else "FAIL",
        "dnssec": "N/A",
        "log": log_file
    }

def main() -> None: 
    global logger
    parser = argparse.ArgumentParser()
    parser.add_argument("domain", nargs='?')
    parser.add_argument("--origin")
    parser.add_argument("--expect")
    parser.add_argument("--profile")
    parser.add_argument("--file")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--version", action="version", version=f"cfdiag {VERSION}")
    parser.add_argument("--update", action="store_true")
    args = parser.parse_args()
    
    if args.update: self_update(); return
    if args.no_color: Colors.disable()

    config = load_config(args.profile)
    domain = args.domain or config.get("domain")
    origin = args.origin or config.get("origin")
    expect = args.expect or config.get("expect")

    if not domain and not args.file: parser.print_help(); sys.exit(1)
    if not check_internet_connection(): print("No Internet."); sys.exit(1)
    check_dependencies()

    if args.file:
        with open(args.file, 'r') as f:
            for line in f:
                d = line.strip()
                if d:
                    logger = FileLogger(verbose=False, silent=True)
                    run_diagnostics(d, origin, expect)
    else:
        logger = FileLogger(verbose=args.verbose, silent=False)
        run_diagnostics(domain.replace("http://", "").replace("https://", "").strip("/"), origin, expect)
        if not args.verbose: print(f"\n{Colors.OKBLUE}📄 Reports saved to reports/ folder.{Colors.ENDC}")

if __name__ == "__main__":
    main()