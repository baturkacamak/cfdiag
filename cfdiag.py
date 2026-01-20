#!/usr/bin/env python3
"""
cfdiag - Cloudflare & Connectivity Diagnostic Tool

A cross-platform (Linux/macOS/Windows) CLI tool to diagnose Cloudflare Error 522, 
DNSSEC, HTTP/3, and other connectivity issues.

It orchestrates native system tools and Python libraries to gather 
diagnostics and presents a structured, actionable summary.

Usage:
    python3 cfdiag.py <domain> [--origin <ip>] [--verbose]
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

# --- Configuration & Constants ---

VERSION = "1.7.0"
SEPARATOR = "=" * 60
SUB_SEPARATOR = "-" * 60
REPO_URL = "https://raw.githubusercontent.com/baturkacamak/cfdiag/main/cfdiag.py"

# Cloudflare compatible ports
CF_PORTS = [8443, 2053, 2083, 2087, 2096]

# Global Resolvers for Propagation Check
PUBLIC_RESOLVERS = [
    ("Google", "8.8.8.8"),
    ("Cloudflare", "1.1.1.1"),
    ("Quad9", "9.9.9.9"),
    ("OpenDNS", "208.67.222.222"),
    ("Level3", "4.2.2.1")
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
    def disable():
        for attr in dir(Colors):
            if not attr.startswith("__") and not callable(getattr(Colors, attr)):
                setattr(Colors, attr, "")

# Enable ANSI colors on Windows 10/11
if os.name == 'nt':
    try:
        from ctypes import windll
        k = windll.kernel32
        k.SetConsoleMode(k.GetStdHandle(-11), 7)
    except:
        pass 

class FileLogger:
    """Handles printing to stdout and buffering for clean file output."""
    def __init__(self, verbose=False, silent=False):
        self.file_buffer = []
        self.ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|[[0-?]*[ -/]*[@-~])')
        self.verbose = verbose # If true, print steps to console
        self.silent = silent   # If true, print NOTHING to console (for batch mode)

    def log_console(self, msg="", end="\n", flush=False, force=False):
        # Print if verbose OR if forced (used for Summary)
        if not self.silent and (self.verbose or force):
            print(msg, end=end, flush=flush)

    def log_file(self, msg, end="\n"):
        clean_msg = self.ansi_escape.sub('', msg)
        self.file_buffer.append(clean_msg + end)

    def log(self, msg="", file_msg=None, end="\n", flush=False, force=False):
        """
        Generic log: Prints to console based on verbosity, always appends to file.
        """
        self.log_console(msg, end, flush, force)
        
        content_for_file = file_msg if file_msg is not None else msg
        clean_msg = self.ansi_escape.sub('', content_for_file)
        self.file_buffer.append(clean_msg + end)

    def save_to_file(self, filename):
        try:
            with open(filename, 'w') as f:
                f.write("".join(self.file_buffer))
            return True
        except Exception as e:
            if self.verbose:
                print(f"{Colors.FAIL}Error saving log: {e}{Colors.ENDC}")
            return False

# Global logger instance
logger = None

# --- Helper Functions ---

def print_header(title):
    logger.log_console(f"\n{Colors.BOLD}{Colors.HEADER}{SEPARATOR}", force=True)
    logger.log_console(f" {title}", force=True)
    logger.log_console(f"{SEPARATOR}{Colors.ENDC}", force=True)
    
    logger.log_file(f"\n# {title}")
    logger.log_file("=" * len(title))

def print_subheader(title):
    # Only print subheaders in verbose mode
    logger.log_console(f"\n{Colors.BOLD}{Colors.OKCYAN}>>> {title}{Colors.ENDC}")
    logger.log_console(f"{Colors.GREY}{SUB_SEPARATOR}{Colors.ENDC}")
    logger.log_file(f"\n## {title}")

def print_success(msg):
    logger.log(f"{Colors.OKGREEN}{Colors.BOLD}✔ [PASS]{Colors.ENDC} {msg}", file_msg=f"[PASS] {msg}")

def print_fail(msg):
    logger.log(f"{Colors.FAIL}{Colors.BOLD}✖ [FAIL]{Colors.ENDC} {msg}", file_msg=f"[FAIL] {msg}")

def print_info(msg):
    logger.log(f"{Colors.OKBLUE}ℹ [INFO]{Colors.ENDC} {msg}", file_msg=f"[INFO] {msg}")

def print_warning(msg):
    logger.log(f"{Colors.WARNING}{Colors.BOLD}⚠ [WARN]{Colors.ENDC} {msg}", file_msg=f"[WARN] {msg}")

def print_cmd(cmd):
    logger.log_console(f"{Colors.GREY}$ {cmd}{Colors.ENDC}")
    logger.log_file(f"Command: {cmd}")

def check_dependencies():
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

def run_command(command, timeout=30, show_output=True, log_output_to_file=True):
    try:
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        output_lines = []
        while True:
            line = process.stdout.readline()
            if not line and process.poll() is not None: break
            if line:
                if show_output and logger.verbose and not logger.silent: 
                    sys.stdout.write(line) 
                output_lines.append(line)
        
        full_output = "".join(output_lines)
        if log_output_to_file and full_output.strip():
             logger.log_file("Output:")
             logger.log_file(textwrap.indent(full_output, '    '))

        return process.poll(), full_output
    except Exception as e:
        logger.log_file(f"[ERROR] {e}")
        return -1, str(e)

def check_internet_connection():
    """
    Sanity check to ensure the local machine has internet access.
    Tries to connect to Cloudflare (1.1.1.1) and Google (8.8.8.8) DNS ports.
    """
    targets = [("1.1.1.1", 53), ("8.8.8.8", 53)]
    for host, port in targets:
        try:
            with socket.create_connection((host, port), timeout=3): return True
        except:
            continue
    return False

# --- Feature: Self Update ---

def self_update():
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

def step_dns(domain):
    print_subheader("1. DNS Resolution & ASN/ISP Check")
    ips, ipv4, ipv6 = [], [], []
    
    print_cmd(f"socket.getaddrinfo('{domain}', 443)")
    try:
        info = socket.getaddrinfo(domain, 443, proto=socket.IPPROTO_TCP)
        for _, _, _, _, sockaddr in info:
            ip = sockaddr[0]
            if ip not in ips:
                ips.append(ip)
                (ipv6 if ':' in ip else ipv4).append(ip)
        
        logger.log_file(f"Output:\n    IPv4: {ipv4}\n    IPv6: {ipv6}")
        
        if ipv4: print_success(f"IPv4 Resolved: {Colors.WHITE}{', '.join(ipv4)}{Colors.ENDC}")
        else: print_warning("No IPv4 records found.")
            
        if ipv6: print_success(f"IPv6 Resolved: {Colors.WHITE}{', '.join(ipv6)}{Colors.ENDC}")
        else: print_info("No IPv6 records found.")
        
        if not ips:
            print_fail("DNS returned empty result.")
            return False, [], []

        target_ip = ipv4[0] if ipv4 else (ipv6[0] if ipv6 else None)
        if target_ip and not target_ip.startswith(("192.168.", "10.", "127.", "::1")):
            c2, out2 = run_command(f"curl -s --connect-timeout 3 http://ip-api.com/json/{target_ip}", show_output=False)
            if c2 == 0:
                try:
                    data = json.loads(out2)
                    print_success(f"Host: {Colors.WHITE}{data.get('isp')} ({data.get('org')}) - {data.get('country')}{Colors.ENDC}")
                except: pass

        return True, ipv4, ipv6
    except Exception as e:
        print_fail(f"DNS resolution failed: {e}")
        return False, [], []

def step_propagation(domain, expected_ns):
    print_subheader(f"2. Global Propagation Check (Expect: {expected_ns})")
    
    if not shutil.which("dig") and os.name != 'nt':
        print_warning("Propagation check requires 'dig' or 'nslookup'.")
        return "ERROR"

    total = len(PUBLIC_RESOLVERS)
    matches = 0
    
    logger.log_file(f"Target Nameserver Substring: {expected_ns}")

    for name, ip in PUBLIC_RESOLVERS:
        if shutil.which("dig"):
            cmd = f"dig @{ip} NS {domain} +short"
        elif os.name == 'nt':
            cmd = f"nslookup -type=NS {domain} {ip}"
        else:
            continue

        c, out = run_command(cmd, show_output=False, log_output_to_file=True)
        
        found = False
        found_records = []
        
        if c == 0:
            if shutil.which("dig"):
                found_records = [l.strip().strip('.') for l in out.splitlines() if l.strip()]
            else: # Windows nslookup
                for line in out.splitlines():
                    if "nameserver =" in line:
                        found_records.append(line.split("=")[1].strip())
            
            for record in found_records:
                if expected_ns.lower() in record.lower():
                    found = True
                    break
            
            if found:
                matches += 1
                print_success(f"{name:<10}: {Colors.WHITE}MATCH{Colors.ENDC} ({found_records[0] if found_records else 'OK'})")
            else:
                res_str = found_records[0] if found_records else "No Records"
                print_fail(f"{name:<10}: {Colors.FAIL}MISMATCH{Colors.ENDC} (Found: {res_str})")
        else:
            print_warning(f"{name:<10}: TIMEOUT/ERROR")

    if matches == total:
        print_success("Global Propagation Complete (Consensus Reached).")
        return "MATCH"
    elif matches == 0:
        print_fail("Global Propagation Failed (Stuck on Old NS).")
        return "FAIL"
    else:
        print_warning(f"Propagation In Progress ({matches}/{total} Resolvers updated).")
        return "PARTIAL"

def step_dnssec(domain):
    print_subheader("3. DNSSEC Validation")
    if not shutil.which("dig"):
        return None

    c, out = run_command(f"dig DS {domain} +short", log_output_to_file=True)
    if not out.strip():
        print_info(f"No DS record found. DNSSEC is likely {Colors.BOLD}DISABLED{Colors.ENDC}.")
        return "DISABLED"
    
    c, out = run_command(f"dig A {domain} +dnssec +short", log_output_to_file=True)
    
    if "RRSIG" in out:
        print_success("DNSSEC Signatures (RRSIG) found. Zone is signed.")
        return "SIGNED"
    else:
        print_fail(f"DS record exists but no RRSIG found on A record. {Colors.BOLD}DNSSEC BROKEN?{Colors.ENDC}")
        return "BROKEN"

def step_domain_status(domain):
    print_subheader("4. Domain Registration Status (RDAP)")
    code, output = run_command(f"curl -s --connect-timeout 5 https://rdap.org/domain/{domain}", show_output=False, log_output_to_file=True)
    if code == 0:
        try:
            data = json.loads(output)
            statuses = [s for s in data.get("status", []) if "transfer" not in s]
            if statuses: print_success(f"Domain Status: {Colors.WHITE}{', '.join(statuses)}{Colors.ENDC}")
            
            for event in data.get("events", []):
                if event.get("eventAction") == "expiration":
                    print_success(f"Expiration Date: {Colors.WHITE}{event.get('eventDate')}{Colors.ENDC}")
                    break
        except: print_warning("Could not parse RDAP data.")

def step_http(domain):
    print_subheader("5. HTTP/HTTPS Availability & WAF Check")
    cmd = f"curl -I --connect-timeout 10 https://{domain}"
    print_cmd(cmd)
    code, output = run_command(cmd, log_output_to_file=True)
    
    status = 0
    waf = False
    
    if code == 0:
        line = next((l for l in output.splitlines() if l.startswith("HTTP/")), None)
        if line:
            try: status = int(line.split()[1])
            except: pass
            
            if status in [403, 503]:
                c2, out2 = run_command(f"curl -s -A 'Mozilla/5.0' --connect-timeout 5 https://{domain}", show_output=False)
                if c2 == 0 and any(x in out2 for x in ["Just a moment...", "cf-captcha-container", "challenge-platform"]):
                    waf = True
                    print_warning(f"{Colors.BOLD}Cloudflare Managed Challenge / CAPTCHA detected.{Colors.ENDC}")

            if 200 <= status < 400:
                print_success(f"Response: {Colors.WHITE}{line.strip()}{Colors.ENDC}")
                return "SUCCESS", status, False
            elif status >= 400:
                return ("WAF_BLOCK" if waf else ("CLIENT_ERROR" if status < 500 else "SERVER_ERROR")), status, waf
    
    if code == 28:
        print_fail("Connection timed out.")
        return "TIMEOUT", 0, False
    
    print_fail("HTTP Check Failed.")
    return "ERROR", 0, False

def step_http3_udp(domain):
    print_subheader("6. HTTP/3 (QUIC) UDP Check")
    print_cmd(f"socket.sendto(..., ('{domain}', 443))")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        sock.sendto(b"PING", (domain, 443))
        print_success("UDP Port 443 outbound appears open (HTTP/3 Candidate).")
        return True
    except Exception as e:
        print_warning(f"UDP 443 Packet failed: {e}")
        return False

def step_ssl(domain):
    print_subheader("7. SSL/TLS Certificate Check")
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                print_success(f"Expiry: {Colors.WHITE}{ssock.getpeercert().get('notAfter')}{Colors.ENDC}")
                return True
    except:
        print_warning("SSL Handshake failed.")
        return False

def step_tcp(domain):
    print_subheader("8. TCP Connectivity (Port 443)")
    try:
        with socket.create_connection((domain, 443), timeout=5):
            print_success("TCP connection established.")
            return True
    except:
        print_fail("TCP connection failed.")
        return False

def step_mtu(domain):
    print_subheader("9. MTU / Fragmentation Check")
    sys_name = platform.system()
    flags = "-n 1 -f -l" if sys_name == "Windows" else ("-c 1 -D -s" if sys_name == "Darwin" else "-c 1 -M do -s")
    cmd = f"ping {flags} 1472 {domain}"
    print_cmd(cmd)
    code, _ = run_command(cmd, log_output_to_file=True)
    if code == 0:
        print_success("Standard MTU (1500) passed.")
        return True
    print_warning("MTU issue detected.")
    return False

def step_traceroute(domain):
    print_subheader("10. Traceroute")
    cmd = f"tracert -h 15 {domain}" if os.name == 'nt' else f"traceroute -m 15 -w 2 {domain}"
    print_info("Tracing...")
    run_command(cmd, timeout=60)

def step_cf_trace(domain):
    print_subheader("11. Cloudflare Debug Trace")
    c, out = run_command(f"curl -s --connect-timeout 5 https://{domain}/cdn-cgi/trace", log_output_to_file=True)
    if c == 0 and "colo=" in out:
        d = dict(l.split('=', 1) for l in out.splitlines() if '=' in l)
        print_success(f"Edge: {Colors.WHITE}{d.get('colo')} / {d.get('ip')}{Colors.ENDC}")
        return True, d
    print_warning("No CF trace found.")
    return False, {}

def step_cf_forced(domain):
    print_subheader("12. Force Resolve (1.1.1.1)")
    c, _ = run_command(f"curl -I -k --resolve {domain}:443:1.1.1.1 https://{domain}", log_output_to_file=True)
    if c == 0: 
        print_success("Connected via 1.1.1.1.")
        return True
    print_fail("Failed via 1.1.1.1.")
    return False

def step_origin(domain, ip):
    print_subheader("13. Direct Origin")
    c, out = run_command(f"curl -I -k --connect-timeout 10 --resolve {domain}:443:{ip} https://{domain}", log_output_to_file=True)
    if c == 0:
        print_success("Origin Connected.")
        return True, "SUCCESS"
    print_fail("Origin Failed.")
    return False, "TIMEOUT" if c == 28 else "ERROR"

# --- Orchestrator ---

def run_diagnostics(domain, origin_ip=None, expected_ns=None):
    reports_dir = "reports"
    if not os.path.exists(reports_dir): os.makedirs(reports_dir)
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    log_file = os.path.join(reports_dir, f"{domain}_{timestamp}.txt")
    
    logger.log_console(f"\n{Colors.BOLD}{Colors.HEADER}DIAGNOSING: {domain}{Colors.ENDC}", force=True)
    logger.log_file(f"# DIAGNOSIS: {domain}\nDate: {timestamp}")

    dns_ok, ipv4, ipv6 = step_dns(domain)
    prop_status = step_propagation(domain, expected_ns) if expected_ns else "N/A"
    dnssec_status = step_dnssec(domain)
    step_domain_status(domain)
    http_res = step_http(domain)
    step_http3_udp(domain)
    
    ssl_ok = step_ssl(domain)
    tcp_ok = step_tcp(domain)
    mtu_ok = step_mtu(domain)
    
    alt_ports_res = (False, [])
    if not tcp_ok or http_res[1] == 0: 
        alt_ports_res = step_alt_ports(domain)
        
    step_traceroute(domain)
    cf_trace_ok = step_cf_trace(domain)
    cf_ok = step_cf_forced(domain)
    
    origin_res = None

    generate_summary(domain, (dns_ok, ipv4, ipv6), http_res, tcp_ok, cf_ok, mtu_ok, ssl_ok, cf_trace_ok, origin_res, alt_ports_res)
    logger.save_to_file(log_file)
    
    return {
        "domain": domain,
        "dns": prop_status if expected_ns else ("OK" if dns_ok else "FAIL"),
        "http": http_res[0],
        "tcp": "OK" if tcp_ok else "FAIL",
        "dnssec": dnssec_status,
        "log": log_file
    }

def generate_summary(domain, dns_res, http_res, tcp_res, cf_res, mtu_res, ssl_res, cf_trace_res, origin_res, alt_ports_res):
    logger.log_console(f"\n{Colors.BOLD}{Colors.HEADER}{SEPARATOR}", force=True)
    logger.log_console(f" DIAGNOSTIC SUMMARY: {domain}", force=True)
    logger.log_console(f"{SEPARATOR}{Colors.ENDC}", force=True)
    
    logger.log_file(f"\n# DIAGNOSTIC SUMMARY")
    logger.log_file("# " + "-" * 30)
    
    conclusions = []
    
    dns_ok, ipv4, ipv6 = dns_res
    if not dns_ok:
        conclusions.append((f"{Colors.FAIL}{Colors.BOLD}[CRITICAL]{Colors.ENDC} DNS Resolution failed.",
                            "[CRITICAL] DNS Resolution failed."))
    else:
        conclusions.append((f"{Colors.OKGREEN}{Colors.BOLD}[PASS]{Colors.ENDC} DNS is resolving correctly.",
                            "[PASS] DNS is resolving correctly."))

    if ssl_res:
         conclusions.append((f"{Colors.OKGREEN}{Colors.BOLD}[PASS]{Colors.ENDC} SSL Certificate is valid.",
                             "[PASS] SSL Certificate is valid."))
    else:
         conclusions.append((f"{Colors.WARNING}{Colors.BOLD}[WARN]{Colors.ENDC} SSL Certificate information could not be verified.",
                             "[WARN] SSL Certificate information could not be verified."))

    if tcp_res:
         conclusions.append((f"{Colors.OKGREEN}{Colors.BOLD}[PASS]{Colors.ENDC} TCP (Port 443) is open.",
                             "[PASS] TCP (Port 443) is open."))
    else:
         conclusions.append((f"{Colors.FAIL}{Colors.BOLD}[CRITICAL]{Colors.ENDC} TCP connection failed.",
                             "[CRITICAL] TCP connection failed."))

    http_status, http_code, is_waf = http_res
    if http_status == "SUCCESS":
        conclusions.append((f"{Colors.OKGREEN}{Colors.BOLD}[PASS]{Colors.ENDC} HTTP requests are working (Code {http_code}).",
                            f"[PASS] HTTP requests are working (Code {http_code})."))
    elif http_status == "WAF_BLOCK":
        conclusions.append((f"{Colors.WARNING}{Colors.BOLD}[BLOCK]{Colors.ENDC} Cloudflare WAF/Challenge detected (Code {http_code}).",
                            f"[BLOCK] Cloudflare WAF/Challenge detected (Code {http_code})."))
    elif http_status == "CLIENT_ERROR":
         conclusions.append((f"{Colors.WARNING}{Colors.BOLD}[WARN]{Colors.ENDC} Server returned Client Error (Code {http_code}).",
                             f"[WARN] Server returned Client Error (Code {http_code})."))
    elif http_status == "SERVER_ERROR":
         conclusions.append((f"{Colors.FAIL}{Colors.BOLD}[CRITICAL]{Colors.ENDC} Server returned Error (Code {http_code}).",
                             f"[CRITICAL] Server returned Error (Code {http_code})."))
         if http_code == 522:
             conclusions.append((f"{Colors.FAIL}{Colors.BOLD}[ALERT]{Colors.ENDC} Cloudflare 522: Connection Timed Out to Origin.",
                                 "[ALERT] Cloudflare 522: Connection Timed Out to Origin."))
         elif http_code == 525:
             conclusions.append((f"{Colors.FAIL}{Colors.BOLD}[ALERT]{Colors.ENDC} Cloudflare 525: SSL Handshake Failed with Origin.",
                                 "[ALERT] Cloudflare 525: SSL Handshake Failed with Origin."))
    elif http_status == "TIMEOUT":
        conclusions.append((f"{Colors.FAIL}{Colors.BOLD}[CRITICAL]{Colors.ENDC} HTTP Request Timed Out (Potential 522).",
                            "[CRITICAL] HTTP Request Timed Out (Potential 522)."))

    if origin_res:
        connected, reason = origin_res
        if connected and reason == "SUCCESS":
             conclusions.append((f"{Colors.OKGREEN}{Colors.BOLD}[PASS]{Colors.ENDC} Direct Origin Connection SUCCEEDED.",
                                 "[PASS] Direct Origin Connection SUCCEEDED."))
             if http_code in [522, 524, 502, 504]:
                  conclusions.append((f"{Colors.FAIL}{Colors.BOLD}[DIAGNOSIS]{Colors.ENDC} Origin is UP but Cloudflare is failing.",
                                      "[DIAGNOSIS] Origin is UP but Cloudflare is failing."))
                  conclusions.append(("  -> CAUSE: Firewall is likely blocking Cloudflare IPs.",
                                      "  -> CAUSE: Firewall is likely blocking Cloudflare IPs."))
        elif not connected and reason == "TIMEOUT":
             conclusions.append((f"{Colors.FAIL}{Colors.BOLD}[CRITICAL]{Colors.ENDC} Direct Origin Connection TIMED OUT.",
                                 "[CRITICAL] Direct Origin Connection TIMED OUT."))
             conclusions.append((f"{Colors.FAIL}{Colors.BOLD}[DIAGNOSIS]{Colors.ENDC} Origin Server is DOWN or Unreachable.",
                                 "[DIAGNOSIS] Origin Server is DOWN or Unreachable."))

    if cf_res or cf_trace_res[0]:
        conclusions.append((f"{Colors.OKGREEN}{Colors.BOLD}[PASS]{Colors.ENDC} Cloudflare Edge Network is reachable.",
                            "[PASS] Cloudflare Edge Network is reachable."))

    for console_msg, file_msg in conclusions:
        logger.log(console_msg, file_msg=file_msg, force=True)
    logger.log_console(f"\n{Colors.GREY}{SEPARATOR}{Colors.ENDC}", force=True)

def main():
    global logger
    
    parser = argparse.ArgumentParser(description="Cloudflare & Connectivity Diagnostic Tool")
    parser.add_argument("domain", help="Domain to diagnose", nargs='?')
    parser.add_argument("--origin", help="Optional: Origin Server IP to test direct connectivity")
    parser.add_argument("--expect", help="Optional: Expected Nameserver (e.g. ns1.host.com) to check propagation")
    parser.add_argument("--file", help="Batch mode: file with list of domains")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show detailed steps")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--version", action="version", version=f"cfdiag {VERSION}")
    parser.add_argument("--update", action="store_true")
    
    args = parser.parse_args()
    
    if args.update:
        self_update()
        return

    if args.no_color: Colors.disable()

    # Pre-flight Check
    if not check_internet_connection():
        print(f"\n{Colors.FAIL}{Colors.BOLD}[CRITICAL] No Internet Connection.{Colors.ENDC}")
        print("Cannot reach Cloudflare (1.1.1.1) or Google (8.8.8.8).")
        print("Please check your local network settings and try again.")
        sys.exit(1)

    check_dependencies()

    if args.file:
        if not os.path.exists(args.file):
            print(f"File not found: {args.file}")
            sys.exit(1)
            
        print(f"\n{Colors.BOLD}{Colors.HEADER}=== BATCH MODE STARTED ==={Colors.ENDC}\n")
        dns_header = "PROPAGATION" if args.expect else "DNS"
        print(f"{ 'DOMAIN':<30} | {dns_header:<12} | {'HTTP':<15} | {'TCP':<6} | {'DNSSEC':<10}")
        print("-" * 85)
        
        with open(args.file, 'r') as f:
            for line in f:
                d = line.strip()
                if not d: continue
                logger = FileLogger(verbose=False, silent=True)
                res = run_diagnostics(d, origin_ip=args.origin, expected_ns=args.expect)
                print(f"{res['domain']:<30} | {res['dns']:<12} | {res['http']:<15} | {res['tcp']:<6} | {str(res['dnssec']):<10}")
        print(f"\n{Colors.OKGREEN}Batch Complete. Detailed reports in reports/{Colors.ENDC}")
    elif args.domain:
        logger = FileLogger(verbose=args.verbose, silent=False)
        target_domain = args.domain.replace("http://", "").replace("https://", "").strip("/")
        run_diagnostics(target_domain, args.origin, args.expect)
        if not args.verbose:
            print(f"\n{Colors.OKBLUE}📄 Full report saved to reports/ folder.{Colors.ENDC}")
    else:
        parser.print_help()

if __name__ == "__main__":
    main()