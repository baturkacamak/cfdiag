#!/usr/bin/env python3
"""
cfdiag - Cloudflare & Connectivity Diagnostic Tool

A cross-platform (Linux/macOS/Windows) CLI tool to diagnose Cloudflare Error 522, 
DNSSEC, HTTP/3, and other connectivity issues.

It orchestrates native system tools and Python libraries to gather 
diagnostics and presents a structured, actionable summary.

Usage:
    python3 cfdiag.py <domain> [--origin <ip>] [--update]
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

VERSION = "1.3.0"
SEPARATOR = "=" * 60
SUB_SEPARATOR = "-" * 60
REPO_URL = "https://raw.githubusercontent.com/baturkacamak/cfdiag/main/cfdiag.py"

# Cloudflare compatible ports
CF_PORTS = [8443, 2053, 2083, 2087, 2096]

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
    def __init__(self, silent=False):
        self.file_buffer = []
        self.ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|[[0-?]*[ -/]*[@-~])')
        self.silent = silent # If true, suppress console output (for batch mode)

    def log_console(self, msg="", end="\n", flush=False):
        if not self.silent:
            print(msg, end=end, flush=flush)

    def log_file(self, msg, end="\n"):
        clean_msg = self.ansi_escape.sub('', msg)
        self.file_buffer.append(clean_msg + end)

    def log(self, msg="", file_msg=None, end="\n", flush=False):
        if not self.silent:
            print(msg, end=end, flush=flush)
        
        content_for_file = file_msg if file_msg is not None else msg
        clean_msg = self.ansi_escape.sub('', content_for_file)
        self.file_buffer.append(clean_msg + end)

    def save_to_file(self, filename):
        try:
            with open(filename, 'w') as f:
                f.write("".join(self.file_buffer))
            return True
        except Exception as e:
            if not self.silent:
                print(f"{Colors.FAIL}Error saving log: {e}{Colors.ENDC}")
            return False

# Global logger instance (initialized in main)
logger = None

# --- Helper Functions ---

def print_header(title):
    logger.log_console(f"\n{Colors.BOLD}{Colors.HEADER}{SEPARATOR}")
    logger.log_console(f" {title}")
    logger.log_console(f"{SEPARATOR}{Colors.ENDC}")
    logger.log_file(f"\n# {title}")
    logger.log_file("=" * len(title))

def print_subheader(title):
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
    
    # We need dig for DNSSEC if available, but optional
    
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
                if show_output and not logger.silent: sys.stdout.write(line) 
                output_lines.append(line)
        
        full_output = "".join(output_lines)
        if log_output_to_file and full_output.strip():
             logger.log_file("Output:")
             logger.log_file(textwrap.indent(full_output, '    '))

        return process.poll(), full_output
    except Exception as e:
        logger.log_file(f"[ERROR] {e}")
        return -1, str(e)

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

        # ISP Check
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

def step_dnssec(domain):
    print_subheader("2. DNSSEC Validation")
    # Native python validation is hard without 3rd party libs (dnspython).
    # We rely on 'dig'. If not available, we skip.
    if not shutil.which("dig"):
        print_info("Skipping DNSSEC check ('dig' tool not found).")
        return None

    # Check for DS record at parent
    print_cmd(f"dig DS {domain} +short")
    c, out = run_command(f"dig DS {domain} +short", log_output_to_file=True)
    if not out.strip():
        print_info("No DS record found. DNSSEC is likely {Colors.BOLD}DISABLED{Colors.ENDC}.")
        return "DISABLED"
    
    # Check for RRSIG on A record
    print_cmd(f"dig A {domain} +dnssec +short")
    c, out = run_command(f"dig A {domain} +dnssec +short", log_output_to_file=True)
    
    if "RRSIG" in out:
        print_success("DNSSEC Signatures (RRSIG) found. Zone is signed.")
        return "SIGNED"
    else:
        print_fail("DS record exists but no RRSIG found on A record. {Colors.BOLD}DNSSEC BROKEN?{Colors.ENDC}")
        return "BROKEN"

def step_domain_status(domain):
    print_subheader("3. Domain Registration Status (RDAP)")
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
    print_subheader("4. HTTP/HTTPS Availability & WAF Check")
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
                # Check WAF
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
    print_subheader("5. HTTP/3 (QUIC) UDP Check")
    # Check if UDP 443 is blocked outbound.
    # We can't easily verify the SERVER accepts it without a QUIC client,
    # but we can check if we can send packets without immediate "Destination Unreachable".
    print_cmd(f"socket.sendto(..., ('{domain}', 443))")
    
    try:
        # Create UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        # Send dummy payload
        sock.sendto(b"PING", (domain, 443))
        # We don't expect a reply usually (unless server speaks UDP/QUIC and sends a reset or garbage)
        # But if we get an ICMP unreachable error immediately, it raises an exception on some OSs
        # or we assume success if no error.
        print_success("UDP Port 443 outbound appears open (HTTP/3 Candidate).")
        return True
    except Exception as e:
        print_warning(f"UDP 443 Packet failed: {e}")
        return False

def step_ssl(domain):
    print_subheader("6. SSL/TLS Certificate Check")
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
    print_subheader("7. TCP Connectivity (Port 443)")
    try:
        with socket.create_connection((domain, 443), timeout=5):
            print_success("TCP connection established.")
            return True
    except:
        print_fail("TCP connection failed.")
        return False

def step_mtu(domain):
    print_subheader("8. MTU / Fragmentation Check")
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
    print_subheader("9. Traceroute")
    cmd = f"tracert -h 15 {domain}" if os.name == 'nt' else f"traceroute -m 15 -w 2 {domain}"
    print_info("Tracing...")
    run_command(cmd, timeout=60)

def step_cf_trace(domain):
    print_subheader("10. Cloudflare Debug Trace")
    c, out = run_command(f"curl -s --connect-timeout 5 https://{domain}/cdn-cgi/trace", log_output_to_file=True)
    if c == 0 and "colo=" in out:
        d = dict(l.split('=', 1) for l in out.splitlines() if '=' in l)
        print_success(f"Edge: {Colors.WHITE}{d.get('colo')} / {d.get('ip')}{Colors.ENDC}")
        return True, d
    print_warning("No CF trace found.")
    return False, {}

def step_cf_forced(domain):
    print_subheader("11. Force Resolve (1.1.1.1)")
    c, _ = run_command(f"curl -I -k --resolve {domain}:443:1.1.1.1 https://{domain}", log_output_to_file=True)
    if c == 0: 
        print_success("Connected via 1.1.1.1.")
        return True
    print_fail("Failed via 1.1.1.1.")
    return False

def step_origin(domain, ip):
    print_subheader("12. Direct Origin")
    c, out = run_command(f"curl -I -k --connect-timeout 10 --resolve {domain}:443:{ip} https://{domain}", log_output_to_file=True)
    if c == 0:
        print_success("Origin Connected.")
        return True, "SUCCESS"
    print_fail("Origin Failed.")
    return False, "TIMEOUT" if c == 28 else "ERROR"

# --- Orchestrator ---

def run_diagnostics(domain, origin_ip=None):
    # This runs all steps for a single domain
    
    # Setup Log File
    reports_dir = "reports"
    if not os.path.exists(reports_dir): os.makedirs(reports_dir)
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    log_file = os.path.join(reports_dir, f"{domain}_{timestamp}.txt")
    
    print_header(f"DIAGNOSING: {domain}")
    logger.log_file(f"Domain: {domain}\nDate: {timestamp}")

    # Run Steps
    dns_ok, ipv4, ipv6 = step_dns(domain)
    dnssec_status = step_dnssec(domain)
    step_domain_status(domain)
    
    http_res = step_http(domain)
    step_http3_udp(domain) # New Feature
    
    ssl_ok = step_ssl(domain)
    tcp_ok = step_tcp(domain)
    mtu_ok = step_mtu(domain)
    step_traceroute(domain)
    cf_trace_ok = step_cf_trace(domain)
    step_cf_forced(domain)
    
    origin_res = None
    if origin_ip:
        origin_res = step_origin(domain, origin_ip)

    # Save
    logger.save_to_file(log_file)
    
    # Return summary dict for batch mode
    return {
        "domain": domain,
        "dns": "OK" if dns_ok else "FAIL",
        "http": http_res[0],
        "tcp": "OK" if tcp_ok else "FAIL",
        "dnssec": dnssec_status,
        "log": log_file
    }

def main():
    global logger
    
    parser = argparse.ArgumentParser(description="Cloudflare & Connectivity Diagnostic Tool")
    parser.add_argument("domain", help="Domain to diagnose", nargs='?')
    parser.add_argument("--origin", help="Origin IP for direct test")
    parser.add_argument("--file", help="Batch mode: file with list of domains")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--version", action="version", version=f"cfdiag {VERSION}")
    parser.add_argument("--update", action="store_true")
    
    args = parser.parse_args()
    
    if args.update:
        self_update()
        return

    if args.no_color: Colors.disable()

    check_dependencies()

    if args.file:
        # Batch Mode
        if not os.path.exists(args.file):
            print(f"File not found: {args.file}")
            sys.exit(1)
            
        print(f"\n{Colors.BOLD}{Colors.HEADER}=== BATCH MODE STARTED ==={Colors.ENDC}\n")
        print(f"{ 'DOMAIN':<30} | {'DNS':<6} | {'HTTP':<15} | {'TCP':<6} | {'DNSSEC':<10}")
        print("-" * 80)
        
        with open(args.file, 'r') as f:
            for line in f:
                d = line.strip()
                if not d: continue
                
                # Use a silent logger for execution, but capture result
                logger = FileLogger(silent=True)
                res = run_diagnostics(d)
                
                # Print Row
                print(f"{res['domain']:<30} | {res['dns']:<6} | {res['http']:<15} | {res['tcp']:<6} | {str(res['dnssec']):<10}")
        
        print(f"\n{Colors.OKGREEN}Batch Complete. Detailed reports in reports/{Colors.ENDC}")
        
    elif args.domain:
        # Single Mode
        logger = FileLogger(silent=False)
        target_domain = args.domain.replace("http://", "").replace("https://", "").strip("/")
        run_diagnostics(target_domain, args.origin)
        print(f"\n{Colors.OKBLUE}📄 Report saved.{Colors.ENDC}")
        
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
