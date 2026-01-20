#!/usr/bin/env python3
"""
cfdiag - Cloudflare & Connectivity Diagnostic Tool

A cross-platform (Linux/macOS/Windows) CLI tool to diagnose Cloudflare Error 522 
(Connection Timed Out) and other origin/edge connectivity issues.

It orchestrates native system tools and Python libraries to gather 
diagnostics and presents a structured, actionable summary.

Usage:
    python3 cfdiag.py <domain> [--origin <ip>]

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

# --- Configuration & Constants ---

VERSION = "1.1.0"
SEPARATOR = "=" * 60
SUB_SEPARATOR = "-" * 60

# Cloudflare compatible ports
CF_PORTS = [8443, 2053, 2083, 2087, 2096] # HTTPS ports

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
    
    # Backgrounds
    BG_FAIL = '\033[41m'
    BG_SUCCESS = '\033[42m'

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
        pass # older windows might fail, colors will just be raw or we disable them via args

class FileLogger:
    """Handles printing to stdout and buffering for clean file output."""
    def __init__(self):
        self.file_buffer = []
        self.ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|[0-9A-FF]|[0-?]*[ -/]*[@-~])')

    def log_console(self, msg="", end="\n", flush=False):
        """Prints directly to console only."""
        print(msg, end=end, flush=flush)

    def log_file(self, msg, end="\n"):
        """Appends to file buffer only (strips ANSI codes just in case)."""
        clean_msg = self.ansi_escape.sub('', msg)
        self.file_buffer.append(clean_msg + end)

    def log(self, msg="", file_msg=None, end="\n", flush=False):
        """
        Prints to console and appends to file buffer.
        If file_msg is provided, it uses that for the file buffer instead of msg.
        """
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
            print(f"{Colors.FAIL}Error saving log: {e}{Colors.ENDC}")
            return False

# Global logger instance
logger = FileLogger()

# --- Helper Functions ---

def print_header(title):
    logger.log_console(f"\n{Colors.BOLD}{Colors.HEADER}{SEPARATOR}")
    logger.log_console(f" {title}")
    logger.log_console(f"{SEPARATOR}{Colors.ENDC}")
    
    # Clean file format
    logger.log_file(f"\n# {title}")
    logger.log_file("=" * len(title))

def print_subheader(title):
    logger.log_console(f"\n{Colors.BOLD}{Colors.OKCYAN}>>> {title}{Colors.ENDC}")
    logger.log_console(f"{Colors.GREY}{SUB_SEPARATOR}{Colors.ENDC}")
    
    # Clean file format
    logger.log_file(f"\n## {title}")

def print_success(msg):
    logger.log(f"{Colors.OKGREEN}{Colors.BOLD}✔ [PASS]{Colors.ENDC} {msg}", 
               file_msg=f"[PASS] {msg}")

def print_fail(msg):
    logger.log(f"{Colors.FAIL}{Colors.BOLD}✖ [FAIL]{Colors.ENDC} {msg}",
               file_msg=f"[FAIL] {msg}")

def print_info(msg):
    logger.log(f"{Colors.OKBLUE}ℹ [INFO]{Colors.ENDC} {msg}",
               file_msg=f"[INFO] {msg}")

def print_warning(msg):
    logger.log(f"{Colors.WARNING}{Colors.BOLD}⚠ [WARN]{Colors.ENDC} {msg}",
               file_msg=f"[WARN] {msg}")

def print_cmd(cmd):
    logger.log_console(f"{Colors.GREY}$ {cmd}{Colors.ENDC}")
    logger.log_file(f"Command: {cmd}")

def check_dependencies():
    """Checks for curl, ping, traceroute equivalent."""
    missing = []
    
    # Check curl
    if not shutil.which("curl"):
        missing.append("curl")
    
    # Check traceroute/tracert
    trace_cmd = "tracert" if os.name == 'nt' else "traceroute"
    if not shutil.which(trace_cmd):
        if os.name != 'nt': # try fallback to /usr/sbin
             if not os.path.exists("/usr/sbin/traceroute"):
                 missing.append("traceroute")
    
    if missing:
        print_fail(f"Missing required system tools: {', '.join(missing)}")
        print("Please install them.")
        if os.name == 'nt':
             print("Note: Windows usually includes 'curl' and 'tracert' by default.")
        sys.exit(1)

def run_command(command, timeout=30, show_output=True, log_output_to_file=True):
    """
    Runs a shell command and returns a tuple (return_code, stdout).
    """
    try:
        process = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )
        
        output_lines = []
        
        while True:
            line = process.stdout.readline()
            if not line and process.poll() is not None:
                break
            if line:
                if show_output:
                    sys.stdout.write(line) 
                output_lines.append(line)
        
        full_output = "".join(output_lines)
        
        if log_output_to_file and full_output.strip():
             logger.log_file("Output:")
             indented = textwrap.indent(full_output, '    ')
             logger.log_file(indented)

        return_code = process.poll()
        return return_code, full_output

    except subprocess.TimeoutExpired:
        print_fail(f"Command timed out after {timeout} seconds.")
        logger.log_file(f"[TIMEOUT] Command timed out after {timeout} seconds.")
        return -1, "TIMEOUT"
    except Exception as e:
        print_fail(f"Error running command: {e}")
        logger.log_file(f"[ERROR] {e}")
        return -1, str(e)

# --- Diagnostic Steps (Cross-Platform) ---

def step_dns(domain):
    print_subheader("1. DNS Resolution & ASN/ISP Check")
    
    # Use native Python DNS first (Platform Independent)
    print_cmd(f"socket.gethostbyname_ex('{domain}')")
    try:
        _, _, ips = socket.gethostbyname_ex(domain)
        # Log this "command" output manually since we aren't using run_command
        logger.log_file("Output:")
        logger.log_file(f"    Resolved IPs: {', '.join(ips)}")
        
        print_success(f"DNS Resolved to: {Colors.WHITE}{', '.join(ips)}{Colors.ENDC}")
        
        # ISP/ASN Check using curl (Feature 2)
        if ips:
            target_ip = ips[0]
            # Simple check to skip private IPs
            if not target_ip.startswith("192.168.") and not target_ip.startswith("10.") and not target_ip.startswith("127."):
                cmd_asn = f"curl -s --connect-timeout 3 http://ip-api.com/json/{target_ip}"
                print_info(f"Identifying ISP for {target_ip}...")
                c2, out2 = run_command(cmd_asn, show_output=False, log_output_to_file=True)
                if c2 == 0:
                    try:
                        data = json.loads(out2)
                        isp = data.get("isp", "Unknown")
                        org = data.get("org", "Unknown")
                        country = data.get("country", "Unknown")
                        print_success(f"Host: {Colors.WHITE}{isp} ({org}) - {country}{Colors.ENDC}")
                    except json.JSONDecodeError:
                        print_warning("Could not parse ISP information.")
        return True, ips

    except socket.gaierror as e:
        logger.log_file(f"    Error: {e}")
        print_fail(f"DNS resolution failed: {e}")
        return False, []

def step_dns_compare(domain):
    print_subheader("2. DNS Resolver Comparison (Local vs Public)")
    
    resolvers = [
        ("Google (8.8.8.8)", "8.8.8.8"),
        ("Cloudflare (1.1.1.1)", "1.1.1.1")
    ]
    
    all_match = True
    local_ips = []
    
    try:
        _, _, local_ips = socket.gethostbyname_ex(domain)
        local_ips.sort()
    except:
        pass # Local failed, handled in step 1

    for name, ip in resolvers:
        # We need a CLI tool for this. 'dig' is best, 'nslookup' is universal fallback.
        cmd = ""
        is_windows = os.name == 'nt'
        
        if shutil.which("dig"):
            cmd = f"dig @{ip} {domain} +short"
        elif is_windows:
            cmd = f"nslookup {domain} {ip}"
        else:
            print_warning(f"Skipping {name}: 'dig' not found and not on Windows.")
            continue

        print_cmd(cmd)
        code, output = run_command(cmd, log_output_to_file=True)
        
        public_ips = []
        if code == 0:
            if shutil.which("dig"):
                public_ips = [l.strip() for l in output.splitlines() if l.strip() and not l.startswith(';')]
            else: # nslookup parsing
                # Windows nslookup output is verbose. We look for lines after "Name:"
                capture = False
                for line in output.splitlines():
                    line = line.strip()
                    if line.startswith("Address:"):
                        # Extract IP
                        parts = line.split()
                        if len(parts) > 1:
                            public_ips.append(parts[1])
                    elif line.startswith("Addresses:"):
                        capture = True
                        parts = line.split()
                        if len(parts) > 1:
                            public_ips.append(parts[1])
                    elif capture and line and not line.startswith("Aliases:"):
                         # Continuation of IPs
                         public_ips.append(line)
            
            public_ips.sort()
            
            # Simple intersection check (Cloudflare returns many IPs, might rotate)
            # If we got ANY valid IP, we consider it a resolve success. 
            # Exact matching logic is tricky with Anycast.
            if public_ips:
                if set(public_ips) == set(local_ips):
                    print_success(f"{name} matches local resolver.")
                else:
                    # It's common for them to differ in Anycast, so just WARN or INFO
                    # If local matches public, great. If not, it's just "Different".
                    print_info(f"{name} resolved to: {', '.join(public_ips)}")
            else:
                print_fail(f"{name} failed to resolve or output parse error.")
                all_match = False
        else:
            print_fail(f"{name} failed to resolve.")
            all_match = False
            
    return all_match

def step_http(domain):
    print_subheader("3. HTTP/HTTPS Availability & WAF Check")
    # Using curl is still best for protocol specific checks
    cmd = f"curl -I --connect-timeout 10 https://{domain}"
    print_cmd(cmd)
    
    code, output = run_command(cmd, log_output_to_file=True)
    
    status_code = 0
    waf_detected = False
    
    if code == 0:
        status_line = next((line for line in output.splitlines() if line.startswith("HTTP/")), None)
        
        if status_line:
            parts = status_line.split()
            if len(parts) >= 2:
                try:
                    status_code = int(parts[1])
                except ValueError:
                    pass
            
            # WAF/Challenge Logic
            if status_code in [403, 503]:
                print_warning(f"Status {status_code} detected. Checking for Cloudflare WAF/Challenge...")
                cmd_body = f"curl -s -A 'Mozilla/5.0' --connect-timeout 5 https://{domain}"
                c2, out2 = run_command(cmd_body, show_output=False, log_output_to_file=False)
                if c2 == 0:
                    if "Just a moment..." in out2 or "cf-captcha-container" in out2 or "challenge-platform" in out2:
                        waf_detected = True
                        print_warning(f"{Colors.BOLD}Cloudflare Managed Challenge / CAPTCHA detected.{Colors.ENDC}")

            if 200 <= status_code < 400:
                print_success(f"Response received: {Colors.WHITE}{Colors.BOLD}{status_line.strip()}{Colors.ENDC}")
                return "SUCCESS", status_code, False
            elif 400 <= status_code < 500:
                if waf_detected:
                    return "WAF_BLOCK", status_code, True
                else:
                    print_warning(f"Client Error received: {Colors.WHITE}{Colors.BOLD}{status_line.strip()}{Colors.ENDC}")
                    return "CLIENT_ERROR", status_code, False
            elif status_code >= 500:
                if waf_detected: # 503 is common for "Under Attack Mode"
                    return "WAF_BLOCK", status_code, True
                else:
                    print_fail(f"Server Error received: {Colors.WHITE}{Colors.BOLD}{status_line.strip()}{Colors.ENDC}")
                    return "SERVER_ERROR", status_code, False
            else:
                 print_warning(f"Unexpected status: {status_line.strip()}")
                 return "WEIRD", status_code, False
        else:
            print_warning("Connection successful, but no HTTP status header found.")
            return "WEIRD", 0, False
    elif code == 28: # curl timeout
        print_fail("Connection timed out (Likely 522 cause).")
        return "TIMEOUT", 0, False
    else:
        print_fail(f"curl failed with exit code {code}.")
        return "ERROR", 0, False

def step_ssl(domain):
    print_subheader("4. SSL/TLS Certificate Check")
    print_cmd(f"ssl.get_server_certificate(({domain}, 443))")
    
    # Use native Python SSL
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                # cert is a dict
                not_after = cert.get('notAfter')
                if not_after:
                    print_success(f"Certificate Expiry: {Colors.WHITE}{not_after}{Colors.ENDC}")
                    logger.log_file(f"Output: Expiry {not_after}")
                    return True
                else:
                    print_warning("Could not retrieve certificate dates.")
                    return False
    except Exception as e:
        print_fail(f"SSL Handshake failed: {e}")
        logger.log_file(f"Error: {e}")
        return False

def step_tcp(domain, port=443):
    if port == 443:
        print_subheader("5. TCP Connectivity Test (Port 443)")
    
    print_cmd(f"socket.connect(({domain}, {port}))")
    
    try:
        with socket.create_connection((domain, port), timeout=5):
            print_success(f"TCP connection to port {port} established.")
            logger.log_file("Output: Connected successfully")
            return True
    except Exception as e:
        if port == 443:
            print_fail(f"Failed to establish TCP connection: {e}")
        logger.log_file(f"Error: {e}")
        return False

def step_alt_ports(domain):
    print_subheader("6. Alternative Cloudflare Port Scan")
    print_info("Scanning other Cloudflare HTTPS ports to find a workaround...")
    
    open_ports = []
    for port in CF_PORTS:
        if step_tcp(domain, port=port): # Reuse the silent python socket check logic essentially
            # step_tcp prints success, which is what we want
            open_ports.append(port)
            
    if open_ports:
        return True, open_ports
    else:
        print_warning("No alternative HTTPS ports (8443, 2053, etc.) are open.")
        return False, []

def step_mtu(domain):
    print_subheader("7. MTU / Fragmentation Check")
    print_info("Testing packet size 1472 (1500 MTU) to detect fragmentation issues.")
    
    system = platform.system()
    cmd = ""
    cmd_small = ""
    
    if system == "Darwin":
        cmd = f"ping -c 1 -D -s 1472 {domain}"
        cmd_small = f"ping -c 1 -D -s 1252 {domain}"
    elif system == "Linux":
        cmd = f"ping -c 1 -M do -s 1472 {domain}"
        cmd_small = f"ping -c 1 -M do -s 1252 {domain}"
    elif system == "Windows":
        cmd = f"ping -n 1 -f -l 1472 {domain}"
        cmd_small = f"ping -n 1 -f -l 1252 {domain}"
        
    print_cmd(cmd)
    code, output = run_command(cmd, log_output_to_file=True)
    
    if code == 0 and "0% loss" in output: # Windows output parsing needs care, but usually 0 exit code is success
        print_success("Packet size 1472 (standard MTU) passed.")
        return True
    else:
        print_warning("Large packet failed. Retrying with safe size (1280 bytes)...")
        c2, out2 = run_command(cmd_small, log_output_to_file=True)
        if c2 == 0:
            print_fail("MTU ISSUE DETECTED: Standard packets drop, but small packets pass.")
            print_info("This often indicates a Path MTU Discovery blackhole somewhere in the route.")
        else:
             print_warning("Even small packets failed. Likely a general connectivity block.")
        return False

def step_traceroute(domain):
    print_subheader("8. Network Path (Traceroute)")
    
    cmd = ""
    if os.name == 'nt':
        cmd = f"tracert -h 15 {domain}" # -h max_hops
    else:
        cmd = f"traceroute -m 15 -w 2 {domain}"
        
    print_cmd(cmd)
    print_info("Tracing path (max 15 hops)...")
    
    code, output = run_command(cmd, timeout=60, log_output_to_file=True)
    
    if code == 0:
        print_success("Traceroute completed.")
        return True
    else:
        print_warning("Traceroute did not exit cleanly.")
        return False

def step_cf_trace(domain):
    print_subheader("9. Cloudflare Debug Trace (cdn-cgi/trace)")
    cmd = f"curl -s --connect-timeout 5 https://{domain}/cdn-cgi/trace"
    print_cmd(cmd)
    
    code, output = run_command(cmd, log_output_to_file=True)
    
    if code == 0 and "colo=" in output:
        details = {}
        for line in output.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                details[k] = v
        
        colo = details.get("colo", "Unknown")
        ip = details.get("ip", "Unknown")
        warp = details.get("warp", "Unknown")
        
        print_success(f"Cloudflare Edge Reachable: {Colors.WHITE}Colo={colo}, YourIP={ip}, Warp={warp}{Colors.ENDC}")
        return True, details
    else:
        print_warning("Could not fetch /cdn-cgi/trace.")
        return False, {}

def step_cf_forced(domain):
    print_subheader("10. Cloudflare Forced Resolution Test")
    print_info("Attempting to connect via Cloudflare DNS resolver (1.1.1.1) to test edge reachability.")
    
    # We use -k (insecure)
    cmd = f"curl -I -k --resolve {domain}:443:1.1.1.1 https://{domain}"
    print_cmd(cmd)
    
    code, output = run_command(cmd, log_output_to_file=True)
    
    if code == 0:
        print_success("Successfully connected to Cloudflare Edge IP (1.1.1.1).")
        return True
    else:
        print_fail("Failed to connect to Cloudflare Edge IP (1.1.1.1).")
        return False

def step_origin_connect(domain, origin_ip):
    print_subheader("11. Direct Origin Connectivity Test")
    print_info(f"Attempting to bypass Cloudflare and connect directly to {origin_ip}...")
    
    cmd = f"curl -I --connect-timeout 10 -k --resolve {domain}:443:{origin_ip} https://{domain}"
    print_cmd(cmd)
    
    code, output = run_command(cmd, log_output_to_file=True)
    
    if code == 0:
        status_line = next((line for line in output.splitlines() if line.startswith("HTTP/")), None)
        status_code = 0
        if status_line:
            parts = status_line.split()
            if len(parts) >= 2:
                try:
                    status_code = int(parts[1])
                except ValueError:
                    pass
            
            if 200 <= status_code < 500:
                print_success(f"Direct connection to Origin succeeded! (Status: {status_code})")
                return True, "SUCCESS"
            else:
                 print_fail(f"Origin returned an error: {status_line.strip()}")
                 return True, "ERROR" 
        else:
             print_warning("Connected to origin, but no status header.")
             return True, "WEIRD"
    elif code == 28:
        print_fail("Direct connection to Origin TIMED OUT.")
        return False, "TIMEOUT"
    else:
        print_fail(f"Direct connection failed (Exit Code {code}).")
        return False, "FAILED"

# --- Summary & Analysis ---

def generate_summary(domain, dns_res, http_res, tcp_res, cf_res, mtu_res, ssl_res, cf_trace_res, origin_res, alt_ports_res):
    print_header("DIAGNOSTIC SUMMARY")
    
    logger.log_console(f"Target: {Colors.BOLD}{domain}{Colors.ENDC}")
    logger.log_console(f"Time:   {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.log_console(Colors.GREY + "-" * 30 + Colors.ENDC)
    
    logger.log_file(f"Target: {domain}")
    logger.log_file(f"Time:   {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.log_file("-" * 30)
    
    conclusions = []
    
    # DNS Analysis
    if not dns_res[0]:
        conclusions.append((f"{Colors.FAIL}{Colors.BOLD}[CRITICAL]{Colors.ENDC} DNS Resolution failed.",
                            "[CRITICAL] DNS Resolution failed."))
    else:
        conclusions.append((f"{Colors.OKGREEN}{Colors.BOLD}[PASS]{Colors.ENDC} DNS is resolving correctly.",
                            "[PASS] DNS is resolving correctly."))

    # SSL
    if ssl_res:
         conclusions.append((f"{Colors.OKGREEN}{Colors.BOLD}[PASS]{Colors.ENDC} SSL Certificate is valid.",
                             "[PASS] SSL Certificate is valid."))
    else:
         conclusions.append((f"{Colors.WARNING}{Colors.BOLD}[WARN]{Colors.ENDC} SSL Certificate information could not be verified.",
                             "[WARN] SSL Certificate information could not be verified."))

    # TCP/Network Analysis
    if tcp_res:
         conclusions.append((f"{Colors.OKGREEN}{Colors.BOLD}[PASS]{Colors.ENDC} TCP (Port 443) is open.",
                             "[PASS] TCP (Port 443) is open."))
    else:
         conclusions.append((f"{Colors.FAIL}{Colors.BOLD}[CRITICAL]{Colors.ENDC} TCP connection failed.",
                             "[CRITICAL] TCP connection failed."))
         
         if alt_ports_res[0]:
             ports_str = ", ".join([str(p) for p in alt_ports_res[1]])
             conclusions.append((f"{Colors.OKGREEN}{Colors.BOLD}[WORKAROUND]{Colors.ENDC} Alternative Ports are OPEN: {ports_str}.",
                                 f"[WORKAROUND] Alternative Ports are OPEN: {ports_str}."))
    
    # MTU
    if mtu_res:
         conclusions.append((f"{Colors.OKGREEN}{Colors.BOLD}[PASS]{Colors.ENDC} Network path supports standard MTU (1500).",
                             "[PASS] Network path supports standard MTU (1500)."))
    else:
         conclusions.append((f"{Colors.WARNING}{Colors.BOLD}[WARN]{Colors.ENDC} MTU/Fragmentation issues detected.",
                             "[WARN] MTU/Fragmentation issues detected."))

    # HTTP Analysis
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
         elif http_code == 502:
             conclusions.append((f"{Colors.FAIL}{Colors.BOLD}[ALERT]{Colors.ENDC} Cloudflare 502: Bad Gateway (Origin invalid response/down).",
                                 "[ALERT] Cloudflare 502: Bad Gateway (Origin invalid response/down)."))
    elif http_status == "TIMEOUT":
        conclusions.append((f"{Colors.FAIL}{Colors.BOLD}[CRITICAL]{Colors.ENDC} HTTP Request Timed Out (Potential 522).",
                            "[CRITICAL] HTTP Request Timed Out (Potential 522)."))

    # Direct Origin
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

    # Edge Reachability
    if cf_res or cf_trace_res[0]:
        conclusions.append((f"{Colors.OKGREEN}{Colors.BOLD}[PASS]{Colors.ENDC} Cloudflare Edge Network is reachable.",
                            "[PASS] Cloudflare Edge Network is reachable."))
        if cf_trace_res[0]:
            colo = cf_trace_res[1].get('colo', 'N/A')
            conclusions.append((f"  -> Connected to Data Center: {Colors.WHITE}{colo}{Colors.ENDC}",
                                f"  -> Connected to Data Center: {colo}"))

    for console_msg, file_msg in conclusions:
        logger.log(console_msg, file_msg=file_msg)
    
    logger.log_console(f"\n{Colors.GREY}{SEPARATOR}{Colors.ENDC}")
    logger.log_console("This report can be copied and sent to your hosting provider or Cloudflare support.")
    logger.log_console(f"{Colors.GREY}{SEPARATOR}{Colors.ENDC}")
    
    logger.log_file("\n" + "=" * 60)
    logger.log_file("This report can be copied and sent to your hosting provider or Cloudflare support.")
    logger.log_file("=" * 60)

# --- Main Entry Point ---

def main():
    parser = argparse.ArgumentParser(description="Cloudflare & Connectivity Diagnostic Tool")
    parser.add_argument("domain", help="The target domain to diagnose (e.g., example.com)")
    parser.add_argument("--origin", help="Optional: Origin Server IP to test direct connectivity (Bypass Cloudflare)", default=None)
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("--version", action="version", version=f"cfdiag {VERSION}")
    
    args = parser.parse_args()
    
    if args.no_color:
        Colors.disable()

    target_domain = args.domain.replace("http://", "").replace("https://", "").strip("/")
    
    reports_dir = "reports"
    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir)
        
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    log_filename = os.path.join(reports_dir, f"{target_domain}_{timestamp}.txt")
    
    check_dependencies()
    
    print_header("CFDIAG - Connectivity Diagnostics")
    logger.log_console(f"Target Domain: {Colors.BOLD}{Colors.WHITE}{target_domain}{Colors.ENDC}")
    if args.origin:
        logger.log_console(f"Origin IP:     {Colors.BOLD}{Colors.OKCYAN}{args.origin}{Colors.ENDC}")
    logger.log_console(f"OS:            {platform.system()} {platform.release()}")
    logger.log_console(f"Date:          {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.log_console(f"Version:       {VERSION}")
    
    logger.log_file(f"Target Domain: {target_domain}")
    if args.origin:
        logger.log_file(f"Origin IP:     {args.origin}")
    logger.log_file(f"OS:            {platform.system()} {platform.release()}")
    logger.log_file(f"Date:          {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.log_file(f"Version:       {VERSION}")
    
    # Steps
    dns_ok, dns_ips = step_dns(target_domain)
    step_dns_compare(target_domain)
    http_result = step_http(target_domain)
    ssl_ok = step_ssl(target_domain)
    tcp_ok = step_tcp(target_domain)
    mtu_ok = step_mtu(target_domain)
    
    alt_ports_res = (False, [])
    if not tcp_ok or http_result[1] == 0: 
        alt_ports_res = step_alt_ports(target_domain)
    
    step_traceroute(target_domain)
    cf_trace_ok = step_cf_trace(target_domain)
    cf_ok = step_cf_forced(target_domain)

    origin_res = None
    if args.origin:
        origin_res = step_origin_connect(target_domain, args.origin)
    
    generate_summary(target_domain, (dns_ok, dns_ips), http_result, tcp_ok, cf_ok, mtu_ok, ssl_ok, cf_trace_ok, origin_res, alt_ports_res)
    
    if logger.save_to_file(log_filename):
        print(f"\n{Colors.OKBLUE}📄 Report saved to: {Colors.BOLD}{log_filename}{Colors.ENDC}")

if __name__ == "__main__":
    main()
