#!/usr/bin/env python3
"""
cfdiag - Cloudflare & Connectivity Diagnostic Tool

A cross-platform (Linux/macOS/Windows) CLI tool to diagnose Cloudflare Error 522 
(Connection Timed Out) and other origin/edge connectivity issues.

It orchestrates native system tools and Python libraries to gather 
diagnostics and presents a structured, actionable summary.

Usage:
    python3 cfdiag.py <domain> [--origin <ip>] [--update]

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

VERSION = "1.2.0"
SEPARATOR = "=" * 60
SUB_SEPARATOR = "-" * 60
REPO_URL = "https://raw.githubusercontent.com/baturkacamak/cfdiag/main/cfdiag.py"

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
        pass 

class FileLogger:
    """Handles printing to stdout and buffering for clean file output."""
    def __init__(self):
        self.file_buffer = []
        self.ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|[\[0-?]*[ -/]*[@-~])')

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
    
    if not shutil.which("curl"):
        missing.append("curl")
    
    trace_cmd = "tracert" if os.name == 'nt' else "traceroute"
    if not shutil.which(trace_cmd):
        if os.name != 'nt': 
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

# --- Feature: Self Update ---

def self_update():
    print_info(f"Checking for updates (Current: {VERSION})...")
    try:
        with urllib.request.urlopen(REPO_URL, timeout=5) as response:
            if response.status != 200:
                print_fail("Could not check for updates (HTTP Error).")
                return

            new_code = response.read().decode('utf-8')
            
            # Simple regex to find version
            match = re.search(r'VERSION = "([\d\.]+)"', new_code)
            if match:
                new_version = match.group(1)
                if new_version > VERSION:
                    print_success(f"New version found: {new_version}")
                    try:
                        with open(sys.argv[0], 'w', encoding='utf-8') as f:
                            f.write(new_code)
                        print_success("Update successful! Please run the tool again.")
                        sys.exit(0)
                    except Exception as e:
                        print_fail(f"Could not overwrite file: {e}")
                        sys.exit(1)
                else:
                    print_success("You are already running the latest version.")
            else:
                print_warning("Could not parse version from remote file.")
    except Exception as e:
        print_fail(f"Update failed: {e}")

# --- Diagnostic Steps ---

def step_dns(domain):
    print_subheader("1. DNS Resolution & ASN/ISP Check (IPv4/IPv6)")
    
    ips = []
    ipv4 = []
    ipv6 = []
    
    print_cmd(f"socket.getaddrinfo('{domain}', 443)")
    try:
        # Fetch both IPv4 and IPv6
        info = socket.getaddrinfo(domain, 443, proto=socket.IPPROTO_TCP)
        for _, _, _, _, sockaddr in info:
            ip = sockaddr[0]
            if ip not in ips:
                ips.append(ip)
                if ':' in ip:
                    ipv6.append(ip)
                else:
                    ipv4.append(ip)
        
        # Log to file
        logger.log_file("Output:")
        logger.log_file(f"    IPv4: {', '.join(ipv4)}")
        logger.log_file(f"    IPv6: {', '.join(ipv6)}")
        
        if ipv4:
            print_success(f"IPv4 Resolved: {Colors.WHITE}{', '.join(ipv4)}{Colors.ENDC}")
        else:
            print_warning("No IPv4 records found.")
            
        if ipv6:
            print_success(f"IPv6 Resolved: {Colors.WHITE}{', '.join(ipv6)}{Colors.ENDC}")
        else:
            print_info("No IPv6 records found.")
        
        if not ips:
            print_fail("DNS returned empty result.")
            return False, [], []

        # ISP/ASN Check
        target_ip = ipv4[0] if ipv4 else (ipv6[0] if ipv6 else None)
        if target_ip:
             # Skip private
             if not target_ip.startswith("192.168.") and not target_ip.startswith("10.") and not target_ip.startswith("127.") and not target_ip.startswith("::1"):
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
                        pass

        return True, ipv4, ipv6

    except socket.gaierror as e:
        logger.log_file(f"    Error: {e}")
        print_fail(f"DNS resolution failed: {e}")
        return False, [], []

def step_domain_status(domain):
    print_subheader("2. Domain Registration Status (RDAP)")
    # Using rdap.org as a redirector/aggregator
    cmd = f"curl -s --connect-timeout 5 https://rdap.org/domain/{domain}"
    print_cmd(cmd)
    
    code, output = run_command(cmd, show_output=False, log_output_to_file=True)
    
    if code == 0:
        try:
            data = json.loads(output)
            # RDAP structure varies, but 'status' and 'events' are common
            statuses = data.get("status", [])
            if not statuses and "err" in data: # RDAP error
                 print_warning("RDAP query returned error (Domain might be private or TLD not supported).")
                 return
            
            # Filter statuses
            formatted_statuses = [s for s in statuses if "transfer" not in s] # remove transfer prohibitions clutter
            if formatted_statuses:
                print_success(f"Domain Status: {Colors.WHITE}{', '.join(formatted_statuses)}{Colors.ENDC}")
            
            # Check expiration
            events = data.get("events", [])
            expiry = None
            for event in events:
                if event.get("eventAction") == "expiration":
                    expiry = event.get("eventDate")
                    break
            
            if expiry:
                print_success(f"Expiration Date: {Colors.WHITE}{expiry}{Colors.ENDC}")
            else:
                print_info("Expiration date not found in RDAP response.")
                
        except json.JSONDecodeError:
            print_warning("Could not parse RDAP/Whois data.")
    else:
        print_warning("Failed to fetch domain registration info.")

def step_http(domain):
    print_subheader("3. HTTP/HTTPS Availability & WAF Check")
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
                if waf_detected:
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
    elif code == 28:
        print_fail("Connection timed out (Likely 522 cause).")
        return "TIMEOUT", 0, False
    else:
        print_fail(f"curl failed with exit code {code}.")
        return "ERROR", 0, False

def step_ssl(domain):
    print_subheader("4. SSL/TLS Certificate Check")
    print_cmd(f"ssl.get_server_certificate(({domain}, 443))")
    
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
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
    
    # We should try to connect to resolved IPs (dual stack check)
    # But socket.create_connection does this automatically (tries v6 then v4 or vice versa)
    # To be explicit for diagnostics, we might want to know WHICH one failed, 
    # but for a general "is it up" check, create_connection is best.
    
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
        if step_tcp(domain, port=port): 
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
    
    if code == 0:
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
        cmd = f"tracert -h 15 {domain}" 
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
    dns_ok, ipv4, ipv6 = dns_res
    if not dns_ok:
        conclusions.append((f"{Colors.FAIL}{Colors.BOLD}[CRITICAL]{Colors.ENDC} DNS Resolution failed.",
                            "[CRITICAL] DNS Resolution failed."))
    else:
        conclusions.append((f"{Colors.OKGREEN}{Colors.BOLD}[PASS]{Colors.ENDC} DNS is resolving correctly.",
                            "[PASS] DNS is resolving correctly."))
        if ipv6:
             conclusions.append((f"{Colors.OKGREEN}{Colors.BOLD}[PASS]{Colors.ENDC} IPv6 connectivity is available.",
                                 "[PASS] IPv6 connectivity is available."))
        else:
             conclusions.append((f"{Colors.WARNING}{Colors.BOLD}[INFO]{Colors.ENDC} No IPv6 records found (IPv4 only).",
                                 "[INFO] No IPv6 records found (IPv4 only)."))

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
    parser.add_argument("domain", help="The target domain to diagnose (e.g., example.com)", nargs='?')
    parser.add_argument("--origin", help="Optional: Origin Server IP to test direct connectivity (Bypass Cloudflare)", default=None)
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("--version", action="version", version=f"cfdiag {VERSION}")
    parser.add_argument("--update", action="store_true", help="Update the tool to the latest version")
    
    args = parser.parse_args()
    
    if args.update:
        self_update()
        return

    if not args.domain:
        parser.print_help()
        sys.exit(1)
    
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
    dns_ok, ipv4, ipv6 = step_dns(target_domain)
    step_domain_status(target_domain) # Feature 2: Domain Status
    # step_dns_compare(target_domain) # Disabling compare if we have comprehensive DNS step
    
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
    
    generate_summary(target_domain, (dns_ok, ipv4, ipv6), http_result, tcp_ok, cf_ok, mtu_ok, ssl_ok, cf_trace_ok, origin_res, alt_ports_res)
    
    if logger.save_to_file(log_filename):
        print(f"\n{Colors.OKBLUE}📄 Report saved to: {Colors.BOLD}{log_filename}{Colors.ENDC}")

if __name__ == "__main__":
    main()