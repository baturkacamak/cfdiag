#!/usr/bin/env python3
"""
cfdiag - Cloudflare & Connectivity Diagnostic Tool

A cross-platform (Linux/macOS) CLI tool to diagnose Cloudflare Error 522 
(Connection Timed Out) and other origin/edge connectivity issues.

It orchestrates native system tools (dig, curl, nc, traceroute, openssl, ping) 
to gather diagnostics and presents a structured, actionable summary.

Usage:
    python3 cfdiag.py <domain>

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

# --- Configuration & Constants ---

SEPARATOR = "=" * 60
SUB_SEPARATOR = "-" * 60

# Required system tools
REQUIRED_TOOLS = ["dig", "curl", "nc", "traceroute", "openssl", "ping"]

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

class FileLogger:
    """Handles printing to stdout and buffering for clean file output."""
    def __init__(self):
        self.file_buffer = []
        self.ansi_escape = re.compile(r'\x1B(?:[@-Z\-_]|[\[0-?]*[ -/]*[@-~])')

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

def print_section_end():
    logger.log_file("") # Add spacing in file

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

def install_dependencies(missing_tools):
    """
    Attempts to install missing dependencies based on the OS.
    """
    system = platform.system()
    package_manager = None
    install_cmd = []
    
    # Map tools to package names for different managers
    pkg_map_apt = {
        'dig': 'dnsutils',
        'traceroute': 'traceroute',
        'nc': 'netcat', 
        'curl': 'curl',
        'openssl': 'openssl',
        'ping': 'iputils-ping'
    }
    pkg_map_dnf = { # RHEL/CentOS/Fedora
        'dig': 'bind-utils',
        'traceroute': 'traceroute',
        'nc': 'nmap-ncat',
        'curl': 'curl',
        'openssl': 'openssl',
        'ping': 'iputils'
    }
    pkg_map_pacman = { # Arch Linux
        'dig': 'bind',
        'traceroute': 'traceroute',
        'nc': 'gnu-netcat',
        'curl': 'curl',
        'openssl': 'openssl',
        'ping': 'iputils'
    }
    pkg_map_brew = { # macOS
        'dig': 'bind',
        'traceroute': 'traceroute',
        'nc': 'netcat',
        'curl': 'curl',
        'openssl': 'openssl',
        'ping': '' # usually preinstalled
    }
    
    if system == "Linux":
        if shutil.which("apt-get"):
            package_manager = "apt"
            install_cmd = ["sudo", "apt-get", "update", "&&", "sudo", "apt-get", "install", "-y"]
            pkg_map = pkg_map_apt
        elif shutil.which("dnf"):
            package_manager = "dnf"
            install_cmd = ["sudo", "dnf", "install", "-y"]
            pkg_map = pkg_map_dnf
        elif shutil.which("yum"):
            package_manager = "yum"
            install_cmd = ["sudo", "yum", "install", "-y"]
            pkg_map = pkg_map_dnf
        elif shutil.which("pacman"):
            package_manager = "pacman"
            install_cmd = ["sudo", "pacman", "-S", "--noconfirm"]
            pkg_map = pkg_map_pacman
    elif system == "Darwin":
        if shutil.which("brew"):
            package_manager = "brew"
            install_cmd = ["brew", "install"]
            pkg_map = pkg_map_brew
            
    if not package_manager:
        print_fail("Could not detect a supported package manager (apt, dnf, yum, pacman, brew).")
        return False
        
    packages_to_install = []
    for tool in missing_tools:
        if tool in pkg_map and pkg_map[tool]:
            packages_to_install.append(pkg_map[tool])
        elif tool not in pkg_map:
            packages_to_install.append(tool) # Fallback to tool name
            
    # Deduplicate
    packages_to_install = list(set(packages_to_install))
    
    if not packages_to_install:
        return False

    print_warning(f"Detected missing tools: {', '.join(missing_tools)}")
    logger.log_console(f"Proposed packages to install: {Colors.BOLD}{', '.join(packages_to_install)}{Colors.ENDC}")
    
    try:
        response = input(f"Do you want to try installing them automatically using '{package_manager}'? [y/N] ").lower()
    except KeyboardInterrupt:
        logger.log_console()
        return False

    if response != 'y':
        return False
        
    full_cmd = " ".join(install_cmd + packages_to_install)
    print_info(f"Running: {full_cmd}")
    
    # Run the installation
    try:
        ret = subprocess.call(full_cmd, shell=True)
        return ret == 0
    except Exception as e:
        print_fail(f"Installation failed: {e}")
        return False

def check_dependencies():
    """Checks if required native tools are installed."""
    missing = []
    for tool in REQUIRED_TOOLS:
        if shutil.which(tool) is None:
            missing.append(tool)
    
    if missing:
        if not install_dependencies(missing):
            print_fail(f"Missing required system tools: {', '.join(missing)}")
            logger.log_console("Please install them using your package manager (apt, brew, yum, etc.).")
            sys.exit(1)
        else:
             print_success("Dependencies installed successfully. Continuing...")

def run_command(command, timeout=30, show_output=True, log_output_to_file=True):
    """
    Runs a shell command and returns a tuple (return_code, stdout, stderr).
    If show_output is True, it prints stdout/stderr to the console in real-time.
    If log_output_to_file is True, it appends the output to the file log.
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
        
        # Stream output
        while True:
            line = process.stdout.readline()
            if not line and process.poll() is not None:
                break
            if line:
                if show_output:
                    sys.stdout.write(line) 
                output_lines.append(line)
        
        full_output = "".join(output_lines)
        
        # Log to file if requested, but formatted nicely
        if log_output_to_file and full_output.strip():
             logger.log_file("Output:")
             # Indent output for file readability
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

# --- Diagnostic Steps ---

def step_dns(domain):
    print_subheader("1. DNS Resolution Check")
    print_cmd(f"dig {domain} +short")
    
    code, output = run_command(f"dig {domain} +short", log_output_to_file=True)
    
    if code == 0 and output.strip():
        # Check if output looks like an IP address
        lines = [l.strip() for l in output.splitlines() if l.strip()]
        if lines:
            print_success(f"DNS Resolved to: {Colors.WHITE}{', '.join(lines)}{Colors.ENDC}")
            return True, lines
        else:
            print_fail("DNS returned empty result.")
            return False, []
    else:
        print_fail("DNS resolution failed.")
        return False, []

def step_dns_compare(domain):
    print_subheader("2. DNS Resolver Comparison (Local vs Public)")
    
    resolvers = [
        ("Google (8.8.8.8)", "8.8.8.8"),
        ("Cloudflare (1.1.1.1)", "1.1.1.1")
    ]
    
    all_match = True
    local_ips = []
    
    # Get local again for comparison context
    c, out = run_command(f"dig {domain} +short", show_output=False, log_output_to_file=False)
    if c == 0:
        local_ips = sorted([l.strip() for l in out.splitlines() if l.strip()])
    
    for name, ip in resolvers:
        cmd = f"dig @{ip} {domain} +short"
        print_cmd(cmd)
        code, output = run_command(cmd, log_output_to_file=True)
        
        if code == 0 and output.strip():
            public_ips = sorted([l.strip() for l in output.splitlines() if l.strip()])
            if public_ips == local_ips:
                print_success(f"{name} matches local resolver.")
            else:
                print_warning(f"{name} returned different IPs: {', '.join(public_ips)}")
                all_match = False
        else:
            print_fail(f"{name} failed to resolve.")
            all_match = False
            
    if all_match:
        return True
    else:
        return False

def step_http(domain):
    print_subheader("3. HTTP/HTTPS Availability (Primary Signal)")
    # Using 10 second connect timeout to detect drops quickly
    cmd = f"curl -I --connect-timeout 10 https://{domain}"
    print_cmd(cmd)
    
    code, output = run_command(cmd, log_output_to_file=True)
    
    if code == 0:
        # Parse status code
        status_line = next((line for line in output.splitlines() if line.startswith("HTTP/")), None)
        status_code = 0
        
        if status_line:
            parts = status_line.split()
            if len(parts) >= 2:
                try:
                    status_code = int(parts[1])
                except ValueError:
                    pass
            
            if 200 <= status_code < 400:
                print_success(f"Response received: {Colors.WHITE}{Colors.BOLD}{status_line.strip()}{Colors.ENDC}")
                return "SUCCESS", status_code
            elif 400 <= status_code < 500:
                print_warning(f"Client Error received: {Colors.WHITE}{Colors.BOLD}{status_line.strip()}{Colors.ENDC}")
                return "CLIENT_ERROR", status_code
            elif status_code >= 500:
                print_fail(f"Server Error received: {Colors.WHITE}{Colors.BOLD}{status_line.strip()}{Colors.ENDC}")
                return "SERVER_ERROR", status_code
            else:
                 print_warning(f"Unexpected status: {status_line.strip()}")
                 return "WEIRD", status_code
        else:
            print_warning("Connection successful, but no HTTP status header found.")
            return "WEIRD", 0
    elif code == 28: # curl timeout code
        print_fail("Connection timed out (Likely 522 cause).")
        return "TIMEOUT", 0
    else:
        print_fail(f"curl failed with exit code {code}.")
        return "ERROR", 0

def step_ssl(domain):
    print_subheader("4. SSL/TLS Certificate Check")
    # Using openssl to get dates
    cmd = f"echo | openssl s_client -servername {domain} -connect {domain}:443 2>/dev/null | openssl x509 -noout -dates"
    print_cmd(cmd)
    
    code, output = run_command(cmd, log_output_to_file=True)
    
    if code == 0 and "notAfter=" in output:
        for line in output.splitlines():
            if "notAfter=" in line:
                print_success(f"Certificate Expiry: {Colors.WHITE}{line.replace('notAfter=', '')}{Colors.ENDC}")
        return True
    else:
        print_warning("Could not retrieve SSL certificate dates (or not using SSL).")
        return False

def step_tcp(domain):
    print_subheader("5. TCP Connectivity Test (Port 443)")
    cmd = f"nc -vz -w 5 {domain} 443"
    print_cmd(cmd)
    
    code, output = run_command(cmd, log_output_to_file=True)
    
    if code == 0:
        print_success("TCP connection to port 443 established.")
        return True
    else:
        print_fail("Failed to establish TCP connection.")
        return False

def step_mtu(domain):
    print_subheader("6. MTU / Fragmentation Check")
    print_info("Testing packet size 1472 (1500 MTU) to detect fragmentation issues.")
    
    system = platform.system()
    if system == "Darwin": # macOS uses -D for "Do not fragment" (approx equivalent for test)
        cmd = f"ping -c 1 -D -s 1472 {domain}"
    else: # Linux uses -M do
        cmd = f"ping -c 1 -M do -s 1472 {domain}"
        
    print_cmd(cmd)
    code, output = run_command(cmd, log_output_to_file=True)
    
    if code == 0:
        print_success("Packet size 1472 (standard MTU) passed.")
        return True
    else:
        print_warning("Large packet failed. Retrying with safe size (1280 bytes)...")
        # Retry small
        if system == "Darwin":
            cmd_small = f"ping -c 1 -D -s 1252 {domain}" # 1280 - 28 header
        else:
            cmd_small = f"ping -c 1 -M do -s 1252 {domain}"
        
        c2, out2 = run_command(cmd_small, log_output_to_file=True)
        if c2 == 0:
            print_fail("MTU ISSUE DETECTED: Standard packets drop, but small packets pass.")
            print_info("This often indicates a Path MTU Discovery blackhole somewhere in the route.")
        else:
             print_warning("Even small packets failed. Likely a general connectivity block, not just MTU.")
        return False

def step_traceroute(domain):
    print_subheader("7. Network Path (Traceroute)")
    # traceroute can take a long time, so we just run it and show output
    cmd = f"traceroute -m 15 -w 2 {domain}" # Max 15 hops, 2s wait to speed up
    print_cmd(cmd)
    print_info("Tracing path (max 15 hops)...")
    
    code, output = run_command(cmd, timeout=60, log_output_to_file=True)
    
    if code == 0:
        print_success("Traceroute completed.")
        return True
    else:
        print_warning("Traceroute did not exit cleanly (common if firewalls block ICMP).")
        return False

def step_cf_trace(domain):
    print_subheader("8. Cloudflare Debug Trace (cdn-cgi/trace)")
    cmd = f"curl -s --connect-timeout 5 https://{domain}/cdn-cgi/trace"
    print_cmd(cmd)
    
    code, output = run_command(cmd, log_output_to_file=True)
    
    if code == 0 and "colo=" in output:
        # Extract interesting fields
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
        print_warning("Could not fetch /cdn-cgi/trace. Site might not be on Cloudflare or is blocking this path.")
        return False, {}

def step_cf_forced(domain):
    print_subheader("9. Cloudflare Forced Resolution Test")
    print_info("Attempting to connect via Cloudflare DNS resolver (1.1.1.1) to test edge reachability.")
    print_info("Note: This tests network path to a known Cloudflare IP. Certificate errors are expected.")
    
    # We use -k (insecure) because 1.1.1.1 won't match the domain cert, 
    # but we care about the TCP/HTTP connection capability here.
    cmd = f"curl -I -k --resolve {domain}:443:1.1.1.1 https://{domain}"
    print_cmd(cmd)
    
    code, output = run_command(cmd, log_output_to_file=True)
    
    if code == 0:
        print_success("Successfully connected to Cloudflare Edge IP (1.1.1.1).")
        return True
    else:
        print_fail("Failed to connect to Cloudflare Edge IP (1.1.1.1).")
        return False

# --- Summary & Analysis ---

def generate_summary(domain, dns_res, http_res, tcp_res, cf_res, mtu_res, ssl_res, cf_trace_res):
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
    
    # MTU
    if mtu_res:
         conclusions.append((f"{Colors.OKGREEN}{Colors.BOLD}[PASS]{Colors.ENDC} Network path supports standard MTU (1500).",
                             "[PASS] Network path supports standard MTU (1500)."))
    else:
         conclusions.append((f"{Colors.WARNING}{Colors.BOLD}[WARN]{Colors.ENDC} MTU/Fragmentation issues detected.",
                             "[WARN] MTU/Fragmentation issues detected. Check your network configuration."))

    # HTTP Analysis (The core of 522)
    http_status, http_code = http_res
    
    if http_status == "SUCCESS":
        conclusions.append((f"{Colors.OKGREEN}{Colors.BOLD}[PASS]{Colors.ENDC} HTTP requests are working (Code {http_code}).",
                            f"[PASS] HTTP requests are working (Code {http_code})."))
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
    else:
        conclusions.append((f"{Colors.WARNING}{Colors.BOLD}[WARN]{Colors.ENDC} HTTP check failed/weird status.",
                            "[WARN] HTTP check failed/weird status."))

    # Cloudflare Edge Analysis
    if cf_res or cf_trace_res[0]:
        conclusions.append((f"{Colors.OKGREEN}{Colors.BOLD}[PASS]{Colors.ENDC} Cloudflare Edge Network is reachable.",
                            "[PASS] Cloudflare Edge Network is reachable."))
        if cf_trace_res[0]:
            colo = cf_trace_res[1].get('colo', 'N/A')
            conclusions.append((f"  -> Connected to Data Center: {Colors.WHITE}{colo}{Colors.ENDC}",
                                f"  -> Connected to Data Center: {colo}"))
    else:
         conclusions.append((f"{Colors.WARNING}{Colors.BOLD}[WARN]{Colors.ENDC} Could not verify Cloudflare Edge reachability.",
                             "[WARN] Could not verify Cloudflare Edge reachability."))

    # Final Verdict - Print loop
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
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    
    args = parser.parse_args()
    
    # Handle Colors
    if args.no_color:
        for attr in dir(Colors):
            if not attr.startswith("__"):
                setattr(Colors, attr, "")

    # Basic cleanup of domain input (remove protocol if user pasted it)
    target_domain = args.domain.replace("http://", "").replace("https://", "").strip("/")
    
    # Generate log filename
    reports_dir = "reports"
    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir)
        
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    log_filename = os.path.join(reports_dir, f"{target_domain}_{timestamp}.txt")
    
    # 0. System Check
    check_dependencies()
    
    # 1. Header
    print_header("CFDIAG - Connectivity Diagnostics")
    logger.log_console(f"Target Domain: {Colors.BOLD}{Colors.WHITE}{target_domain}{Colors.ENDC}")
    logger.log_console(f"OS:            {platform.system()} {platform.release()}")
    logger.log_console(f"Date:          {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    logger.log_file(f"Target Domain: {target_domain}")
    logger.log_file(f"OS:            {platform.system()} {platform.release()}")
    logger.log_file(f"Date:          {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # 2. DNS
    dns_ok, dns_ips = step_dns(target_domain)
    
    # 2.5 DNS Compare (New)
    step_dns_compare(target_domain)
    
    # 3. HTTP HEAD (Primary 522 Check)
    http_result = step_http(target_domain)
    
    # 3.5 SSL Check (New)
    ssl_ok = step_ssl(target_domain)
    
    # 4. TCP Connect
    tcp_ok = step_tcp(target_domain)
    
    # 4.5 MTU Check (New)
    mtu_ok = step_mtu(target_domain)
    
    # 5. Traceroute
    step_traceroute(target_domain)
    
    # 6. CF Debug Trace (New)
    cf_trace_ok = step_cf_trace(target_domain)
    
    # 7. CF Force Resolve
    cf_ok = step_cf_forced(target_domain)
    
    # 8. Summary
    generate_summary(target_domain, (dns_ok, dns_ips), http_result, tcp_ok, cf_ok, mtu_ok, ssl_ok, cf_trace_ok)
    
    # 9. Save Log
    if logger.save_to_file(log_filename):
        print(f"\n{Colors.OKBLUE}📄 Report saved to: {Colors.BOLD}{log_filename}{Colors.ENDC}")

if __name__ == "__main__":
    main()