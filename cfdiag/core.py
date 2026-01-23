import argparse
import datetime
import time
import os
import concurrent.futures
import sys
from typing import Dict, Any, Optional
from .utils import VERSION, get_context, set_context, console_lock, Colors
from .reporting import (
    FileLogger, set_logger, get_logger, 
    send_webhook, SEPARATOR,
    print_skip, print_subheader
)
from .network import (
    check_internet_connection, check_dependencies,
    step_dns, step_blacklist, step_dns_trace, step_propagation,
    step_dnssec, step_domain_status, step_http, step_security_headers,
    step_http3_udp, step_ssl, step_ocsp, step_tcp, step_mtu,
    step_traceroute, step_cf_trace, step_cf_forced, step_origin,
    step_alt_ports, step_waf_evasion,
    step_speed, step_doh, step_websocket, detect_cloudflare_usage,
    run_mtr
)
from .probes import probe_dns
from .system import step_lint_config, step_audit
from .server import run_diagnostic_server
from .log_analysis import analyze_logs

def load_config(profile_name: Optional[str] = None) -> Dict[str, Any]:
    from .utils import CONFIG_FILE_NAME
    from pathlib import Path
    import json
    
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
    import urllib.request
    import re
    import ssl
    from .utils import REPO_URL
    
    print(f"Checking for updates (Current: {VERSION})...")
    
    def fetch_url(context=None):
        with urllib.request.urlopen(REPO_URL, timeout=5, context=context) as response:
            if response.status != 200: return
            new_code = response.read().decode('utf-8')
            match = re.search(r'VERSION = "([\d\.]+)"', new_code)
            if match and match.group(1) > VERSION:
                print(f"New version found: {match.group(1)}")
                print("Please update via 'pip install --upgrade cfdiag' or your package manager.")
            else:
                print("You are already running the latest version.")

    try:
        # 1. Try secure default
        context = ssl.create_default_context()
        try:
            import certifi
            context.load_verify_locations(cafile=certifi.where())
        except ImportError:
            pass # certifi not installed, ignore
            
        fetch_url(context)
        
    except Exception as e:
        # 2. Fallback for macOS/Cert issues
        if "CERTIFICATE_VERIFY_FAILED" in str(e):
            try:
                # Only print if verbose? No, this is a direct user action (--update)
                print(f"{Colors.WARNING}SSL verification failed. Retrying unverified...{Colors.ENDC}")
                context = ssl._create_unverified_context()
                fetch_url(context)
                return
            except:
                pass
        print(f"Update failed: {e}")

def generate_grafana() -> None:
    from .dashboard import GRAFANA_JSON
    print(GRAFANA_JSON)

def generate_summary(domain, dns_res, http_res, tcp_res, cf_res, mtu_res, ssl_res, cf_trace_res, origin_res, alt_ports_res, dnssec_status, prop_status, history_diff) -> None:
    l = get_logger()
    if not l: return
    l.log_console(f"\n{Colors.BOLD}{Colors.HEADER}{SEPARATOR}", force=True)
    l.log_console(f" DIAGNOSTIC SUMMARY: {domain}", force=True)
    l.log_console(f"{SEPARATOR}{Colors.ENDC}", force=True)
    
    l.log_file(f"\n{SEPARATOR}", force=True)
    l.log_file(f" DIAGNOSTIC SUMMARY", force=True)
    l.log_file(f"{SEPARATOR}", force=True)
    
    # Initialize Cloudflare detection variable (used later for timeout message and summary)
    cloudflare_in_use = False
    
    dns_ok, ipv4, ipv6 = dns_res
    if not dns_ok:
        l.log(f"{Colors.FAIL}{Colors.BOLD}[CRITICAL]{Colors.ENDC} DNS Resolution failed.", file_msg="[CRITICAL] DNS Resolution failed.", force=True)
        l.log(f"{Colors.GREY}Note: Dependent checks (TCP, SSL, HTTP) were skipped due to DNS failure.{Colors.ENDC}", file_msg="Note: Dependent checks (TCP, SSL, HTTP) were skipped due to DNS failure.", force=True)
    else:
        l.log(f"{Colors.OKGREEN}{Colors.BOLD}[PASS]{Colors.ENDC} DNS is resolving correctly.", file_msg="[PASS] DNS is resolving correctly.", force=True)

    if prop_status != "N/A":
        if prop_status == "MATCH":
            l.log(f"{Colors.OKGREEN}{Colors.BOLD}[PASS]{Colors.ENDC} Propagation Complete.", file_msg="[PASS] Propagation Complete.", force=True)
        else:
            l.log(f"{Colors.WARNING}{Colors.BOLD}[WARN]{Colors.ENDC} Propagation Issue ({prop_status}).", file_msg=f"[WARN] Propagation Issue ({prop_status}).", force=True)

    if dnssec_status == "BROKEN":
        l.log(f"{Colors.FAIL}{Colors.BOLD}[CRITICAL]{Colors.ENDC} DNSSEC Broken.", file_msg="[CRITICAL] DNSSEC Broken.", force=True)
    elif dnssec_status == "SIGNED":
        l.log(f"{Colors.OKGREEN}{Colors.BOLD}[PASS]{Colors.ENDC} DNSSEC Signed.", file_msg="[PASS] DNSSEC Signed.", force=True)

    if dns_ok:
        if ssl_res:
             l.log(f"{Colors.OKGREEN}{Colors.BOLD}[PASS]{Colors.ENDC} SSL Certificate is valid.", file_msg="[PASS] SSL Certificate is valid.", force=True)
        else:
             l.log(f"{Colors.WARNING}{Colors.BOLD}[WARN]{Colors.ENDC} SSL Certificate information could not be verified.", file_msg="[WARN] SSL Certificate information could not be verified.", force=True)

        if tcp_res:
             l.log(f"{Colors.OKGREEN}{Colors.BOLD}[PASS]{Colors.ENDC} TCP (Port 443) is open.", file_msg="[PASS] TCP (Port 443) is open.", force=True)
        else:
             l.log(f"{Colors.FAIL}{Colors.BOLD}[CRITICAL]{Colors.ENDC} TCP connection failed.", file_msg="[CRITICAL] TCP connection failed.", force=True)

        if mtu_res:
             l.log(f"{Colors.OKGREEN}{Colors.BOLD}[PASS]{Colors.ENDC} MTU (1500) supported.", file_msg="[PASS] MTU (1500) supported.", force=True)
        else:
             l.log(f"{Colors.WARNING}{Colors.BOLD}[WARN]{Colors.ENDC} MTU/Fragmentation issue.", file_msg="[WARN] MTU/Fragmentation issue.", force=True)

        # Check Cloudflare usage before HTTP status evaluation (needed for timeout message)
        try:
            cloudflare_in_use = detect_cloudflare_usage(domain, ipv4 or [], ipv6 or [])
        except Exception:
            cloudflare_in_use = False

        http_status, http_code, is_waf, metrics = http_res
        if http_status == "SUCCESS":
            l.log(f"{Colors.OKGREEN}{Colors.BOLD}[PASS]{Colors.ENDC} HTTP requests are working (Code {http_code}).", file_msg=f"[PASS] HTTP requests are working (Code {http_code}).", force=True)
        elif http_status == "WAF_BLOCK":
            l.log(f"{Colors.WARNING}{Colors.BOLD}[BLOCK]{Colors.ENDC} Cloudflare WAF/Challenge detected (Code {http_code}).", file_msg=f"[BLOCK] Cloudflare WAF/Challenge detected (Code {http_code}).", force=True)
        elif http_status == "CLIENT_ERROR":
             l.log(f"{Colors.WARNING}{Colors.BOLD}[WARN]{Colors.ENDC} Server returned Client Error (Code {http_code}).", file_msg=f"[WARN] Server returned Client Error (Code {http_code}).", force=True)
        elif http_status == "SERVER_ERROR":
             l.log(f"{Colors.FAIL}{Colors.BOLD}[CRITICAL]{Colors.ENDC} Server returned Error (Code {http_code}).", file_msg=f"[CRITICAL] Server returned Error (Code {http_code}).", force=True)
             if http_code == 522:
                l.log(f"{Colors.FAIL}{Colors.BOLD}[ALERT]{Colors.ENDC} Cloudflare 522: Connection Timed Out to Origin.", file_msg="[ALERT] Cloudflare 522: Connection Timed Out to Origin.", force=True)
             elif http_code == 525:
                l.log(f"{Colors.FAIL}{Colors.BOLD}[ALERT]{Colors.ENDC} Cloudflare 525: SSL Handshake Failed with Origin.", file_msg="[ALERT] Cloudflare 525: SSL Handshake Failed with Origin.", force=True)
        elif http_status == "TIMEOUT":
            # Only mention "Potential 522" if Cloudflare is actually in use
            if cloudflare_in_use or cf_trace_res[0]:
                l.log(f"{Colors.FAIL}{Colors.BOLD}[CRITICAL]{Colors.ENDC} HTTP Request Timed Out (Potential 522).", file_msg="[CRITICAL] HTTP Request Timed Out (Potential 522).", force=True)
            else:
                l.log(f"{Colors.FAIL}{Colors.BOLD}[CRITICAL]{Colors.ENDC} HTTP Request Timed Out.", file_msg="[CRITICAL] HTTP Request Timed Out.", force=True)
        elif http_status == "SKIPPED":
             l.log(f"{Colors.GREY}[SKIP] HTTP Check skipped.", file_msg="[SKIP] HTTP Check skipped.", force=True)

        if origin_res:
            connected, reason = origin_res
            if connected and reason == "SUCCESS":
                 l.log(f"{Colors.OKGREEN}{Colors.BOLD}[PASS]{Colors.ENDC} Direct Origin Connection SUCCEEDED.", file_msg="[PASS] Direct Origin Connection SUCCEEDED.", force=True)
                 if http_code in [522, 524, 502, 504]:
                      l.log(f"{Colors.FAIL}{Colors.BOLD}[DIAGNOSIS]{Colors.ENDC} Origin is UP but Cloudflare is failing.", file_msg="[DIAGNOSIS] Origin is UP but Cloudflare is failing.", force=True)
                      l.log("  -> CAUSE: Firewall is likely blocking Cloudflare IPs.", file_msg="  -> CAUSE: Firewall is likely blocking Cloudflare IPs.", force=True)
            elif not connected and reason == "TIMEOUT":
                 l.log(f"{Colors.FAIL}{Colors.BOLD}[CRITICAL]{Colors.ENDC} Direct Origin Connection TIMED OUT.", file_msg="[CRITICAL] Direct Origin Connection TIMED OUT.", force=True)
                 l.log(f"{Colors.FAIL}{Colors.BOLD}[DIAGNOSIS]{Colors.ENDC} Origin Server is DOWN or Unreachable.", file_msg="[DIAGNOSIS] Origin Server is DOWN or Unreachable.", force=True)

    # Cloudflare usage detection based on resolved IPs and NS records.
    # Only report Cloudflare Edge as reachable if target actually uses Cloudflare.
    # Note: cloudflare_in_use is already calculated above (before HTTP status check) for timeout message logic.
    # cf_trace_res[0] is True if /cdn-cgi/trace responded, which is a strong Cloudflare signal.
    if cloudflare_in_use or cf_trace_res[0]:
        l.log(f"{Colors.OKGREEN}{Colors.BOLD}[PASS]{Colors.ENDC} Cloudflare Edge Network is reachable.", file_msg="[PASS] Cloudflare Edge Network is reachable.", force=True)
    else:
        # No Cloudflare IP/NS match detected – make this explicit in the report.
        l.log(
            f"{Colors.OKBLUE}{Colors.BOLD}[INFO]{Colors.ENDC} Target is NOT using Cloudflare (Direct/Third-party hosting detected).",
            file_msg="[INFO] Target is NOT using Cloudflare (Direct/Third-party hosting detected).",
            force=True,
        )

    if history_diff:
        l.log_file("\n-- History Comparison --")
        l.log_console(f"\n{Colors.BOLD}-- History Comparison --{Colors.ENDC}", force=True)
        if 'ttfb_diff' in history_diff:
            diff = history_diff['ttfb_diff']
            sign = "+" if diff > 0 else ""
            color = Colors.FAIL if diff > 0.5 else Colors.OKGREEN
            msg = f"TTFB Change: {color}{sign}{diff:.2f}s{Colors.ENDC}"
            l.log(msg, file_msg=f"TTFB Change: {sign}{diff:.2f}s", force=True)

    l.log_console(f"\n{Colors.GREY}{SEPARATOR}{Colors.ENDC}", force=True)
    l.log_file(f"\n{SEPARATOR}")

def run_diagnostics(domain: str, origin_ip: Optional[str]=None, expected_ns: Optional[str]=None, export_metrics: bool=False, speed_test: bool=False, dns_benchmark: bool=False, doh_check: bool=False, audit: bool=False, ws_check: bool=False) -> Dict[str, Any]:
    reports_dir = "reports"
    domain_dir = os.path.join(reports_dir, domain)
    if not os.path.exists(domain_dir): os.makedirs(domain_dir)
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    log_file = os.path.join(domain_dir, f"{timestamp}.txt")
    
    l = get_logger()
    if l:
        l.html_data['domain'] = domain
        l.html_data['timestamp'] = timestamp
        l.log_console(f"\n{Colors.BOLD}{Colors.HEADER}DIAGNOSING: {domain}{Colors.ENDC}", force=True)
        l.log_file(f"# DIAGNOSIS: {domain}\nDate: {timestamp}", force=True)

    # Get DNS results first to determine ipv4/ipv6 and dns_ok
    probe_res = probe_dns(domain)
    ipv4 = probe_res.get("records", {}).get("A", [])
    ipv6 = probe_res.get("records", {}).get("AAAA", [])
    dns_ok = not probe_res.get("error") and (len(ipv4) > 0 or len(ipv6) > 0)
    
    # 1. Linear Diagnostic Flow
    step_dns(domain)
    
    if doh_check: step_doh(domain)
    
    if ipv4: step_blacklist(domain, ipv4[0])
    step_dns_trace(domain)
    prop_status = step_propagation(domain, expected_ns) if expected_ns else "N/A"
    dnssec_status = step_dnssec(domain)
    step_domain_status(domain)
    
    # State flags and human-readable status strings for dependent checks
    http_ok = False
    tcp_ok = False
    ssl_ok = False
    mtu_ok = False
    http_res = ("SKIPPED", 0, False, {})
    ssl_status = "N/A"
    mtu_status = "N/A"
    history_diff = None  # Initialize history_diff

    # If DNS failed, skip all downstream network checks entirely.
    if not dns_ok:
        print_subheader("7. HTTP/HTTPS Availability")
        print_skip("DNS resolution failed.")
        print_subheader("8. HTTP/3 (QUIC) Check")
        print_skip("DNS resolution failed.")
        print_subheader("9. SSL/TLS Check")
        print_skip("DNS resolution failed.")
        print_subheader("10. TCP Connectivity")
        print_skip("DNS resolution failed.")
        print_subheader("11. MTU Check")
        print_skip("DNS resolution failed.")
        # No TCP/SSL/HTTP/MTU executed when DNS failed.
    else:
        # 2. TCP Connectivity immediately after DNS.
        tcp_ok = step_tcp(domain)

        if not tcp_ok:
            # Dependency chain: when TCP fails, higher-level checks are skipped.
            skip_reason = "SKIPPED (No TCP Connection)"

            print_subheader("7. HTTP/HTTPS Availability")
            print_skip("SKIPPED (No TCP Connection)")
            http_res = (skip_reason, 0, False, {})

            print_subheader("9. SSL/TLS Check")
            print_skip("SKIPPED (No TCP Connection)")
            ssl_status = skip_reason

            print_subheader("11. MTU Check")
            print_skip("SKIPPED (No TCP Connection)")
            mtu_status = skip_reason
        else:
            # 7. HTTP Check (Depends on DNS + TCP)
            http_res = step_http(domain)
            if http_res is None:
                http_res = ("ERROR", 0, False, {})
            if http_res[1] > 0:
                http_ok = True

            # 7.5 Security Headers (Depends on HTTP)
            if http_ok:
                step_security_headers(domain)
            else:
                print_subheader("7.5. Security Header Audit")
                print_skip("Requires functional HTTP response.")

            # 8. HTTP/3 (Depends on DNS + TCP)
            step_http3_udp(domain)

            # 22. WebSocket (Depends on HTTP)
            if ws_check:
                if http_ok:
                    step_websocket(domain)
                else:
                    print_subheader("22. WebSocket Handshake Check")
                    print_skip("Requires functional HTTP.")

            # 9. SSL (Depends on DNS + TCP)
            ssl_ok = step_ssl(domain)
            ssl_status = "PASS" if ssl_ok else "FAIL"

            # 9.5 OCSP (Depends on SSL)
            if ssl_ok:
                step_ocsp(domain)
            else:
                print_subheader("9.5 OCSP Stapling Check")
                print_skip("Requires valid SSL.")

            # 11. MTU (Depends on TCP/Connectivity)
            mtu_ok = step_mtu(domain)
            mtu_status = "PASS" if mtu_ok else "WARN"
        
    # 16. Alt Ports (Depends on failed TCP, so if DNS OK but TCP Fail)
    alt_ports_res = (False, [])
    if dns_ok and not tcp_ok:
        alt_ports_res = step_alt_ports(domain)
    
    # 12. Traceroute (Depends on DNS)
    if dns_ok:
        step_traceroute(domain)
        
    # 13. CF Trace (Depends on HTTP)
    cf_trace_ok = (False, {})
    if http_ok:
        cf_trace_ok = step_cf_trace(domain)
    else:
        print_subheader("13. CF Trace")
        print_skip("Requires functional HTTP.")
        
    # 14. CF Forced (Environment check)
    cf_ok = step_cf_forced(domain)
    
    # 15. Origin (Depends on user input)
    origin_res = None
    if origin_ip:
         step_origin(domain, origin_ip)

    if l:
        l.save_to_file(log_file)
        l.save_html(os.path.join(domain_dir, f"{timestamp}.html"))
    
    return {
        "domain": domain,
        "dns": prop_status if expected_ns else ("OK" if dns_ok else "FAIL"),
        "http": http_res[0],
        "tcp": "OK" if tcp_ok else "FAIL",
        "ssl": ssl_status,
        "mtu": mtu_status,
        "dnssec": dnssec_status,
        "log": log_file,
        "details": {
            "ipv4": ipv4,
            "ipv6": ipv6,
            "ssl_ok": ssl_ok,
            "http_status": http_res[1],
            "http_metrics": http_res[3],
            "history_diff": history_diff
        }
    }

def run_diagnostics_wrapper(domain: str, origin: Optional[str], context: Dict[str, Any], expected_ns: Optional[str] = None, export_metrics: bool = False) -> Dict[str, Any]:
    l = FileLogger(verbose=True, silent=False)
    set_logger(l)
    set_context(context)
    return run_diagnostics(domain, origin, expected_ns, export_metrics=export_metrics)

def interactive_mode() -> None:
    """Interactive wizard mode for easier usage."""
    print(f"{Colors.BOLD}{Colors.HEADER}=== cfdiag Interactive Mode ==={Colors.ENDC}\n")
    
    # Get domain
    domain = input(f"{Colors.OKBLUE}Enter domain to diagnose: {Colors.ENDC}").strip()
    if not domain:
        print(f"{Colors.FAIL}Domain is required.{Colors.ENDC}")
        sys.exit(1)
    
    domain = domain.replace("http://", "").replace("https://", "").strip("/")
    
    # Ask for origin IP
    origin_input = input(f"{Colors.OKBLUE}Origin IP (optional, press Enter to skip): {Colors.ENDC}").strip()
    origin = origin_input if origin_input else None
    
    # Ask for expected nameserver
    expect_input = input(f"{Colors.OKBLUE}Expected nameserver substring for propagation check (optional): {Colors.ENDC}").strip()
    expected_ns = expect_input if expect_input else None
    
    # Ask for verbose mode
    verbose_input = input(f"{Colors.OKBLUE}Enable verbose output? (y/N): {Colors.ENDC}").strip().lower()
    verbose = verbose_input in ['y', 'yes']
    
    # Ask for output format
    print(f"\n{Colors.OKBLUE}Output format:")
    print("  1. Standard (default)")
    print("  2. JSON")
    print("  3. Markdown")
    print("  4. JUnit XML")
    print("  5. All formats{Colors.ENDC}")
    format_input = input(f"{Colors.OKBLUE}Choose (1-5, default 1): {Colors.ENDC}").strip() or "1"
    
    # Ask for advanced options
    metrics_input = input(f"{Colors.OKBLUE}Export Prometheus metrics? (y/N): {Colors.ENDC}").strip().lower()
    export_metrics = metrics_input in ['y', 'yes']
    
    # Setup context
    ctx = {
        'ipv4': False,
        'ipv6': False,
        'proxy': None,
        'keylog_file': None,
        'headers': None,
        'timeout': 10
    }
    
    silent = format_input == "2"  # JSON mode is silent
    l = FileLogger(verbose=verbose, silent=silent)
    set_logger(l)
    set_context(ctx)
    
    # Run diagnostics
    result = run_diagnostics(domain, origin, expected_ns, export_metrics=export_metrics)
    
    # Save additional formats
    if format_input in ["3", "5"]:
        l.save_markdown(os.path.join("reports", domain, f"{datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.md"))
    if format_input in ["4", "5"]:
        l.save_junit(os.path.join("reports", domain, "junit.xml"))
    if format_input == "2":
        import json
        print(json.dumps(result, indent=4))
    else:
        if not verbose:
            print(f"\n{Colors.OKGREEN}✓ Diagnostic complete! Reports saved to reports/{domain}/ folder.{Colors.ENDC}")

def generate_completion(shell: str) -> None:
    if shell == "bash":
        print("""
_cfdiag()
{
    local cur prev opts
    COMPREPLY=()
    cur=\"${COMP_WORDS[COMP_CWORD]}\"
    prev=\"${COMP_WORDS[COMP_CWORD-1]}\" 
    opts=\"--origin --expect --profile --file --threads --ipv4 --ipv6 --proxy --timeout --header --keylog --mtr --watch --json --markdown --junit --metrics --lint-config --analyze-logs --serve --grafana --completion --verbose --no-color --interactive --version --update\"

    if [[ ${cur} == -* ]] ; then
        COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
        return 0
    fi
}
complete -F _cfdiag cfdiag
        """.strip())
    elif shell == "zsh":
        print("""
#compdef cfdiag

_cfdiag() {
    local -a args
    args=(
        '--origin[Direct IP address of origin server]:ip:_hosts'
        '--expect[Expected nameserver substring for propagation check]:string'
        '--profile[Load profile from config]:string'
        '--file[Batch mode file path]:filename:_files'
        '--threads[Number of concurrent threads for batch mode]:int'
        '--ipv4[Force IPv4]'
        '--ipv6[Force IPv6]'
        '--proxy[HTTP Proxy URL]:url'
        '--timeout[Connection timeout in seconds]:int'
        '--header[Custom HTTP header]:string'
        '--keylog[SSL Keylog file]:filename:_files'
        '--mtr[Run interactive MTR trace]'
        '--watch[Run continuously every 5 seconds]'
        '--json[Output JSON to stdout]'
        '--markdown[Generate Markdown report]'
        '--junit[Generate JUnit XML report]'
        '--metrics[Export Prometheus metrics]'
        '--lint-config[Lint web server config file]:filename:_files'
        '--analyze-logs[Analyze web server access logs]:filename:_files'
        '--serve[Start diagnostic HTTP server on port]:port'
        '--grafana[Generate Grafana Dashboard JSON]'
        '--completion[Generate shell completion]:(bash zsh)'
        '--verbose[Enable verbose output]'
        '--no-color[Disable color output]'
        '--interactive[Run in interactive mode]'
        '--version[Show version]'
        '--update[Self-update tool]'
    )
    _arguments "${args[@]}"
}
        """.strip())
    else:
        print(f"Unsupported shell: {shell}")

def main() -> None: 
    import json
    
    parser = argparse.ArgumentParser(
        description="Professional-grade diagnostic tool for Cloudflare and connectivity issues.",
        epilog="""
Examples:
  %(prog)s example.com
  %(prog)s example.com --origin 1.2.3.4
  %(prog)s --file domains.txt --threads 20
  %(prog)s example.com --json | jq .
  %(prog)s --completion bash >> ~/.bashrc

For more information, visit: https://github.com/baturkacamak/cfdiag
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Core arguments
    core_group = parser.add_argument_group('Core Options')
    core_group.add_argument("domain", nargs='?', 
                           help="Domain name to diagnose (e.g. example.com)")
    core_group.add_argument("--origin", metavar="IP",
                           help="Direct IP address of origin server. Bypasses DNS and Cloudflare to test direct connectivity. Essential for verifying if firewall is blocking Cloudflare IPs.")
    core_group.add_argument("--expect", metavar="NS_SUBSTRING",
                           help="Check DNS propagation. Verifies if public resolvers return a nameserver matching the provided substring (e.g. 'ns1.digitalocean.com').")
    core_group.add_argument("--profile", metavar="NAME",
                           help="Load configuration profile from ~/.cfdiag.json or ./cfdiag.json")
    
    # Batch mode
    batch_group = parser.add_argument_group('Batch Mode')
    batch_group.add_argument("--file", metavar="FILENAME",
                            help="Batch mode: Read domains from file (one per line) and scan them in parallel")
    batch_group.add_argument("--threads", type=int, default=5, metavar="N",
                            help="Number of concurrent threads for batch mode (default: 5)")
    
    # Network options
    network_group = parser.add_argument_group('Network Options')
    ip_group = network_group.add_mutually_exclusive_group()
    ip_group.add_argument("--ipv4", action="store_true",
                         help="Force all checks (DNS, HTTP, Traceroute) to use IPv4 only")
    ip_group.add_argument("--ipv6", action="store_true",
                         help="Force all checks to use IPv6 only")
    network_group.add_argument("--proxy", metavar="URL",
                              help="Use HTTP/HTTPS proxy for all web requests (e.g. http://1.2.3.4:8080)")
    network_group.add_argument("--timeout", type=int, default=10, metavar="SECONDS",
                              help="Connection timeout in seconds (default: 10)")
    network_group.add_argument("--header", action="append", metavar="HEADER",
                              help="Add custom HTTP header (can be used multiple times). Format: 'X-Foo: Bar'")
    
    # Advanced diagnostics
    advanced_group = parser.add_argument_group('Advanced Diagnostics')
    advanced_group.add_argument("--keylog", metavar="FILE",
                               help="Save SSL/TLS session keys to file (for Wireshark decryption)")
    advanced_group.add_argument("--mtr", action="store_true",
                               help="Run interactive MTR (My Traceroute) with real-time statistics")
    advanced_group.add_argument("--watch", action="store_true",
                               help="Run diagnostics continuously, updating every 5 seconds (Ctrl+C to stop)")
    
    # Output formats
    output_group = parser.add_argument_group('Output Formats')
    output_group.add_argument("--json", action="store_true",
                             help="Output full diagnostic result as JSON to stdout (suppresses normal logging)")
    output_group.add_argument("--markdown", action="store_true",
                             help="Generate Markdown report file in addition to standard reports")
    output_group.add_argument("--junit", action="store_true",
                             help="Generate JUnit XML report file (useful for CI/CD integration)")
    output_group.add_argument("--metrics", action="store_true",
                             help="Export Prometheus-compatible metrics file")
    
    # Utility commands
    utility_group = parser.add_argument_group('Utility Commands')
    utility_group.add_argument("--lint-config", metavar="FILE",
                              help="Lint web server configuration file (nginx.conf, apache.conf, etc.) for Cloudflare Real IP directives")
    utility_group.add_argument("--analyze-logs", metavar="FILE",
                              help="Analyze web server access log file for common error patterns")
    utility_group.add_argument("--serve", type=int, nargs='?', const=8080, metavar="PORT",
                               help="Start diagnostic HTTP server on specified port (default: 8080)")
    utility_group.add_argument("--grafana", action="store_true",
                              help="Generate Grafana Dashboard JSON configuration")
    utility_group.add_argument("--completion", choices=['bash', 'zsh'], metavar="SHELL",
                              help="Generate shell completion script for bash or zsh")
    
    # General options
    general_group = parser.add_argument_group('General Options')
    general_group.add_argument("--verbose", "-v", action="store_true",
                              help="Enable verbose output. Shows full command outputs and detailed diagnostic information")
    general_group.add_argument("--no-color", action="store_true",
                              help="Disable colored output (useful for scripts or terminals without color support)")
    general_group.add_argument("--interactive", "-i", action="store_true",
                              help="Run in interactive mode - guided wizard for easier usage")
    general_group.add_argument("--version", action="version", version=f"cfdiag {VERSION}",
                              help="Show version number and exit")
    general_group.add_argument("--update", action="store_true",
                              help="Check for updates and display latest version information")
    
    args = parser.parse_args()
    
    # Handle interactive mode early
    if args.interactive:
        interactive_mode()
        return
    
    if args.update: self_update(); return
    if args.no_color: Colors.disable()
    if args.completion: generate_completion(args.completion); return
    if args.grafana: generate_grafana(); return
    if args.lint_config: step_lint_config(args.lint_config); return
    if args.analyze_logs: analyze_logs(args.analyze_logs); return
    if args.serve: run_diagnostic_server(args.serve); return

    config = load_config(args.profile)
    domain = args.domain or config.get("domain")
    origin = args.origin or config.get("origin")
    expected_ns = args.expect or config.get("expect")

    if not domain and not args.file: parser.print_help(); sys.exit(1)
    if not check_internet_connection(): print("No Internet."); sys.exit(1)
    check_dependencies()
    
    ctx = {
        'ipv4': args.ipv4,
        'ipv6': args.ipv6,
        'proxy': args.proxy,
        'keylog_file': args.keylog,
        'headers': args.header,
        'timeout': args.timeout
    }

    if args.file:
        if not os.path.exists(args.file):
            print(f"File not found: {args.file}")
            sys.exit(1)
        
        domains = []
        with open(args.file, 'r') as f:
            domains = [line.strip() for line in f if line.strip()]
            
        print(f"\n{Colors.BOLD}{Colors.HEADER}=== BATCH MODE STARTED ({len(domains)} domains, {args.threads} threads) ==={Colors.ENDC}\n")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {executor.submit(run_diagnostics_wrapper, d, origin, ctx, expected_ns, args.metrics): d for d in domains}
            for future in concurrent.futures.as_completed(futures):
                try:
                    res = future.result()
                    with console_lock:
                        print(f"Processed: {res['domain']}")
                except Exception as e:
                    with console_lock:
                        print(f"Error processing {futures[future]}: {e}")

        print(f"\n{Colors.OKGREEN}Batch Complete. Detailed reports in reports/{Colors.ENDC}")

    else:
        if args.mtr:
            run_mtr(domain)
            return

        silent = True if args.json else False
        l = FileLogger(verbose=args.verbose, silent=silent)
        set_logger(l)
        set_context(ctx)
        
        if args.watch:
            try:
                while True:
                    os.system('cls' if os.name == 'nt' else 'clear')
                    print(f"{Colors.BOLD}--- Watch Mode (Ctrl+C to stop) ---")
                    l = FileLogger(verbose=args.verbose, silent=silent)
                    set_logger(l)
                    
                    result = run_diagnostics(
                        domain.replace("http://", "").replace("https://", "").strip("/"),
                        origin,
                        expected_ns,
                        export_metrics=args.metrics
                    )
                    time.sleep(5)
            except KeyboardInterrupt:
                print("\nStopped.")
                sys.exit(0)
        else:
            result = run_diagnostics(
                domain.replace("http://", "").replace("https://", "").strip("/"),
                origin,
                expected_ns,
                export_metrics=args.metrics
            )
            
            if args.markdown:
                l.save_markdown(os.path.join("reports", domain, f"{datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.md"))
            if args.junit:
                l.save_junit(os.path.join("reports", domain, "junit.xml"))

            if args.json:
                print(json.dumps(result, indent=4))
            else:
                if not args.verbose: print(f"\n{Colors.OKBLUE}Reports saved to reports/{domain}/ folder.{Colors.ENDC}")

if __name__ == "__main__":
    main()