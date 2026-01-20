import argparse
import datetime
import time
import os
import concurrent.futures
from typing import Dict, Any, Optional
from .utils import VERSION, get_context, set_context, console_lock, Colors
from .reporting import (
    FileLogger, set_logger, get_logger, 
    save_history, save_metrics, print_header, 
    compare_reports, SEPARATOR
)
from .network import (
    check_internet_connection, check_dependencies,
    step_dns, step_blacklist, step_dns_trace, step_propagation,
    step_dnssec, step_domain_status, step_http, step_security_headers,
    step_http3_udp, step_ssl, step_ocsp, step_tcp, step_mtu,
    step_traceroute, step_cf_trace, step_cf_forced, step_origin,
    step_alt_ports, step_redirects, step_waf_evasion
)

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
    import sys
    from .utils import REPO_URL
    
    print(f"Checking for updates (Current: {VERSION})...")
    try:
        with urllib.request.urlopen(REPO_URL, timeout=5) as response:
            if response.status != 200: return
            new_code = response.read().decode('utf-8')
            match = re.search(r'VERSION = "([\d\.]+)"', new_code)
            if match and match.group(1) > VERSION:
                print(f"New version found: {match.group(1)}")
                # This self-update mechanism relies on the single-file structure.
                # In package mode, this is harder. We might deprecate it or rely on pip.
                print("Please update via 'pip install --upgrade cfdiag' or your package manager.")
            else:
                print("You are already running the latest version.")
    except Exception as e:
        print(f"Update failed: {e}")

def generate_summary(domain, dns_res, http_res, tcp_res, cf_res, mtu_res, ssl_res, cf_trace_res, origin_res, alt_ports_res, dnssec_status, prop_status, history_diff) -> None: 
    l = get_logger()
    if not l: return
    l.log_console(f"\n{Colors.BOLD}{Colors.HEADER}{SEPARATOR}", force=True)
    l.log_console(f" DIAGNOSTIC SUMMARY: {domain}", force=True)
    l.log_console(f"{SEPARATOR}{Colors.ENDC}", force=True)
    
    l.log_file(f"\n{SEPARATOR}", force=True)
    l.log_file(f" DIAGNOSTIC SUMMARY", force=True)
    l.log_file(f"{SEPARATOR}", force=True)
    
    dns_ok, ipv4, ipv6 = dns_res
    if not dns_ok:
        l.log(f"{Colors.FAIL}{Colors.BOLD}[CRITICAL]{Colors.ENDC} DNS Resolution failed.", file_msg="[CRITICAL] DNS Resolution failed.", force=True)
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
        l.log(f"{Colors.FAIL}{Colors.BOLD}[CRITICAL]{Colors.ENDC} HTTP Request Timed Out (Potential 522).", file_msg="[CRITICAL] HTTP Request Timed Out (Potential 522).", force=True)

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

    if cf_res or cf_trace_res[0]:
        l.log(f"{Colors.OKGREEN}{Colors.BOLD}[PASS]{Colors.ENDC} Cloudflare Edge Network is reachable.", file_msg="[PASS] Cloudflare Edge Network is reachable.", force=True)

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

def run_diagnostics(domain: str, origin_ip: Optional[str]=None, expected_ns: Optional[str]=None, export_metrics: bool=False) -> Dict[str, Any]:
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

    dns_ok, ipv4, ipv6 = step_dns(domain)
    if ipv4: step_blacklist(domain, ipv4[0])
    step_dns_trace(domain)
    prop_status = step_propagation(domain, expected_ns) if expected_ns else "N/A"
    dnssec_status = step_dnssec(domain)
    step_domain_status(domain)
    http_res = step_http(domain)
    step_security_headers(domain)
    step_http3_udp(domain)
    ssl_ok = step_ssl(domain)
    step_ocsp(domain)
    tcp_ok = step_tcp(domain)
    mtu_ok = step_mtu(domain)
    alt_ports_res = (False, [])
    if not tcp_ok: alt_ports_res = step_alt_ports(domain)
    step_traceroute(domain)
    cf_trace_ok = step_cf_trace(domain)
    cf_ok = step_cf_forced(domain)
    origin_res = step_origin(domain, origin_ip) if origin_ip else None
    
    step_redirects(domain)
    step_waf_evasion(domain)

    current_metrics = {
        "timestamp": time.time(),
        "http_status": http_res[1],
        "ttfb": http_res[3].get('ttfb', 0) if http_res[3] else 0
    }
    prev_data = save_history(domain, current_metrics)
    history_diff = {}
    if prev_data:
        history_diff['ttfb_diff'] = current_metrics['ttfb'] - prev_data.get('ttfb', 0)

    if export_metrics: save_metrics(domain, current_metrics)

    generate_summary(domain, (dns_ok, ipv4, ipv6), http_res, tcp_ok, cf_ok, mtu_ok, ssl_ok, cf_trace_ok, origin_res, alt_ports_res, dnssec_status, prop_status, history_diff)

    if l:
        l.save_to_file(log_file)
        l.save_html(os.path.join(domain_dir, f"{timestamp}.html"))
    
    return {
        "domain": domain,
        "dns": prop_status if expected_ns else ("OK" if dns_ok else "FAIL"),
        "http": http_res[0],
        "tcp": "OK" if tcp_ok else "FAIL",
        "dnssec": dnssec_status,
        "log": log_file,
        "details": {
            "ipv4": ipv4,
            "ipv6": ipv6,
            "ssl_ok": ssl_ok,
            "http_metrics": http_res[3],
            "history_diff": history_diff
        }
    }

def run_diagnostics_wrapper(domain: str, origin: Optional[str], expect: Optional[str], metrics: bool, verbose: bool, silent: bool, context: Dict[str, Any]) -> Dict[str, Any]:
    l = FileLogger(verbose=verbose, silent=silent)
    set_logger(l)
    set_context(context)
    return run_diagnostics(domain, origin, expect, metrics)

def generate_completion(shell: str) -> None:
    if shell == "bash":
        print("""
_cfdiag()
{
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    opts="--origin --expect --profile --file --verbose --no-color --diff --version --update --metrics --threads --ipv4 --ipv6 --proxy --json --completion"

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
        '--expect[Expected nameservers substring]:string'
        '--profile[Load profile from config]:string'
        '--file[Batch mode file path]:filename:_files'
        '--verbose[Enable verbose output]'
        '--no-color[Disable color output]'
        '--diff[Compare two reports]:filename:_files'
        '--version[Show version]'
        '--update[Self-update tool]'
        '--metrics[Export metrics]'
        '--threads[Number of threads]:number'
        '--ipv4[Force IPv4]'
        '--ipv6[Force IPv6]'
        '--proxy[HTTP Proxy URL]:url'
        '--json[Output JSON to stdout]'
        '--completion[Generate shell completion]:(bash zsh)'
    )
    _arguments "${args[@]}"
}
        """.strip())
    else:
        print(f"Unsupported shell: {shell}")

def main() -> None: 
    import json
    
    parser = argparse.ArgumentParser()
    parser.add_argument("domain", nargs='?')
    parser.add_argument("--origin")
    parser.add_argument("--expect")
    parser.add_argument("--profile")
    parser.add_argument("--file")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--diff", nargs=2)
    parser.add_argument("--version", action="version", version=f"cfdiag {VERSION}")
    parser.add_argument("--update", action="store_true")
    parser.add_argument("--metrics", action="store_true")
    parser.add_argument("--threads", type=int, default=5)
    
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--ipv4", action="store_true", help="Force IPv4")
    group.add_argument("--ipv6", action="store_true", help="Force IPv6")
    parser.add_argument("--proxy", help="Use HTTP Proxy (e.g. http://1.2.3.4:8080)")
    parser.add_argument("--json", action="store_true", help="Output JSON to stdout")
    parser.add_argument("--completion", choices=['bash', 'zsh'], help="Generate shell completion")
    
    args = parser.parse_args()
    
    if args.update: self_update(); return
    if args.no_color: Colors.disable()
    if args.diff: compare_reports(args.diff[0], args.diff[1]); return
    if args.completion: generate_completion(args.completion); return

    config = load_config(args.profile)
    domain = args.domain or config.get("domain")
    origin = args.origin or config.get("origin")
    expect = args.expect or config.get("expect")

    if not domain and not args.file: parser.print_help(); sys.exit(1)
    if not check_internet_connection(): print("No Internet."); sys.exit(1)
    check_dependencies()
    
    ctx = {
        'ipv4': args.ipv4,
        'ipv6': args.ipv6,
        'proxy': args.proxy
    }

    if args.file:
        if not os.path.exists(args.file):
            print(f"File not found: {args.file}")
            sys.exit(1)
        
        domains = []
        with open(args.file, 'r') as f:
            domains = [line.strip() for line in f if line.strip()]
            
        print(f"\n{Colors.BOLD}{Colors.HEADER}=== BATCH MODE STARTED ({len(domains)} domains, {args.threads} threads) ==={Colors.ENDC}\n")
        dns_header = "PROPAGATION" if args.expect else "DNS"
        print(f"{'DOMAIN':<30} | {dns_header:<12} | {'HTTP':<15} | {'TCP':<6} | {'DNSSEC':<10}")
        print("-" * 85)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {executor.submit(run_diagnostics_wrapper, d, origin, expect, args.metrics, False, True, ctx): d for d in domains}
            for future in concurrent.futures.as_completed(futures):
                try:
                    res = future.result()
                    with console_lock:
                        print(f"{res['domain']:<30} | {res['dns']:<12} | {res['http']:<15} | {res['tcp']:<6} | {str(res['dnssec']):<10}")
                except Exception as e:
                    with console_lock:
                        print(f"Error processing {futures[future]}: {e}")

        print(f"\n{Colors.OKGREEN}Batch Complete. Detailed reports in reports/{Colors.ENDC}")

    else:
        silent = True if args.json else False
        l = FileLogger(verbose=args.verbose, silent=silent)
        set_logger(l)
        set_context(ctx)
        
        result = run_diagnostics(domain.replace("http://", "").replace("https://", "").strip("/"), origin, expect, args.metrics)
        
        if args.json:
            print(json.dumps(result, indent=4))
        else:
            if not args.verbose: print(f"\n{Colors.OKBLUE}📄 Reports saved to reports/{domain}/ folder.{Colors.ENDC}")

if __name__ == "__main__":
    main()
