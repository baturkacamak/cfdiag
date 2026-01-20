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
    save_history, save_metrics, print_header, 
    compare_reports, send_webhook, SEPARATOR
)
from .network import (
    check_internet_connection, check_dependencies,
    step_dns, step_blacklist, step_dns_trace, step_propagation,
    step_dnssec, step_domain_status, step_http, step_security_headers,
    step_http3_udp, step_ssl, step_ocsp, step_tcp, step_mtu,
    step_traceroute, step_cf_trace, step_cf_forced, step_origin,
    step_alt_ports, step_redirects, step_waf_evasion,
    step_speed, step_dns_benchmark, step_doh, step_graph,
    get_traceroute_hops, ping_host
)
from .system import step_lint_config, step_audit

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
    from .utils import REPO_URL
    
    print(f"Checking for updates (Current: {VERSION})...")
    try:
        with urllib.request.urlopen(REPO_URL, timeout=5) as response:
            if response.status != 200: return
            new_code = response.read().decode('utf-8')
            match = re.search(r'VERSION = "([\d\.]+)"', new_code)
            if match and match.group(1) > VERSION:
                print(f"New version found: {match.group(1)}")
                print("Please update via 'pip install --upgrade cfdiag' or your package manager.")
            else:
                print("You are already running the latest version.")
    except Exception as e:
        print(f"Update failed: {e}")

def generate_grafana() -> None:
    from .dashboard import GRAFANA_JSON
    print(GRAFANA_JSON)

def run_mtr(domain: str) -> None:
    print(f"Tracing route to {domain}...")
    hops = get_traceroute_hops(domain)
    if not hops:
        print("No hops found or traceroute failed.")
        return
        
    stats = {h: {"sent": 0, "lost": 0, "rtt": []} for h in hops}
    
    try:
        while True:
            # Clear screen
            os.system('cls' if os.name == 'nt' else 'clear')
            print(f"{Colors.BOLD}--- MTR Mode: {domain} (Ctrl+C to quit) ---")
            print(f"{'HOST':<30} | {'LOSS%':<6} | {'AVG':<6} | {'LAST':<6}")
            print("-" * 60)
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                futures = {executor.submit(ping_host, h): h for h in hops}
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

def run_diagnostics(domain: str, origin_ip: Optional[str]=None, expected_ns: Optional[str]=None, export_metrics: bool=False, speed_test: bool=False, dns_benchmark: bool=False, doh_check: bool=False, audit: bool=False) -> Dict[str, Any]:
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
    if doh_check: step_doh(domain)
    
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
    
    if speed_test: step_speed(domain)
    if dns_benchmark: step_dns_benchmark(domain)

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
    
    if audit:
        step_audit(domain, {"ssl_ok": ssl_ok, "http_status": http_res[1]})

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
    cur=\"${COMP_WORDS[COMP_CWORD]}\"
    prev=\"${COMP_WORDS[COMP_CWORD-1]}\"
    opts=\"--origin --expect --profile --file --verbose --no-color --diff --version --update --metrics --threads --ipv4 --ipv6 --proxy --json --completion --grafana --keylog --watch --notify --speed --benchmark-dns --doh --audit --lint-config --graph --mtr\"

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
        '--grafana[Generate Grafana Dashboard JSON]'
        '--keylog[SSL Keylog file]:filename:_files'
        '--watch[Run continuously every 5 seconds]'
        '--notify[Webhook URL for notifications]:url'
        '--speed[Run throughput/speed test]'
        '--benchmark-dns[Benchmark public resolvers against the domain]'
        '--doh[Check DNS-over-HTTPS resolution]'
        '--audit[Run security compliance audit]'
        '--lint-config[Lint web server config file]:filename:_files'
        '--graph[Generate Graphviz DOT output]'
        '--mtr[Run interactive MTR trace]'
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
    parser.add_argument("--grafana", action="store_true", help="Generate Grafana Dashboard JSON")
    parser.add_argument("--keylog", help="File to save SSL session keys (for Wireshark)")
    parser.add_argument("--header", action="append", help="Custom HTTP Header (e.g. 'X-Foo: Bar')")
    parser.add_argument("--timeout", type=int, default=10, help="Connection timeout in seconds")
    parser.add_argument("--markdown", action="store_true", help="Generate Markdown Report")
    parser.add_argument("--junit", action="store_true", help="Generate JUnit XML Report")
    parser.add_argument("--watch", action="store_true", help="Run continuously (every 5s)")
    parser.add_argument("--notify", help="Webhook URL for notification on completion")
    parser.add_argument("--speed", action="store_true", help="Run Throughput/Speed test")
    parser.add_argument("--benchmark-dns", action="store_true", help="Benchmark DNS Resolvers")
    parser.add_argument("--doh", action="store_true", help="Check DNS-over-HTTPS")
    parser.add_argument("--audit", action="store_true", help="Run Security Compliance Audit")
    parser.add_argument("--lint-config", help="Lint web server configuration file")
    parser.add_argument("--graph", action="store_true", help="Output Graphviz DOT topology")
    parser.add_argument("--mtr", action="store_true", help="Run interactive MTR")
    
    args = parser.parse_args()
    
    if args.update: self_update(); return
    if args.no_color: Colors.disable()
    if args.diff: compare_reports(args.diff[0], args.diff[1]); return
    if args.completion: generate_completion(args.completion); return
    if args.grafana: generate_grafana(); return
    if args.lint_config: step_lint_config(args.lint_config); return

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
        dns_header = "PROPAGATION" if args.expect else "DNS"
        print(f"{'.'.ljust(30)} | {dns_header:<12} | {'HTTP':<15} | {'TCP':<6} | {'DNSSEC':<10}")
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
        
        if args.notify:
            send_webhook(args.notify, f"Batch ({len(domains)} domains)", {"dns": "DONE", "http": "DONE"})

    else:
        # Handle Modes that don't run standard diag first
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
                    
                    result = run_diagnostics(domain.replace("http://", "").replace("https://", "").strip("/"), origin, expect, args.metrics, args.speed, args.benchmark_dns, args.doh, args.audit)
                    time.sleep(5)
            except KeyboardInterrupt:
                print("\nStopped.")
                sys.exit(0)
        else:
            result = run_diagnostics(domain.replace("http://", "").replace("https://", "").strip("/"), origin, expect, args.metrics, args.speed, args.benchmark_dns, args.doh, args.audit)
            
            if args.graph:
                step_graph(domain)

            if args.markdown:
                l.save_markdown(os.path.join("reports", domain, f"{datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.md"))
            if args.junit:
                l.save_junit(os.path.join("reports", domain, "junit.xml"))

            if args.json:
                print(json.dumps(result, indent=4))
            else:
                if not args.verbose: print(f"\n{Colors.OKBLUE}📄 Reports saved to reports/{domain}/ folder.{Colors.ENDC}")
            
            if args.notify:
                send_webhook(args.notify, domain, result)

if __name__ == "__main__":
    main()