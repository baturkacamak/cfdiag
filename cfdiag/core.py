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
    step_dns, step_http,
    step_ssl, step_mtu, step_origin,
    run_mtr, step_asn
)
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

def run_diagnostics(domain: str, origin_ip: Optional[str]=None) -> Dict[str, Any]:
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

    # 1. Linear Diagnostic Flow
    step_dns(domain)
    step_http(domain)
    step_ssl(domain)
    step_mtu(domain)
    step_asn(domain)
    
    if origin_ip:
         step_origin(domain, origin_ip)

    if l:
        l.save_to_file(log_file)
        l.save_html(os.path.join(domain_dir, f"{timestamp}.html"))
    
    return {
        "domain": domain,
        "log": log_file
    }

def run_diagnostics_wrapper(domain: str, origin: Optional[str], context: Dict[str, Any]) -> Dict[str, Any]:
    l = FileLogger(verbose=True, silent=False)
    set_logger(l)
    set_context(context)
    return run_diagnostics(domain, origin)

def generate_completion(shell: str) -> None:
    if shell == "bash":
        print("""
_cfdiag()
{
    local cur prev opts
    COMPREPLY=()
    cur=\"${COMP_WORDS[COMP_CWORD]}\"
    prev=\"${COMP_WORDS[COMP_CWORD-1]}\" 
    opts=\"--origin --profile --file --verbose --no-color --version --update --ipv4 --ipv6 --proxy --json --completion --grafana --keylog --watch --lint-config --mtr --serve --analyze-logs\"

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
        '--profile[Load profile from config]:string'
        '--file[Batch mode file path]:filename:_files'
        '--verbose[Enable verbose output]'
        '--no-color[Disable color output]'
        '--version[Show version]'
        '--update[Self-update tool]'
        '--ipv4[Force IPv4]'
        '--ipv6[Force IPv6]'
        '--proxy[HTTP Proxy URL]:url'
        '--json[Output JSON to stdout]'
        '--completion[Generate shell completion]:(bash zsh)'
        '--grafana[Generate Grafana Dashboard JSON]'
        '--keylog[SSL Keylog file]:filename:_files'
        '--watch[Run continuously every 5 seconds]'
        '--lint-config[Lint web server config file]:filename:_files'
        '--mtr[Run interactive MTR trace]'
        '--serve[Start diagnostic HTTP server on port]:port'
        '--analyze-logs[Analyze web server access logs]:filename:_files'
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
    parser.add_argument("--profile")
    parser.add_argument("--file")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--version", action="version", version=f"cfdiag {VERSION}")
    parser.add_argument("--update", action="store_true")
    
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
    parser.add_argument("--lint-config", help="Lint web server configuration file")
    parser.add_argument("--mtr", action="store_true", help="Run interactive MTR")
    parser.add_argument("--serve", type=int, nargs='?', const=8080, help="Start diagnostic server (default port 8080)")
    parser.add_argument("--analyze-logs", help="Analyze access log file")
    
    args = parser.parse_args()
    
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
            futures = {executor.submit(run_diagnostics_wrapper, d, origin, ctx): d for d in domains}
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
                    
                    result = run_diagnostics(domain.replace("http://", "").replace("https://", "").strip("/"), origin)
                    time.sleep(5)
            except KeyboardInterrupt:
                print("\nStopped.")
                sys.exit(0)
        else:
            result = run_diagnostics(domain.replace("http://", "").replace("https://", "").strip("/"), origin)
            
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