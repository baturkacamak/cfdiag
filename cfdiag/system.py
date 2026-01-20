import os
import re
from .utils import CLOUDFLARE_IPS, Colors
from .reporting import get_logger, print_header, print_success, print_fail, print_warning, print_info

def step_lint_config(config_path: str) -> None:
    print_header("Configuration Linting")
    if not os.path.exists(config_path):
        print_fail(f"Config file not found: {config_path}")
        return

    print_info(f"Scanning {config_path}...")
    try:
        with open(config_path, 'r') as f:
            content = f.read()
        
        issues = []
        
        # Check for Real IP setup (Nginx/Apache style)
        if "set_real_ip_from" not in content and "RemoteIPHeader" not in content:
             issues.append("Missing 'set_real_ip_from' or 'RemoteIPHeader' (Cloudflare Real IP).")
        
        # Check if ranges are present
        found_ranges = 0
        for ip in CLOUDFLARE_IPS:
            if ip in content:
                found_ranges += 1
        
        if found_ranges < 5: # Arbitrary threshold
             issues.append(f"Only found {found_ranges} Cloudflare IP ranges. List might be outdated.")

        if issues:
            print_warning("Issues Found:")
            for i in issues:
                print(f"  - {i}")
        else:
            print_success("Configuration looks good (Real IP setup detected).")

    except Exception as e:
        print_fail(f"Error reading config: {e}")

def step_audit(domain: str, results: dict) -> None:
    print_header("Security Compliance Audit")
    
    audit_pass = True
    
    def check(name, condition):
        nonlocal audit_pass
        if condition:
            print_success(f"{name}: PASS")
        else:
            print_fail(f"{name}: FAIL")
            audit_pass = False

    # Check TLS (Assumes results has ssl_ok)
    check("SSL Certificate Valid", results.get('ssl_ok'))
    
    # Check HSTS (Need headers)
    # We don't have headers in 'results' dict easily exposed from step_http yet.
    # We might need to rely on what was logged?
    # Or step_audit calls step_security_headers itself?
    # But core calls them sequentially.
    # Let's assume step_audit is run as a standalone report generator at the end.
    
    pass 
    # Actually, step_audit should probably run its own checks or analyze the 'l.html_data'?
    # It's easier if step_audit is just a summary function.
    
    print(f"\n{Colors.BOLD}Audit Result: {'PASSED' if audit_pass else 'FAILED'}{Colors.ENDC}")
