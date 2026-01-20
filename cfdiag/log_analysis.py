import re
import os
from collections import Counter
from .reporting import print_header, print_success, print_fail, print_warning, print_info, Colors

def analyze_logs(log_path: str) -> None:
    print_header("Log Analyzer")
    if not os.path.exists(log_path):
        print_fail(f"Log file not found: {log_path}")
        return

    print_info(f"Analyzing {log_path}...")
    
    # Regex for Common Log Format / Combined
    # 127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326
    log_pattern = re.compile(r'(?P<ip>\S+) - - \[(?P<time>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) [^\\"]+" (?P<status>\d+) (?P<size>\d+)')
    
    stats = Counter()
    errors = Counter()
    cf_errors = Counter()
    
    total_lines = 0
    parsed_lines = 0
    
    try:
        with open(log_path, 'r') as f:
            for line in f:
                total_lines += 1
                match = log_pattern.search(line)
                if match:
                    parsed_lines += 1
                    data = match.groupdict()
                    status = int(data['status'])
                    
                    if status >= 500:
                        errors[data['time'].split(':')[0]] += 1 # Group by date/hour
                        if 520 <= status <= 530:
                            cf_errors[status] += 1
                    
                    if status >= 400:
                        pass # Track client errors?
                        
    except Exception as e:
        print_fail(f"Error parsing log: {e}")
        return

    print_success(f"Parsed {parsed_lines}/{total_lines} lines.")
    
    if cf_errors:
        print(f"\n{Colors.FAIL}Cloudflare Specific Errors:{Colors.ENDC}")
        for code, count in cf_errors.most_common():
            print(f"  HTTP {code}: {count} occurrences")
            if code == 522: print(f"    -> Connection Timed Out (Origin Firewall/Down)")
            if code == 525: print(f"    -> SSL Handshake Failed (Origin Cert Invalid)")
            if code == 524: print(f"    -> Connection Timeout (Origin too slow)")
            if code == 520: print(f"    -> Unknown Error (Catch-all)")
            if code == 521: print(f"    -> Web Server Is Down")
            if code == 523: print(f"    -> Origin Is Unreachable")
    else:
        print_success("No Cloudflare-specific errors (520-530) found.")

    if errors:
        print(f"\n{Colors.WARNING}General Server Errors (5xx): {sum(errors.values())} total{Colors.ENDC}")
