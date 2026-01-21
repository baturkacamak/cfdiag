import re
import json
import os
import threading
import urllib.request
from typing import Dict, Any, Optional, List
from .utils import Colors, SEPARATOR, SUB_SEPARATOR, console_lock, thread_local

def get_logger() -> Optional['FileLogger']:
    return getattr(thread_local, 'logger', None)

def set_logger(log_obj: 'FileLogger') -> None:
    thread_local.logger = log_obj

class FileLogger:
    def __init__(self, verbose: bool = False, silent: bool = False):
        self.file_buffer: List[str] = []
        self.html_data: Dict[str, Any] = {
            "domain": "",
            "timestamp": "",
            "steps": [],
            "summary": []
        }
        self.ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|[0-?]*[@-~])')
        self.verbose = verbose 
        self.silent = silent   

    def log_console(self, msg: str = "", end: str = "\n", flush: bool = False, force: bool = False) -> None:
        if not self.silent and (self.verbose or force):
            with console_lock:
                print(msg, end=end, flush=flush)

    def log_file(self, msg: str, end: str = "\n", force: bool = False) -> None:
        if self.verbose or force:
            clean_msg = self.ansi_escape.sub('', msg)
            self.file_buffer.append(clean_msg + end)

    def log(self, msg: str = "", file_msg: Optional[str] = None, end: str = "\n", flush: bool = False, force: bool = False) -> None:
        self.log_console(msg, end, flush, force)
        content = file_msg if file_msg is not None else msg
        self.log_file(content, end, force)

    def add_html_step(self, title: str, status: str, details: str) -> None:
        if "steps" not in self.html_data:
             self.html_data["steps"] = []
        self.html_data["steps"].append({
            "title": title,
            "status": status,
            "details": details
        })

    def save_to_file(self, filename: str) -> bool:
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("".join(self.file_buffer))
            return True
        except Exception as e:
            if self.verbose: 
                with console_lock:
                    print(f"{Colors.FAIL}Error saving log: {e}{Colors.ENDC}")
            return False

    def save_html(self, filename: str) -> bool:
        domain = self.html_data.get('domain', '')
        ts = self.html_data.get('timestamp', '')
        html_parts = []
        html_parts.append("<!DOCTYPE html><html><head>")
        html_parts.append(f"<title>cfdiag Report - {domain}</title>")
        html_parts.append("<style>")
        html_parts.append("body { font-family: sans-serif; background: #f4f6f8; padding: 20px; }")
        html_parts.append(".container { max-width: 900px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }")
        html_parts.append("h1 { color: #2c3e50; border-bottom: 2px solid #ecf0f1; padding-bottom: 10px; }")
        html_parts.append(".meta { color: #7f8c8d; margin-bottom: 20px; }")
        html_parts.append(".step { border: 1px solid #e1e4e8; margin-bottom: 15px; border-radius: 4px; overflow: hidden; }")
        html_parts.append(".step-header { padding: 10px 15px; font-weight: bold; display: flex; justify-content: space-between; align-items: center; }")
        html_parts.append(".step-content { padding: 15px; background: #fafbfc; border-top: 1px solid #e1e4e8; font-family: monospace; white-space: pre-wrap; }")
        html_parts.append(".status-PASS { background: #d4edda; color: #155724; }")
        html_parts.append(".status-FAIL { background: #f8d7da; color: #721c24; }")
        html_parts.append(".status-WARN { background: #fff3cd; color: #856404; }")
        html_parts.append(".status-INFO { background: #d1ecf1; color: #0c5460; }")
        html_parts.append(".summary { background: #2c3e50; color: white; padding: 20px; border-radius: 4px; margin-top: 30px; }")
        html_parts.append(".summary h2 { border-bottom: 1px solid #465a69; color: white; }")
        html_parts.append("</style></head><body><div class='container'>")
        html_parts.append(f"<h1>cfdiag Report</h1><div class='meta'>Target: <strong>{domain}</strong> | Date: {ts}</div>")
        steps = self.html_data.get("steps", [])
        if isinstance(steps, list):
            for step in steps:
                if isinstance(step, dict):
                    status = step.get('status', 'INFO')
                    title = step.get('title', '')
                    details = step.get('details', '')
                    html_parts.append(f"<div class='step'><div class='step-header status-{status}'><span>{title}</span><span>[{status}]</span></div><div class='step-content'>{details}</div></div>")
        html_parts.append("<div class='summary'><h2>Summary</h2><ul>")
        summary = self.html_data.get("summary", [])
        if isinstance(summary, list):
            for line in summary:
                html_parts.append(f"<li>{line}</li>")
        html_parts.append("</ul></div></div></body></html>")
        try:
            with open(filename, 'w', encoding='utf-8') as f: f.write("\n".join(html_parts))
            return True
        except: return False

    def save_markdown(self, filename: str) -> bool:
        domain = self.html_data.get('domain', '')
        ts = self.html_data.get('timestamp', '')
        lines = []
        lines.append(f"# cfdiag Report: {domain}")
        lines.append(f"**Date:** {ts}")
        lines.append("")
        lines.append("## Diagnostic Summary")
        lines.append("| Check | Status |")
        lines.append("|---|---|")
        summary = self.html_data.get("summary", [])
        if isinstance(summary, list):
            for line in summary:
                if ":" in line:
                    k, v = line.split(":", 1)
                    icon = "[PASS]" if "PASS" in v or "OK" in v or "SUCCESS" in v else ("[FAIL]" if "FAIL" in v else "[WARN]")
                    lines.append(f"| {k.strip()} | {icon} {v.strip()} |")
        lines.append("")
        lines.append("## Detailed Steps")
        steps = self.html_data.get("steps", [])
        if isinstance(steps, list):
            for step in steps:
                if isinstance(step, dict):
                    status = step.get('status', 'INFO')
                    title = step.get('title', '')
                    details = step.get('details', '')
                    icon = "[PASS]" if status == "PASS" else ("[FAIL]" if status == "FAIL" else ("[WARN]" if status == "WARN" else "[INFO]"))
                    lines.append(f"### {icon} {title}")
                    lines.append(f"**Status:** {status}")
                    lines.append("```")
                    lines.append(details)
                    lines.append("```")
                    lines.append("")
        try:
            with open(filename, 'w', encoding='utf-8') as f: f.write("\n".join(lines))
            return True
        except: return False

    def save_junit(self, filename: str) -> bool:
        domain = self.html_data.get('domain', '')
        steps = self.html_data.get("steps", [])
        xml = []
        xml.append('<?xml version="1.0" encoding="UTF-8"?>')
        failures = 0
        tests = 0
        testcases = []
        if isinstance(steps, list):
            for step in steps:
                if isinstance(step, dict):
                    tests += 1
                    status = step.get('status', 'INFO')
                    title = step.get('title', '')
                    details = step.get('details', '').replace("<", "&lt;").replace(">", "&gt;")
                    case = f'<testcase name="{title}" classname="cfdiag.{domain}">'
                    if status == "FAIL":
                        failures += 1
                        case += f'<failure message="{status}">{details}</failure>'
                    case += '</testcase>'
                    testcases.append(case)
        xml.append(f'<testsuites><testsuite name="cfdiag" tests="{tests}" failures="{failures}">')
        xml.extend(testcases)
        xml.append('</testsuite></testsuites>')
        try:
            with open(filename, 'w', encoding='utf-8') as f: f.write("\n".join(xml))
            return True
        except: return False

def send_webhook(url: str, domain: str, result_dict: Dict[str, Any]) -> None:
    # Feature: Webhook Notification
    try:
        # Construct simple payload
        dns = result_dict.get('dns', 'Unknown')
        http = result_dict.get('http', 'Unknown')
        
        payload = {
            "text": f"cfdiag scan finished for *{domain}*.\nDNS: {dns}\nHTTP: {http}"
        }
        data = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=5) as resp:
            if resp.status == 200:
                print(f"{Colors.OKGREEN}Webhook sent successfully.{Colors.ENDC}")
            else:
                print(f"{Colors.FAIL}Webhook failed: {resp.status}{Colors.ENDC}")
    except Exception as e:
        print(f"{Colors.FAIL}Webhook error: {e}{Colors.ENDC}")

def print_header(title: str) -> None:
    l = get_logger()
    if l:
        l.log_console(f"\n{Colors.BOLD}{Colors.HEADER}{SEPARATOR}", force=True)
        l.log_console(f" {title}", force=True)
        l.log_console(f"{SEPARATOR}{Colors.ENDC}", force=True)
        l.log_file(f"\n{SEPARATOR}", force=True)
        l.log_file(f" {title}", force=True)
        l.log_file(f"{SEPARATOR}", force=True)

def print_subheader(title: str) -> None:
    l = get_logger()
    if l:
        l.log_console(f"\n{Colors.BOLD}{Colors.OKCYAN}>>> {title}{Colors.ENDC}")
        l.log_console(f"{Colors.GREY}{SUB_SEPARATOR}{Colors.ENDC}")
        l.log_file(f"\n>>> {title}")
        l.log_file(f"{SUB_SEPARATOR}")

def print_success(msg: str) -> None:
    l = get_logger()
    if l: l.log(f"{Colors.OKGREEN}{Colors.BOLD}+ [PASS]{Colors.ENDC} {msg}", file_msg=f"[PASS] {msg}")

def print_fail(msg: str) -> None:
    l = get_logger()
    if l: l.log(f"{Colors.FAIL}{Colors.BOLD}x [FAIL]{Colors.ENDC} {msg}", file_msg=f"[FAIL] {msg}")

def print_info(msg: str) -> None:
    l = get_logger()
    if l: l.log(f"{Colors.OKBLUE}* [INFO]{Colors.ENDC} {msg}", file_msg=f"[INFO] {msg}")

def print_warning(msg: str) -> None:
    l = get_logger()
    if l: l.log(f"{Colors.WARNING}{Colors.BOLD}! [WARN]{Colors.ENDC} {msg}", file_msg=f"[WARN] {msg}")

def print_skip(msg: str) -> None:
    l = get_logger()
    if l: l.log(f"{Colors.GREY}{Colors.BOLD}- [SKIP]{Colors.ENDC} {msg}", file_msg=f"[SKIP] {msg}")

def print_cmd(cmd: str) -> None:
    l = get_logger()
    if l:
        l.log_console(f"{Colors.GREY}$ {cmd}{Colors.ENDC}")
        l.log_file(f"Command: {cmd}")

def compare_reports(file1: str, file2: str) -> None:
    print(f"\n{Colors.BOLD}COMPARING REPORTS:{Colors.ENDC}")
    print(f"A: {file1}")
    print(f"B: {file2}\n")
    try:
        with open(file1, 'r', encoding='utf-8') as f1, open(file2, 'r', encoding='utf-8') as f2:
            lines1 = f1.readlines()
            lines2 = f2.readlines()
        def extract_summary(lines):
            summary = {}
            in_summary = False
            for line in lines:
                if "DIAGNOSTIC SUMMARY" in line:
                    in_summary = True
                    continue
                if in_summary and line.strip() and "[" in line:
                    parts = line.strip().split(']', 1)
                    if len(parts) == 2:
                        key = parts[1].strip()
                        status = parts[0].replace('[', '')
                        summary[key] = status
            return summary
        s1 = extract_summary(lines1)
        s2 = extract_summary(lines2)
        all_keys = set(s1.keys()) | set(s2.keys())
        changes = 0
        for k in all_keys:
            v1 = s1.get(k, "N/A")
            v2 = s2.get(k, "N/A")
            if v1 != v2:
                print(f"{Colors.BOLD}{k}{Colors.ENDC}")
                print(f"  Old: {Colors.FAIL if 'FAIL' in v1 else Colors.OKGREEN}{v1}{Colors.ENDC}")
                print(f"  New: {Colors.FAIL if 'FAIL' in v2 else Colors.OKGREEN}{v2}{Colors.ENDC}")
                changes += 1
        if changes == 0:
            print(f"{Colors.OKGREEN}No changes in summary status detected.{Colors.ENDC}")
    except Exception as e:
        print(f"Error comparing files: {e}")

def save_history(domain: str, metrics: Dict[str, Any]) -> Dict[str, Any]:
    history_file = os.path.join("reports", domain, ".history.json")
    prev_data = {}
    if os.path.exists(history_file):
        try:
            with open(history_file, 'r', encoding='utf-8') as f: prev_data = json.load(f)
        except: pass
    try:
        with open(history_file, 'w', encoding='utf-8') as f: json.dump(metrics, f)
    except: pass
    return prev_data

def save_metrics(domain: str, metrics: Dict[str, Any]):
    prom_file = os.path.join("reports", domain, "metrics.prom")
    lines = []
    ttfb = metrics.get('ttfb', 0)
    lines.append("# HELP cfdiag_http_ttfb_seconds HTTP Time To First Byte")
    lines.append("# TYPE cfdiag_http_ttfb_seconds gauge")
    lines.append(f'cfdiag_http_ttfb_seconds{{domain="{domain}"}} {ttfb}')
    up = 1 if metrics.get('http_status', 0) == 200 else 0
    lines.append("# HELP cfdiag_up Domain is reachable")
    lines.append("# TYPE cfdiag_up gauge")
    lines.append(f'cfdiag_up{{domain="{domain}"}} {up}')
    try:
        with open(prom_file, 'w', encoding='utf-8') as f: f.write("\n".join(lines))
    except: pass
