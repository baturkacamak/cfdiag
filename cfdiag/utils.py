import os
import threading
from typing import Dict, Any

VERSION = "3.10.3"
SEPARATOR = "=" * 60
SUB_SEPARATOR = "-" * 60
REPO_URL = "https://raw.githubusercontent.com/baturkacamak/cfdiag/main/cfdiag.py"
CONFIG_FILE_NAME = ".cfdiag.json"

CF_PORTS = [8443, 2053, 2083, 2087, 2096]

# Cloudflare IP Ranges (v4/v6)
CLOUDFLARE_IPS = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
    "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32"
]

PUBLIC_RESOLVERS = [
    ("Google", "8.8.8.8"),
    ("Cloudflare", "1.1.1.1"),
    ("Quad9", "9.9.9.9"),
    ("OpenDNS", "208.67.222.222"),
    ("Level3", "4.2.2.1")
]

DNSBL_LIST = [
    ("Spamhaus ZEN", "zen.spamhaus.org"),
    ("Barracuda", "b.barracudacentral.org")
]

USER_AGENTS = {
    "Browser (Chrome)": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Bot (Googlebot)": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Empty UA": ""
}

console_lock = threading.Lock()
thread_local = threading.local()

def get_context() -> Dict[str, Any]:
    return getattr(thread_local, 'context', {})

def set_context(ctx: Dict[str, Any]) -> None:
    thread_local.context = ctx

def get_curl_flags() -> str:
    ctx = get_context()
    flags = []
    if ctx.get('ipv4'): flags.append("-4")
    if ctx.get('ipv6'): flags.append("-6")
    if ctx.get('proxy'): flags.append(f"--proxy {ctx.get('proxy')}")
    if ctx.get('headers'):
        for h in ctx.get('headers'):
            flags.append(f'-H "{h}"')
    if ctx.get('timeout'):
        # Curl connection timeout
        flags.append(f"--connect-timeout {ctx.get('timeout')}")
        flags.append(f"--max-time {int(ctx.get('timeout')) * 2}") # Total time slightly longer
    return " " + " ".join(flags) if flags else ""

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
    
    @staticmethod
    def disable() -> None:
        for attr in dir(Colors):
            if not attr.startswith("__") and not callable(getattr(Colors, attr)):
                setattr(Colors, attr, "")

if os.name == 'nt':
    try:
        from ctypes import windll # type: ignore
        k = windll.kernel32
        k.SetConsoleMode(k.GetStdHandle(-11), 7)
    except:
        pass 
