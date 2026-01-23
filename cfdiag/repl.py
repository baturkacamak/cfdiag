"""
Interactive REPL mode for cfdiag with modern CLI interface, command autocomplete and banner.
"""
import os
import sys
import shlex
from typing import Dict, List, Optional, Tuple
from pathlib import Path

try:
    from prompt_toolkit import PromptSession
    from prompt_toolkit.completion import Completer, Completion
    from prompt_toolkit.history import FileHistory
    from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
    from prompt_toolkit.formatted_text import FormattedText
    from prompt_toolkit.styles import Style
    PROMPT_TOOLKIT_AVAILABLE = True
except ImportError:
    PROMPT_TOOLKIT_AVAILABLE = False

try:
    from rich.console import Console
    from rich.text import Text
    from rich.panel import Panel
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

from .utils import VERSION, Colors, get_context, set_context
from .core import (
    run_diagnostics, load_config, self_update, generate_grafana,
    step_lint_config, analyze_logs, run_diagnostic_server,
    check_internet_connection, check_dependencies
)
from .reporting import FileLogger, set_logger


# Command definitions with descriptions
COMMANDS = {
    "diagnose": {
        "description": "Run diagnostics on a domain",
        "usage": "diagnose <domain> [--origin <ip>] [--expect <ns>] [--verbose]",
        "aliases": ["diag", "d"],
        "category": "Core"
    },
    "help": {
        "description": "Show help for commands",
        "usage": "help [command]",
        "aliases": ["h", "?"],
        "category": "General"
    },
    "exit": {
        "description": "Exit the REPL",
        "usage": "exit",
        "aliases": ["quit", "q"],
        "category": "General"
    },
    "clear": {
        "description": "Clear the terminal",
        "usage": "clear",
        "aliases": ["cls"],
        "category": "General"
    },
    "version": {
        "description": "Show version information",
        "usage": "version",
        "aliases": ["v", "ver"],
        "category": "General"
    },
    "update": {
        "description": "Check for updates",
        "usage": "update",
        "aliases": [],
        "category": "General"
    },
    "config": {
        "description": "Show current configuration",
        "usage": "config",
        "aliases": ["cfg"],
        "category": "Configuration"
    },
    "set": {
        "description": "Set configuration option (e.g., set timeout 15)",
        "usage": "set <option> <value>",
        "aliases": [],
        "category": "Configuration"
    },
    "lint": {
        "description": "Lint web server config file",
        "usage": "lint <config_file>",
        "aliases": [],
        "category": "Utilities"
    },
    "analyze": {
        "description": "Analyze web server access logs",
        "usage": "analyze <log_file>",
        "aliases": [],
        "category": "Utilities"
    },
    "serve": {
        "description": "Start diagnostic HTTP server",
        "usage": "serve [port]",
        "aliases": [],
        "category": "Utilities"
    },
    "grafana": {
        "description": "Generate Grafana dashboard JSON",
        "usage": "grafana",
        "aliases": [],
        "category": "Utilities"
    },
}


def print_banner() -> None:
    """Print a beautiful application banner."""
    cwd = os.getcwd()
    home = str(Path.home())
    if cwd.startswith(home):
        display_cwd = "~" + cwd[len(home):]
    else:
        display_cwd = cwd
    
    if RICH_AVAILABLE:
        console = Console()
        
        # Create banner with rich
        banner_text = Text()
        banner_text.append("🔍 ", style="bold cyan")
        banner_text.append("cfdiag", style="bold white")
        banner_text.append(f" v{VERSION}", style="cyan")
        
        info_text = Text()
        info_text.append("Cloudflare Diagnostics", style="dim white")
        info_text.append(" · ", style="dim")
        info_text.append("Domain Connectivity Tool", style="dim white")
        
        path_text = Text()
        path_text.append(display_cwd, style="dim cyan")
        
        # Print banner
        console.print()
        console.print(banner_text, justify="left")
        console.print(info_text, justify="left")
        console.print(path_text, justify="left")
        console.print()
    else:
        # Fallback to basic banner
        icon = "🔍"
        print(f"\n{Colors.BOLD}{Colors.HEADER}{icon}  cfdiag v{VERSION}{Colors.ENDC}")
        print(f"{Colors.GREY}Cloudflare Diagnostics · Domain Connectivity Tool{Colors.ENDC}")
        print(f"{Colors.GREY}{display_cwd}{Colors.ENDC}\n")


class CommandCompleter(Completer):
    """Advanced completer with rich suggestions display."""
    
    def __init__(self):
        self.commands = {}
        # Build command map including aliases
        for cmd, info in COMMANDS.items():
            self.commands[cmd] = info
            for alias in info.get("aliases", []):
                self.commands[alias] = info
    
    def get_completions(self, document, complete_event):
        text = document.text_before_cursor
        words = text.split()
        
        if len(words) == 0:
            # Show all commands
            for cmd, info in sorted(self.commands.items()):
                if not cmd.startswith("_"):
                    # Create a nice display string with description
                    display = f"{cmd:<12} {info.get('description', '')}"
                    yield Completion(
                        cmd,
                        start_position=-len(text),
                        display=cmd,
                        display_meta=info.get("description", "")
                    )
        elif len(words) == 1:
            # Complete command name
            prefix = words[0].lower()
            matches = []
            for cmd, info in sorted(self.commands.items()):
                if cmd.startswith(prefix) and not cmd.startswith("_"):
                    matches.append((cmd, info))
                # Also check aliases
                for alias in info.get("aliases", []):
                    if alias.startswith(prefix) and cmd not in [m[0] for m in matches]:
                        matches.append((cmd, info))
                        break
            
            # Sort by relevance (exact matches first, then by length)
            matches.sort(key=lambda x: (not x[0].startswith(prefix), len(x[0])))
            
            for cmd, info in matches:
                # Show description in meta
                desc = info.get("description", "")
                yield Completion(
                    cmd,
                    start_position=-len(prefix),
                    display=cmd,
                    display_meta=desc
                )
        else:
            # Command-specific completions
            cmd = words[0].lower()
            if cmd in ["diagnose", "diag", "d"]:
                # Could add domain history here
                pass
            elif cmd in ["set"]:
                if len(words) == 2:
                    # Complete option names
                    options = ["timeout", "traceroute-limit", "ipv4", "ipv6", "proxy"]
                    prefix = words[1].lower()
                    for opt in options:
                        if opt.startswith(prefix):
                            yield Completion(
                                opt,
                                start_position=-len(prefix),
                                display=opt
                            )


def get_suggestions(text: str) -> List[Tuple[str, str]]:
    """Get command suggestions based on partial input."""
    if not text:
        return []
    
    text_lower = text.lower().strip()
    suggestions = []
    
    # Check for command matches
    for cmd, info in COMMANDS.items():
        if cmd.startswith(text_lower):
            suggestions.append((cmd, info.get("description", "")))
        # Check aliases
        for alias in info.get("aliases", []):
            if alias.startswith(text_lower):
                suggestions.append((cmd, info.get("description", "")))
                break
    
    # Sort by length (shorter = more likely exact match)
    suggestions.sort(key=lambda x: len(x[0]))
    return suggestions[:3]  # Return top 3 suggestions


def print_suggestions(suggestions: List[Tuple[str, str]], current_input: str) -> None:
    """Print command suggestions below the input line."""
    if not suggestions:
        return
    
    if RICH_AVAILABLE:
        console = Console()
        for cmd, desc in suggestions:
            # Highlight the matching part
            match_len = len(current_input.strip())
            suggestion_text = Text()
            suggestion_text.append("  ", style="dim")
            suggestion_text.append(cmd[:match_len], style="bold cyan")
            suggestion_text.append(cmd[match_len:], style="cyan")
            suggestion_text.append("  ", style="dim")
            suggestion_text.append(desc, style="dim white")
            console.print(suggestion_text)
    else:
        # Fallback
        for cmd, desc in suggestions:
            match_len = len(current_input.strip())
            highlighted = f"{Colors.BOLD}{Colors.OKCYAN}{cmd[:match_len]}{Colors.ENDC}{Colors.OKCYAN}{cmd[match_len:]}{Colors.ENDC}"
            print(f"  {highlighted}  {Colors.GREY}{desc}{Colors.ENDC}")


def parse_command(line: str) -> Tuple[str, List[str]]:
    """Parse command line into command and arguments."""
    try:
        parts = shlex.split(line)
        if not parts:
            return "", []
        return parts[0].lower(), parts[1:]
    except ValueError:
        # Handle unclosed quotes
        return line.split()[0].lower() if line.split() else "", []


def resolve_command(cmd: str) -> Optional[str]:
    """Resolve command alias to canonical command name."""
    cmd_lower = cmd.lower()
    if cmd_lower in COMMANDS:
        return cmd_lower
    
    # Check aliases
    for canonical, info in COMMANDS.items():
        if cmd_lower in info.get("aliases", []):
            return canonical
    
    return None


def show_help(cmd: Optional[str] = None) -> None:
    """Show help for commands with rich formatting."""
    if cmd:
        canonical = resolve_command(cmd)
        if canonical and canonical in COMMANDS:
            info = COMMANDS[canonical]
            if RICH_AVAILABLE:
                console = Console()
                console.print()
                console.print(f"[bold white]{canonical}[/bold white]")
                console.print(f"  [dim white]{info['description']}[/dim white]")
                console.print(f"  [cyan]Usage:[/cyan] {info['usage']}")
                if info.get('aliases'):
                    console.print(f"  [cyan]Aliases:[/cyan] {', '.join(info['aliases'])}")
                console.print()
            else:
                print(f"\n{Colors.BOLD}{canonical}{Colors.ENDC}")
                print(f"  {info['description']}")
                print(f"  Usage: {info['usage']}")
                if info.get('aliases'):
                    print(f"  Aliases: {', '.join(info['aliases'])}")
        else:
            print(f"{Colors.FAIL}Unknown command: {cmd}{Colors.ENDC}")
    else:
        if RICH_AVAILABLE:
            console = Console()
            console.print()
            console.print("[bold white]Available Commands:[/bold white]\n")
            
            # Group by category
            categories = {}
            for cmd, info in sorted(COMMANDS.items()):
                cat = info.get('category', 'General')
                if cat not in categories:
                    categories[cat] = []
                categories[cat].append((cmd, info))
            
            for cat in sorted(categories.keys()):
                console.print(f"[bold cyan]{cat}:[/bold cyan]")
                for cmd, info in categories[cat]:
                    aliases = ", ".join(info.get("aliases", []))
                    alias_str = f" [dim]({aliases})[/dim]" if aliases else ""
                    console.print(f"  [cyan]{cmd}[/cyan]{alias_str}")
                    console.print(f"    [dim white]{info['description']}[/dim white]")
                console.print()
            
            console.print("[dim]Type 'help <command>' for detailed usage.[/dim]")
        else:
            print(f"\n{Colors.BOLD}Available Commands:{Colors.ENDC}\n")
            for cmd, info in sorted(COMMANDS.items()):
                aliases = ", ".join(info.get("aliases", []))
                alias_str = f" ({aliases})" if aliases else ""
                print(f"  {Colors.OKBLUE}{cmd}{Colors.ENDC}{alias_str}")
                print(f"    {Colors.GREY}{info['description']}{Colors.ENDC}")
            print(f"\n{Colors.GREY}Type 'help <command>' for detailed usage.{Colors.ENDC}")


def show_config() -> None:
    """Show current configuration with rich formatting."""
    ctx = get_context()
    if RICH_AVAILABLE:
        console = Console()
        console.print()
        console.print("[bold white]Current Configuration:[/bold white]")
        console.print(f"  [cyan]Timeout:[/cyan] {ctx.get('timeout', 10)}s")
        console.print(f"  [cyan]Traceroute Limit:[/cyan] {ctx.get('traceroute_limit', 5)}")
        console.print(f"  [cyan]IPv4 Only:[/cyan] {ctx.get('ipv4', False)}")
        console.print(f"  [cyan]IPv6 Only:[/cyan] {ctx.get('ipv6', False)}")
        console.print(f"  [cyan]Proxy:[/cyan] {ctx.get('proxy', 'None')}")
        console.print(f"  [cyan]Headers:[/cyan] {ctx.get('headers', 'None')}")
        console.print()
    else:
        print(f"\n{Colors.BOLD}Current Configuration:{Colors.ENDC}")
        print(f"  Timeout: {ctx.get('timeout', 10)}s")
        print(f"  Traceroute Limit: {ctx.get('traceroute_limit', 5)}")
        print(f"  IPv4 Only: {ctx.get('ipv4', False)}")
        print(f"  IPv6 Only: {ctx.get('ipv6', False)}")
        print(f"  Proxy: {ctx.get('proxy', 'None')}")
        print(f"  Headers: {ctx.get('headers', 'None')}")


def set_config(option: str, value: str) -> None:
    """Set a configuration option."""
    ctx = get_context()
    option_lower = option.lower()
    
    if option_lower == "timeout":
        try:
            ctx['timeout'] = int(value)
            set_context(ctx)
            if RICH_AVAILABLE:
                console = Console()
                console.print(f"[green]✓[/green] Timeout set to {value}s")
            else:
                print(f"{Colors.OKGREEN}✓ Timeout set to {value}s{Colors.ENDC}")
        except ValueError:
            print(f"{Colors.FAIL}Invalid timeout value{Colors.ENDC}")
    elif option_lower == "traceroute-limit":
        try:
            ctx['traceroute_limit'] = int(value)
            set_context(ctx)
            if RICH_AVAILABLE:
                console = Console()
                console.print(f"[green]✓[/green] Traceroute limit set to {value}")
            else:
                print(f"{Colors.OKGREEN}✓ Traceroute limit set to {value}{Colors.ENDC}")
        except ValueError:
            print(f"{Colors.FAIL}Invalid traceroute limit value{Colors.ENDC}")
    elif option_lower == "ipv4":
        ctx['ipv4'] = value.lower() in ['true', '1', 'yes', 'on']
        ctx['ipv6'] = False  # Mutually exclusive
        set_context(ctx)
        if RICH_AVAILABLE:
            console = Console()
            console.print(f"[green]✓[/green] IPv4 only: {ctx['ipv4']}")
        else:
            print(f"{Colors.OKGREEN}✓ IPv4 only: {ctx['ipv4']}{Colors.ENDC}")
    elif option_lower == "ipv6":
        ctx['ipv6'] = value.lower() in ['true', '1', 'yes', 'on']
        ctx['ipv4'] = False  # Mutually exclusive
        set_context(ctx)
        if RICH_AVAILABLE:
            console = Console()
            console.print(f"[green]✓[/green] IPv6 only: {ctx['ipv6']}")
        else:
            print(f"{Colors.OKGREEN}✓ IPv6 only: {ctx['ipv6']}{Colors.ENDC}")
    elif option_lower == "proxy":
        ctx['proxy'] = value if value.lower() != 'none' else None
        set_context(ctx)
        if RICH_AVAILABLE:
            console = Console()
            console.print(f"[green]✓[/green] Proxy set to {ctx['proxy']}")
        else:
            print(f"{Colors.OKGREEN}✓ Proxy set to {ctx['proxy']}{Colors.ENDC}")
    else:
        print(f"{Colors.FAIL}Unknown configuration option: {option}{Colors.ENDC}")
        print(f"{Colors.GREY}Available options: timeout, traceroute-limit, ipv4, ipv6, proxy{Colors.ENDC}")


def handle_diagnose(args: List[str]) -> None:
    """Handle diagnose command."""
    if not args:
        if RICH_AVAILABLE:
            console = Console()
            console.print("[red]Error:[/red] Domain required")
            console.print("[dim]Usage: diagnose <domain> [--origin <ip>] [--expect <ns>] [--verbose][/dim]")
        else:
            print(f"{Colors.FAIL}Error: Domain required{Colors.ENDC}")
            print(f"{Colors.GREY}Usage: diagnose <domain> [--origin <ip>] [--expect <ns>] [--verbose]{Colors.ENDC}")
        return
    
    domain = args[0].replace("http://", "").replace("https://", "").strip("/")
    origin = None
    expected_ns = None
    verbose = False
    
    # Parse flags
    i = 1
    while i < len(args):
        if args[i] == "--origin" and i + 1 < len(args):
            origin = args[i + 1]
            i += 2
        elif args[i] == "--expect" and i + 1 < len(args):
            expected_ns = args[i + 1]
            i += 2
        elif args[i] == "--verbose" or args[i] == "-v":
            verbose = True
            i += 1
        else:
            i += 1
    
    # Setup logger
    l = FileLogger(verbose=verbose, silent=False)
    set_logger(l)
    
    # Run diagnostics
    try:
        result = run_diagnostics(domain, origin, expected_ns, export_metrics=False)
        if RICH_AVAILABLE:
            console = Console()
            console.print()
            console.print(f"[green]✓[/green] Diagnostic complete!")
            console.print(f"[dim]Reports saved to reports/{domain}/ folder.[/dim]")
        else:
            print(f"\n{Colors.OKGREEN}✓ Diagnostic complete!{Colors.ENDC}")
            print(f"{Colors.GREY}Reports saved to reports/{domain}/ folder.{Colors.ENDC}")
    except Exception as e:
        if RICH_AVAILABLE:
            console = Console()
            console.print(f"[red]Error:[/red] {e}")
        else:
            print(f"{Colors.FAIL}Error: {e}{Colors.ENDC}")


def run_repl() -> None:
    """Run the interactive REPL with modern CLI interface."""
    if not PROMPT_TOOLKIT_AVAILABLE:
        print(f"{Colors.FAIL}Error: prompt_toolkit is required for REPL mode.{Colors.ENDC}")
        print(f"{Colors.GREY}Install it with: pip install prompt-toolkit{Colors.ENDC}")
        sys.exit(1)
    
    # Check prerequisites with error handling
    try:
        if not check_internet_connection():
            print(f"{Colors.WARNING}Warning: No Internet connection detected.{Colors.ENDC}")
            print(f"{Colors.GREY}Some features may not work without internet.{Colors.ENDC}\n")
    except Exception as e:
        print(f"{Colors.WARNING}Warning: Could not check internet connection: {e}{Colors.ENDC}\n")
    
    try:
        check_dependencies()
    except Exception as e:
        print(f"{Colors.WARNING}Warning: Dependency check failed: {e}{Colors.ENDC}\n")
    
    # Initialize context
    try:
        ctx = {
            'ipv4': False,
            'ipv6': False,
            'proxy': None,
            'keylog_file': None,
            'headers': None,
            'timeout': 10,
            'traceroute_limit': 5
        }
        set_context(ctx)
    except Exception as e:
        print(f"{Colors.FAIL}Error initializing context: {e}{Colors.ENDC}")
        sys.exit(1)
    
    # Print banner
    try:
        print_banner()
    except Exception as e:
        print(f"{Colors.WARNING}Warning: Could not print banner: {e}{Colors.ENDC}\n")
    
    # Setup history with error handling
    history_file = os.path.join(Path.home(), ".cfdiag_history")
    try:
        history = FileHistory(history_file)
    except Exception as e:
        print(f"{Colors.WARNING}Warning: Could not load history: {e}{Colors.ENDC}")
        history = None
    
    # Create custom style with error handling
    try:
        style = Style.from_dict({
            'prompt': 'bold cyan',
            'completion-menu.completion': 'bg:#008888 #ffffff',
            'completion-menu.completion.current': 'bg:#00aaaa #000000',
            'scrollbar.background': 'bg:#88aaaa',
            'scrollbar.button': 'bg:#222222',
            'bottom-toolbar': 'bg:#1a1a1a #cccccc',
        })
    except Exception as e:
        # Fallback to default style if custom style fails
        print(f"{Colors.WARNING}Warning: Could not load custom style: {e}{Colors.ENDC}")
        style = None
    
    # Create prompt session with enhanced features
    # Use only arguments supported across prompt_toolkit versions
    try:
        session_kwargs = {
            'completer': CommandCompleter(),
            'auto_suggest': AutoSuggestFromHistory(),
            'complete_while_typing': True,
        }
        
        # Only add style if it was created successfully
        if style is not None:
            session_kwargs['style'] = style
        
        # Add history if available
        if history is not None:
            session_kwargs['history'] = history
        
        # Add optional features if supported by prompt_toolkit version
        try:
            import prompt_toolkit
            # Check if these features are available (newer versions)
            try:
                version = prompt_toolkit.__version__
                major, minor = map(int, version.split('.')[:2])
                if major >= 3:
                    session_kwargs['enable_open_in_editor'] = True
            except (ValueError, AttributeError):
                pass  # Skip if version detection fails
        except Exception:
            pass  # Continue without optional features
        
        session = PromptSession(**session_kwargs)
    except Exception as e:
        print(f"{Colors.FAIL}Error creating prompt session: {e}{Colors.ENDC}")
        print(f"{Colors.GREY}Try updating prompt-toolkit: pip install --upgrade prompt-toolkit{Colors.ENDC}")
        sys.exit(1)
    
    # Welcome message
    if RICH_AVAILABLE:
        console = Console()
        console.print("[dim]Type 'help' for available commands. Type 'exit' to quit.[/dim]\n")
    else:
        print(f"{Colors.GREY}Type 'help' for available commands. Type 'exit' to quit.{Colors.ENDC}\n")
    
    while True:
        try:
            # Get user input with custom prompt
            if RICH_AVAILABLE:
                # Use rich formatting for prompt
                prompt_text = FormattedText([("bold cyan", "> ")])
            else:
                prompt_text = f"{Colors.BOLD}{Colors.OKBLUE}>{Colors.ENDC} "
            
            text = session.prompt(prompt_text).strip()
            
            if not text:
                continue
            
            # Parse command
            cmd, args = parse_command(text)
            
            # Show suggestions if command is incomplete (before executing)
            if cmd and not resolve_command(cmd):
                suggestions = get_suggestions(cmd)
                if suggestions:
                    print()  # New line before suggestions
                    print_suggestions(suggestions, cmd)
                    print()  # New line after suggestions
                    continue  # Don't execute, let user try again
            
            if not cmd:
                continue
            
            # Resolve command
            canonical = resolve_command(cmd)
            
            if canonical == "exit" or canonical == "quit":
                if RICH_AVAILABLE:
                    console = Console()
                    console.print("[dim]Goodbye![/dim]")
                else:
                    print(f"{Colors.GREY}Goodbye!{Colors.ENDC}")
                break
            elif canonical == "help":
                show_help(args[0] if args else None)
            elif canonical == "clear" or canonical == "cls":
                os.system('cls' if os.name == 'nt' else 'clear')
                print_banner()
            elif canonical == "version":
                if RICH_AVAILABLE:
                    console = Console()
                    console.print()
                    console.print(f"[bold white]cfdiag v{VERSION}[/bold white]")
                    console.print()
                else:
                    print(f"\n{Colors.BOLD}cfdiag v{VERSION}{Colors.ENDC}")
            elif canonical == "update":
                try:
                    self_update()
                except Exception as e:
                    if RICH_AVAILABLE:
                        console = Console()
                        console.print(f"[red]Error checking for updates:[/red] {e}")
                    else:
                        print(f"{Colors.FAIL}Error checking for updates: {e}{Colors.ENDC}")
            elif canonical == "config":
                try:
                    show_config()
                except Exception as e:
                    if RICH_AVAILABLE:
                        console = Console()
                        console.print(f"[red]Error showing config:[/red] {e}")
                    else:
                        print(f"{Colors.FAIL}Error showing config: {e}{Colors.ENDC}")
            elif canonical == "set":
                if len(args) < 2:
                    if RICH_AVAILABLE:
                        console = Console()
                        console.print("[red]Usage:[/red] set <option> <value>")
                    else:
                        print(f"{Colors.FAIL}Usage: set <option> <value>{Colors.ENDC}")
                else:
                    try:
                        set_config(args[0], args[1])
                    except Exception as e:
                        if RICH_AVAILABLE:
                            console = Console()
                            console.print(f"[red]Error setting config:[/red] {e}")
                        else:
                            print(f"{Colors.FAIL}Error setting config: {e}{Colors.ENDC}")
            elif canonical == "diagnose":
                try:
                    handle_diagnose(args)
                except Exception as e:
                    if RICH_AVAILABLE:
                        console = Console()
                        console.print(f"[red]Error running diagnostics:[/red] {e}")
                    else:
                        print(f"{Colors.FAIL}Error running diagnostics: {e}{Colors.ENDC}")
            elif canonical == "lint":
                if not args:
                    if RICH_AVAILABLE:
                        console = Console()
                        console.print("[red]Error:[/red] Config file required")
                    else:
                        print(f"{Colors.FAIL}Error: Config file required{Colors.ENDC}")
                else:
                    try:
                        step_lint_config(args[0])
                    except Exception as e:
                        if RICH_AVAILABLE:
                            console = Console()
                            console.print(f"[red]Error linting config:[/red] {e}")
                        else:
                            print(f"{Colors.FAIL}Error linting config: {e}{Colors.ENDC}")
            elif canonical == "analyze":
                if not args:
                    if RICH_AVAILABLE:
                        console = Console()
                        console.print("[red]Error:[/red] Log file required")
                    else:
                        print(f"{Colors.FAIL}Error: Log file required{Colors.ENDC}")
                else:
                    try:
                        analyze_logs(args[0])
                    except Exception as e:
                        if RICH_AVAILABLE:
                            console = Console()
                            console.print(f"[red]Error analyzing logs:[/red] {e}")
                        else:
                            print(f"{Colors.FAIL}Error analyzing logs: {e}{Colors.ENDC}")
            elif canonical == "serve":
                try:
                    port = int(args[0]) if args and args[0].isdigit() else 8080
                    if RICH_AVAILABLE:
                        console = Console()
                        console.print(f"[cyan]Starting server on port {port}...[/cyan]")
                        console.print("[dim]Press Ctrl+C to stop[/dim]")
                    else:
                        print(f"{Colors.OKBLUE}Starting server on port {port}...{Colors.ENDC}")
                        print(f"{Colors.GREY}Press Ctrl+C to stop{Colors.ENDC}")
                    try:
                        run_diagnostic_server(port)
                    except KeyboardInterrupt:
                        if RICH_AVAILABLE:
                            console = Console()
                            console.print()
                            console.print("[dim]Server stopped.[/dim]")
                        else:
                            print(f"\n{Colors.GREY}Server stopped.{Colors.ENDC}")
                    except Exception as e:
                        if RICH_AVAILABLE:
                            console = Console()
                            console.print(f"[red]Server error:[/red] {e}")
                        else:
                            print(f"{Colors.FAIL}Server error: {e}{Colors.ENDC}")
                except ValueError:
                    if RICH_AVAILABLE:
                        console = Console()
                        console.print("[red]Error:[/red] Invalid port number")
                    else:
                        print(f"{Colors.FAIL}Error: Invalid port number{Colors.ENDC}")
            elif canonical == "grafana":
                try:
                    generate_grafana()
                except Exception as e:
                    if RICH_AVAILABLE:
                        console = Console()
                        console.print(f"[red]Error generating Grafana config:[/red] {e}")
                    else:
                        print(f"{Colors.FAIL}Error generating Grafana config: {e}{Colors.ENDC}")
            else:
                if RICH_AVAILABLE:
                    console = Console()
                    console.print(f"[red]Unknown command:[/red] {cmd}")
                    console.print("[dim]Type 'help' for available commands.[/dim]")
                else:
                    print(f"{Colors.FAIL}Unknown command: {cmd}{Colors.ENDC}")
                    print(f"{Colors.GREY}Type 'help' for available commands.{Colors.ENDC}")
        
        except KeyboardInterrupt:
            if RICH_AVAILABLE:
                console = Console()
                console.print()
                console.print("[dim]Use 'exit' to quit.[/dim]")
            else:
                print(f"\n{Colors.GREY}Use 'exit' to quit.{Colors.ENDC}")
        except EOFError:
            if RICH_AVAILABLE:
                console = Console()
                console.print()
                console.print("[dim]Goodbye![/dim]")
            else:
                print(f"\n{Colors.GREY}Goodbye!{Colors.ENDC}")
            break
        except Exception as e:
            if RICH_AVAILABLE:
                console = Console()
                console.print(f"[red]Error:[/red] {e}")
            else:
                print(f"{Colors.FAIL}Error: {e}{Colors.ENDC}")
