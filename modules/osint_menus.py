"""
osint_menus.py — Interactive menus and result rendering for the OSINT Recon module.

All display uses the shared console from modules/utils.py.
All menus loop until the user selects Back (0).
"""

from __future__ import annotations

import json
import os
import sys
import webbrowser
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from rich import box
from rich.columns import Columns
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from modules.utils import console  # noqa: E402
from modules.osint_recon import (  # noqa: E402
    THEHARVESTER_AVAILABLE,
    EXIFTOOL_AVAILABLE,
    WAPPALYZER_AVAILABLE,
    PYMUPDF_AVAILABLE,
    clean_domain,
    harvest_emails_and_subdomains,
    wayback_lookup,
    builtwith_lookup,
    wappalyzer_lookup,
    fingerprint_tech_stack,
    check_exposed_files,
    extract_metadata_from_url,
    extract_metadata_from_file,
    full_domain_recon,
    _SEVERITY_ORDER,
)

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ---------------------------------------------------------------------------
# Top-level menu
# ---------------------------------------------------------------------------

def show_osint_menu() -> None:
    """Called from main.py when user selects [O]. Loops until Back."""
    while True:
        console.clear()

        console.print(
            Panel(
                Text(
                    "OSINT Reconnaissance\n"
                    "[dim]Passive intelligence gathering on domains and files[/dim]",
                    justify="center",
                    style="bold white",
                ),
                border_style="cyan",
                box=box.DOUBLE_EDGE,
                padding=(0, 4),
            )
        )
        console.print()

        table = Table(
            box=box.SIMPLE_HEAD,
            show_header=True,
            header_style="bold bright_white on grey23",
            border_style="cyan",
            expand=False,
            padding=(0, 2),
        )
        table.add_column("KEY",    style="bold", min_width=5,  justify="center")
        table.add_column("OPTION",               min_width=32)
        table.add_column("METHOD",               min_width=22, style="dim")
        table.add_column("API / TOOL",           min_width=26, style="dim")

        rows = [
            ("[bold bright_cyan]1[/bold bright_cyan]",
             "[bold white]Email & Subdomain Harvesting[/bold white]",
             "Passive enumeration", "theHarvester"),
            ("[bold bright_green]2[/bold bright_green]",
             "[bold white]Tech Stack Fingerprinting[/bold white]",
             "Live + API analysis", "BuiltWith + Wappalyzer"),
            ("[bold bright_yellow]3[/bold bright_yellow]",
             "[bold white]Historical Domain Lookup[/bold white]",
             "Archive search", "Wayback Machine"),
            ("[bold bright_red]4[/bold bright_red]",
             "[bold white]Exposed Files & Paths[/bold white]",
             "Active HTTP checks", "Direct HTTP requests"),
            ("[bold bright_magenta]5[/bold bright_magenta]",
             "[bold white]Metadata Extraction[/bold white]",
             "File analysis", "exiftool / PyMuPDF"),
            ("[bold orange1]6[/bold orange1]",
             "[bold white]Full Domain Recon[/bold white]",
             "All passive modules", "All sources"),
            ("[dim]0[/dim]", "[dim]Back to Main Menu[/dim]", "", ""),
        ]
        for row in rows:
            table.add_row(*row)

        console.print(table)
        console.print()

        # Tool availability strip
        def _status(available: bool) -> str:
            return "[bold green]✓[/bold green]" if available else "[bold red]✗[/bold red]"

        bw_key = bool(__import__("sys").modules.get("modules.osint_recon") and
                      __import__("modules.osint_recon", fromlist=["BUILTWITH_API_KEY"]).BUILTWITH_API_KEY)
        console.print(
            f"  [dim]Tools:[/dim]  "
            f"theHarvester {_status(THEHARVESTER_AVAILABLE)}  "
            f"exiftool {_status(EXIFTOOL_AVAILABLE)}  "
            f"Wappalyzer {_status(WAPPALYZER_AVAILABLE)}  "
            f"PyMuPDF {_status(PYMUPDF_AVAILABLE)}  "
            f"BuiltWith key {_status(bw_key)}"
        )
        console.print()

        choice = Prompt.ask(
            "[bold yellow]Select option[/bold yellow]",
            choices=["0", "1", "2", "3", "4", "5", "6"],
            show_choices=False,
        )

        if choice == "0":
            break
        elif choice == "1":
            handle_email_harvesting()
        elif choice == "2":
            handle_tech_stack()
        elif choice == "3":
            handle_wayback_lookup()
        elif choice == "4":
            handle_exposed_files()
        elif choice == "5":
            handle_metadata_extraction()
        elif choice == "6":
            handle_full_recon()

        Prompt.ask(
            "\n[dim]Press Enter to return to OSINT menu[/dim]",
            default="",
            show_default=False,
        )


# ---------------------------------------------------------------------------
# Shared input helper
# ---------------------------------------------------------------------------

def prompt_domain_input(prompt_text: str = "Enter domain") -> str:
    """Prompt for a domain, validate, and return the cleaned domain."""
    console.print("  [dim]Accepts: example.com · sub.example.com · https://example.com[/dim]")
    while True:
        raw = Prompt.ask(f"[bold]{prompt_text}[/bold]").strip()
        if not raw:
            console.print("[bold red]  Domain cannot be empty.[/bold red]")
            continue
        cleaned = clean_domain(raw)
        if "." not in cleaned or len(cleaned) < 4:
            console.print(f"[bold red]  Invalid domain: '{cleaned}'. Try: example.com[/bold red]")
            continue
        return cleaned


def _offer_json_export(data: object, filename_prefix: str) -> None:
    """Offer to export data to a JSON file in the reports/ directory."""
    choice = Prompt.ask(
        "[yellow]Export results to JSON?[/yellow]",
        choices=["y", "n"],
        default="n",
    )
    if choice != "y":
        return

    reports_dir = os.path.join(_ROOT, "reports")
    os.makedirs(reports_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename  = os.path.join(reports_dir, f"{filename_prefix}_{timestamp}.json")

    def _sanitise(obj):  # type: ignore
        if isinstance(obj, dict):
            return {k: _sanitise(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [_sanitise(i) for i in obj]
        try:
            json.dumps(obj)
            return obj
        except (TypeError, ValueError):
            return str(obj)

    with open(filename, "w", encoding="utf-8") as fh:
        json.dump(_sanitise(data), fh, indent=2, ensure_ascii=False)
    console.print(f"\n[bold green]Report exported → {filename}[/bold green]")


# ---------------------------------------------------------------------------
# Option 1 — Email & Subdomain Harvesting
# ---------------------------------------------------------------------------

def handle_email_harvesting() -> None:
    """Run theHarvester against a domain with configurable source selection."""
    if not THEHARVESTER_AVAILABLE:
        console.print(
            Panel(
                "[bold white]theHarvester Not Found[/bold white]\n\n"
                "theHarvester is required for email and subdomain harvesting.\n\n"
                "  [cyan]sudo apt install theharvester[/cyan]          (Kali/Debian)\n"
                "  [cyan]pip install theHarvester[/cyan]               (pip)\n"
                "  [dim]https://github.com/laramies/theHarvester[/dim]",
                border_style="red",
                padding=(1, 2),
            )
        )
        return

    domain = prompt_domain_input("Enter target domain for email harvesting")

    # Source selection
    console.print()
    src_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    src_table.add_column(style="bold cyan", min_width=4)
    src_table.add_column(min_width=30)
    src_table.add_column(style="dim", min_width=20)
    src_table.add_row("1", "Quick  (Google + Bing + DuckDuckGo)",    "fastest, ~30s")
    src_table.add_row("2", "Standard  (+ crt.sh + OTX + Baidu)",     "recommended default")
    src_table.add_row("3", "Deep  (+ Shodan + LinkedIn + Twitter)",   "needs extra API keys")
    src_table.add_row("4", "Custom — enter source list manually",      "")
    console.print(Panel(src_table, title="[bold]Select Source Depth[/bold]", border_style="cyan"))

    src_choice = Prompt.ask("Source depth", choices=["1", "2", "3", "4"], default="2")

    source_sets = {
        "1": "google,bing,duckduckgo",
        "2": "google,bing,duckduckgo,crtsh,otx,baidu",
        "3": "google,bing,duckduckgo,crtsh,otx,shodan,linkedin,twitter",
    }
    if src_choice == "4":
        sources = Prompt.ask("[bold]Enter comma-separated sources[/bold]").strip()
        if not sources:
            sources = source_sets["2"]
    else:
        sources = source_sets[src_choice]

    limit_str = Prompt.ask(
        "[bold]Max results per source[/bold] [dim](50–500)[/dim]",
        default="200",
    )
    try:
        limit = max(50, min(500, int(limit_str)))
    except ValueError:
        limit = 200

    console.print()
    console.print(Panel(
        "[yellow]ℹ  OPSEC: theHarvester queries public search engines.\n"
        "Some sources may log your queries. Use a VPN if operational\n"
        "security is a concern.[/yellow]",
        border_style="yellow",
    ))
    console.print()

    result: dict = {}
    with Progress(SpinnerColumn(), TextColumn("[bold cyan]{task.description}"),
                  console=console, transient=True) as progress:
        progress.add_task(f"Harvesting {domain} from {sources}…", total=None)
        console.print(
            f"[yellow]⏳ This may take 30–120 seconds depending on sources selected…[/yellow]"
        )
        result = harvest_emails_and_subdomains(domain, sources, limit)

    print_osint_result(result)

    # Sub-actions
    details    = result.get("details", {})
    email_list = details.get("Email List", [])
    sub_list   = details.get("Subdomain List", [])

    if email_list or sub_list:
        console.print()
        action_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        action_table.add_column(style="bold cyan", min_width=4)
        action_table.add_column()
        action_table.add_row("1", "Export email list to TXT")
        action_table.add_row("2", "Export subdomain list to TXT")
        action_table.add_row("3", "Run DNS lookup on top 5 discovered subdomains")
        action_table.add_row("0", "[dim]Skip[/dim]")
        console.print(Panel(action_table, title="[bold]Sub-Actions[/bold]", border_style="dim"))

        sub_choice = Prompt.ask("Action", choices=["0", "1", "2", "3"], default="0")

        reports_dir = os.path.join(_ROOT, "reports")
        os.makedirs(reports_dir, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")

        if sub_choice == "1" and email_list:
            path = os.path.join(reports_dir, f"emails_{domain}_{ts}.txt")
            with open(path, "w") as fh:
                fh.write("\n".join(email_list))
            console.print(f"[bold green]Email list → {path}[/bold green]")

        elif sub_choice == "2" and sub_list:
            path = os.path.join(reports_dir, f"subdomains_{domain}_{ts}.txt")
            with open(path, "w") as fh:
                fh.write("\n".join(sub_list))
            console.print(f"[bold green]Subdomain list → {path}[/bold green]")

        elif sub_choice == "3" and sub_list:
            try:
                from modules import dns_tools  # type: ignore
                top5 = sub_list[:5]
                console.print(f"\n[bold cyan]DNS lookup on {len(top5)} subdomains…[/bold cyan]")
                for sd in top5:
                    dns_r = dns_tools.dns_lookup(sd)
                    _print_compact_result(dns_r)
            except Exception as exc:
                console.print(f"[red]DNS lookup failed: {exc}[/red]")

    _offer_json_export(result, f"harvest_{domain}")


# ---------------------------------------------------------------------------
# Option 2 — Tech Stack Fingerprinting
# ---------------------------------------------------------------------------

def handle_tech_stack() -> None:
    """Run technology fingerprinting using BuiltWith API + Wappalyzer locally."""
    domain = prompt_domain_input("Enter domain for tech stack analysis")

    console.print()
    src_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    src_table.add_column(style="bold cyan", min_width=4)
    src_table.add_column()
    src_table.add_row("1", "BuiltWith API only  [dim](requires free API key)[/dim]")
    src_table.add_row("2", "Wappalyzer only  [dim](local, live HTTPS fetch — no key needed)[/dim]")
    src_table.add_row("3", "[bold]Both — merged report[/bold]  [dim](recommended)[/dim]")
    console.print(Panel(src_table, title="[bold]Select Analysis Source[/bold]", border_style="cyan"))
    console.print("  [dim]BuiltWith free tier: 1 request per domain per day.[/dim]")
    console.print("  [dim]Wappalyzer makes a live HTTPS request to the target domain.[/dim]")
    console.print()

    src = Prompt.ask("Source", choices=["1", "2", "3"], default="3")

    result: dict = {}
    with Progress(SpinnerColumn(), TextColumn("[bold cyan]{task.description}"),
                  console=console, transient=True) as progress:
        progress.add_task(f"Fingerprinting tech stack for {domain}…", total=None)
        if src == "1":
            result = builtwith_lookup(domain)
        elif src == "2":
            result = wappalyzer_lookup(domain)
        else:
            result = fingerprint_tech_stack(domain)

    print_osint_result(result)

    # Security header summary
    details = result.get("details", {})
    missing = details.get("Security Headers Missing", [])
    present = details.get("Security Headers Present", [])
    if missing or present:
        console.print()
        risk = details.get("Missing Header Risk", "Unknown")
        console.print(Panel(
            f"[bold white]Security Header Audit[/bold white]\n\n"
            f"  Present : [green]{', '.join(present) if present else 'None'}[/green]\n"
            f"  Missing : [red]{', '.join(missing) if missing else 'None'}[/red]\n\n"
            f"  Risk Level: [yellow]{risk}[/yellow]\n\n"
            "[dim]Missing headers may indicate security misconfiguration.[/dim]",
            border_style="yellow" if missing else "green",
            padding=(1, 2),
        ))

    _offer_json_export(result, f"techstack_{domain}")


# ---------------------------------------------------------------------------
# Option 3 — Historical Domain Lookup
# ---------------------------------------------------------------------------

def handle_wayback_lookup() -> None:
    """Look up a domain's history on the Wayback Machine."""
    domain = prompt_domain_input("Enter domain for history lookup")

    limit_str = Prompt.ask(
        "[bold]Recent snapshots to retrieve[/bold] [dim](1–50)[/dim]",
        default="10",
    )
    try:
        limit = max(1, min(50, int(limit_str)))
    except ValueError:
        limit = 10

    result: dict = {}
    with Progress(SpinnerColumn(), TextColumn("[bold cyan]{task.description}"),
                  console=console, transient=True) as progress:
        progress.add_task(f"Searching Internet Archive for {domain}…", total=None)
        console.print("[yellow]⏳ Wayback API may be slow — please wait…[/yellow]")
        result = wayback_lookup(domain, limit)

    _print_wayback_result(result)

    # Offer browser open
    details    = result.get("details", {})
    latest_url = details.get("Latest Snapshot URL", "")
    if latest_url and latest_url != "N/A":
        console.print()
        open_choice = Prompt.ask(
            "[bold]Open latest snapshot in browser?[/bold]",
            choices=["y", "n"],
            default="n",
        )
        if open_choice == "y":
            webbrowser.open(latest_url)

    _offer_json_export(result, f"wayback_{domain}")


# ---------------------------------------------------------------------------
# Option 4 — Exposed Files & Paths Check
# ---------------------------------------------------------------------------

_ACTIVE_WARNING = (
    "[bold red]⚠  ACTIVE SCAN WARNING[/bold red]\n\n"
    "This module makes [bold]DIRECT HTTP requests[/bold] to the target server.\n"
    "It is NOT fully passive — the target may log your IP.\n\n"
    "[bold white]Only use against:[/bold white]\n"
    "  • Domains you own\n"
    "  • Domains you have explicit written authorisation to test\n"
    "  • Bug bounty targets within defined scope\n\n"
    "[yellow]Using this against unauthorised targets may violate law.[/yellow]\n\n"
    "Type [bold]YES[/bold] to confirm you have authorisation, or press Enter to cancel."
)


def handle_exposed_files() -> None:
    """Check for exposed files and sensitive paths. Requires authorisation confirmation."""
    console.print(Panel(_ACTIVE_WARNING, border_style="red", box=box.HEAVY, padding=(1, 2)))
    console.print()

    confirm = Prompt.ask("[bold red]Confirm authorisation[/bold red]", default="").strip()
    if confirm.upper() != "YES":
        console.print("[dim]Scan cancelled.[/dim]")
        return

    domain = prompt_domain_input("Enter target domain for exposed files check")

    console.print()
    scope_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    scope_table.add_column(style="bold cyan", min_width=4)
    scope_table.add_column()
    scope_table.add_column(style="dim")
    scope_table.add_row("1", "Quick scan",    "CRITICAL + HIGH only, ~15 paths")
    scope_table.add_row("2", "Standard scan", "All severity levels, ~70 paths  ← default")
    scope_table.add_row("3", "Full scan",     "All paths including INFO, ~85 paths")
    console.print(Panel(scope_table, title="[bold]Scan Scope[/bold]", border_style="cyan"))

    scope_choice = Prompt.ask("Scope", choices=["1", "2", "3"], default="2")

    severity_filter = None
    if scope_choice == "1":
        severity_filter = ["CRITICAL", "HIGH"]
    elif scope_choice == "3":
        severity_filter = None  # All paths
    else:
        severity_filter = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

    result: dict = {}
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]Checking paths against {task.description}…"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task(domain, total=None)
        result = check_exposed_files(domain, severity_filter)

    print_exposed_files_result(result)

    # Robots.txt interactive
    details   = result.get("details", {})
    disallowed = details.get("Robots.txt Disallowed", [])
    if disallowed:
        console.print()
        inv = Prompt.ask(
            "[bold]Inspect disallowed paths interactively?[/bold]",
            choices=["y", "n"],
            default="n",
        )
        if inv == "y":
            t = Table(title="Robots.txt Disallowed Paths", box=box.ROUNDED,
                      header_style="bold cyan")
            t.add_column("#", style="dim", min_width=4)
            t.add_column("Path", min_width=40)
            for i, p in enumerate(disallowed, 1):
                t.add_row(str(i), p)
            console.print(t)
            console.print("[dim]Paths listed above are hidden in robots.txt and may contain sensitive content.[/dim]")

    _offer_json_export(result, f"exposed_{domain}")


# ---------------------------------------------------------------------------
# Option 5 — Metadata Extraction
# ---------------------------------------------------------------------------

def handle_metadata_extraction() -> None:
    """Extract metadata from a URL-linked file or local file."""
    tools_avail: list[str] = []
    if EXIFTOOL_AVAILABLE:
        tools_avail.append("exiftool")
    if PYMUPDF_AVAILABLE:
        tools_avail.append("PyMuPDF (PDF only)")

    if tools_avail:
        console.print(f"  [dim]Extraction tools available: {', '.join(tools_avail)}[/dim]")
    else:
        console.print(Panel(
            "[yellow]No extraction tools found.\n\n"
            "For full metadata extraction, install:\n"
            "  [cyan]sudo apt install libimage-exiftool-perl[/cyan]  (exiftool — recommended)\n"
            "  [cyan]pip install PyMuPDF[/cyan]                      (PDF only)\n\n"
            "Basic file info will still be shown without these tools.[/yellow]",
            border_style="yellow",
        ))

    console.print()
    src_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    src_table.add_column(style="bold cyan", min_width=4)
    src_table.add_column()
    src_table.add_row("1", "Extract from URL    (download file, then analyse)")
    src_table.add_row("2", "Extract from local file path")
    src_table.add_row("0", "[dim]Back[/dim]")
    console.print(Panel(src_table, title="[bold]Select Source[/bold]", border_style="magenta"))

    src = Prompt.ask("Source", choices=["0", "1", "2"], default="0")
    if src == "0":
        return

    result: dict = {}

    if src == "1":
        url = Prompt.ask(
            "[bold]Enter URL of file to analyse[/bold] "
            "[dim](e.g. https://example.com/document.pdf)[/dim]"
        ).strip()
        if not url:
            return

        console.print()
        console.print(Panel(
            "[yellow]ℹ  The file will be downloaded to a temporary location,\n"
            "analysed, and the temp file deleted immediately after.\n"
            "This makes an HTTP request to the target server.[/yellow]",
            border_style="yellow",
        ))
        proceed = Prompt.ask("[bold]Proceed with download?[/bold]", choices=["y", "n"], default="n")
        if proceed != "y":
            return

        with Progress(SpinnerColumn(), TextColumn("[bold cyan]{task.description}"),
                      console=console, transient=True) as progress:
            progress.add_task("Downloading and extracting metadata…", total=None)
            result = extract_metadata_from_url(url)

    else:  # local file
        console.print("[dim]Supports: PDF, JPEG, PNG, TIFF, DOCX, XLSX, MP3, MP4, and more[/dim]")
        file_path = Prompt.ask("[bold]Enter full path to local file[/bold]").strip()
        if not file_path:
            return

        with Progress(SpinnerColumn(), TextColumn("[bold cyan]{task.description}"),
                      console=console, transient=True) as progress:
            progress.add_task("Extracting metadata…", total=None)
            result = extract_metadata_from_file(file_path)

    print_metadata_result(result)

    # GPS follow-up
    details = result.get("details", {})
    gps     = details.get("GPS Coordinates", "None")
    if gps and gps != "None" and gps != "N/A":
        console.print()
        console.print("[bold red]⚠  GPS COORDINATES FOUND IN FILE METADATA[/bold red]")
        console.print(f"   Location: [bold]{gps}[/bold]")
        maps_url = f"https://maps.google.com/?q={gps.replace(' ', '')}"
        console.print(f"   [dim]{maps_url}[/dim]")
        open_map = Prompt.ask("[bold]Open location in browser?[/bold]", choices=["y", "n"], default="n")
        if open_map == "y":
            webbrowser.open(maps_url)

    _offer_json_export(result, "metadata")


# ---------------------------------------------------------------------------
# Option 6 — Full Domain Recon
# ---------------------------------------------------------------------------

def handle_full_recon() -> None:
    """Run all passive OSINT modules concurrently against a domain."""
    console.print(Panel(_ACTIVE_WARNING, border_style="red", box=box.HEAVY, padding=(1, 2)))
    console.print()

    confirm = Prompt.ask("[bold red]Confirm authorisation[/bold red]", default="").strip()
    if confirm.upper() != "YES":
        console.print("[dim]Scan cancelled.[/dim]")
        return

    domain = prompt_domain_input("Enter target domain for full OSINT recon")

    console.print()
    console.print(Panel(
        "[cyan]ℹ  Full recon will run:\n"
        "  • Email & Subdomain Harvesting (theHarvester)\n"
        "  • Tech Stack Fingerprinting (BuiltWith + Wappalyzer)\n"
        "  • Wayback Machine History\n"
        "  • Exposed Files Check (active HTTP requests to target)\n\n"
        "Metadata extraction requires a specific file URL — run separately (option 5).[/cyan]",
        border_style="cyan",
        padding=(1, 2),
    ))
    console.print()

    all_results: list[dict] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console,
        transient=True,
    ) as progress:
        total_task = progress.add_task(f"Running OSINT recon on {domain}…", total=4)

        tasks = {
            "Email Harvesting (theHarvester)":     lambda: harvest_emails_and_subdomains(domain),
            "Tech Stack (BuiltWith + Wappalyzer)": lambda: fingerprint_tech_stack(domain),
            "Wayback Machine History":             lambda: wayback_lookup(domain),
            "Exposed Files Check":                 lambda: check_exposed_files(domain),
        }

        with ThreadPoolExecutor(max_workers=4) as executor:
            future_map = {executor.submit(fn): name for name, fn in tasks.items()}
            for future in as_completed(future_map):
                name = future_map[future]
                try:
                    r = future.result()
                    all_results.append(r)
                except Exception as exc:
                    all_results.append({
                        "source":  name,
                        "skipped": False,
                        "error":   True,
                        "flagged": False,
                        "details": {"Error": str(exc)},
                    })
                console.print(f"  [green]✓[/green] [dim]{name} complete[/dim]")
                progress.update(total_task, advance=1)

    console.print()
    console.print(f"[bold cyan]━━━ Full Recon Results — {domain} ━━━[/bold cyan]")
    console.print()

    for result in all_results:
        src = result.get("source", "Unknown")
        if result.get("skipped"):
            console.print(f"  [dim]○ {src}: SKIPPED — {result.get('details', {}).get('Reason', 'no data')}[/dim]")
        elif result.get("error"):
            console.print(f"  [red]✗ {src}: ERROR — {result.get('details', {}).get('Error', '')}[/red]")
        elif "Exposed Files" in src:
            print_exposed_files_result(result)
        elif "Wayback" in src:
            _print_wayback_result(result)
        elif "Metadata" in src:
            print_metadata_result(result)
        else:
            print_osint_result(result)

    print_full_recon_summary(domain, all_results)
    _offer_json_export(all_results, f"full_recon_{domain}")


# ---------------------------------------------------------------------------
# Rendering functions
# ---------------------------------------------------------------------------

def _print_compact_result(result: dict) -> None:
    """Print a compact one-table result (used for inline DNS lookups)."""
    from modules.utils import print_result_table
    print_result_table(result, result.get("source", "Result"))


def print_osint_result(result: dict) -> None:
    """General-purpose OSINT result renderer matching utils.print_result_table() style."""
    if result.get("skipped"):
        reason = result.get("details", {}).get("Reason", "no key configured")
        console.print(f"  [dim]○ {result.get('source', 'Unknown')}: SKIPPED — {reason}[/dim]\n")
        return

    if result.get("error"):
        err = result.get("details", {}).get("Error", "Unknown error")
        console.print(Panel(
            f"[bold red]Error:[/bold red] {err}",
            title=f"[bold red]✗ {result.get('source', 'Unknown')}[/bold red]",
            border_style="red",
        ))
        console.print()
        return

    flagged     = result.get("flagged", False)
    border      = "yellow" if flagged else "green"
    details     = result.get("details", {})
    source      = result.get("source", "Result")

    table = Table(
        title=source,
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
        title_style="bold white",
        border_style=border,
        expand=False,
        show_lines=True,
    )
    table.add_column("Field", style="bold white", no_wrap=True, min_width=28)
    table.add_column("Value", min_width=48)

    # Source-specific list display limits
    LIST_LIMITS = {
        "Email List":      30,
        "Subdomain List":  50,
        "IP List":         20,
        "All Technologies": None,
    }

    for key, value in details.items():
        if value is None or value == "" or value == [] or value == {}:
            table.add_row(str(key), "[dim]N/A[/dim]")
            continue

        if isinstance(value, list):
            if not value:
                table.add_row(str(key), "[dim]None[/dim]")
                continue

            if key == "All Technologies":
                # Wrap as comma-separated
                display_val = ", ".join(str(v) for v in value)
                if len(display_val) > 200:
                    display_val = display_val[:197] + "…"
                colour = "cyan"
                style  = "Security Headers Missing" in key and "red" or colour
                table.add_row(str(key), f"[{colour}]{display_val}[/{colour}]")
                continue

            limit = LIST_LIMITS.get(key, 20)
            shown = value[:limit] if limit else value
            extra = len(value) - len(shown)

            # Colour code security header rows
            if key == "Security Headers Missing":
                items = "\n".join(f"  [red]✗ {v}[/red]" for v in shown)
            elif key == "Security Headers Present":
                items = "\n".join(f"  [green]✓ {v}[/green]" for v in shown)
            else:
                items = "\n".join(f"  {i+1}. {v}" for i, v in enumerate(shown))

            if extra > 0:
                items += f"\n  [dim]+ {extra} more…[/dim]"
            table.add_row(str(key), items)

        elif isinstance(value, dict):
            pairs = "\n".join(f"  [dim]{k}:[/dim] {str(v)[:80]}" for k, v in list(value.items())[:10])
            table.add_row(str(key), pairs)

        else:
            str_val = str(value)
            # URL styling
            if any(x in key for x in ("URL", "Report", "Link")):
                display = f"[dim]{str_val[:120]}[/dim]"
            elif len(str_val) > 120:
                display = str_val[:117] + "…"
            else:
                display = str_val
            table.add_row(str(key), display)

    console.print(table)
    console.print()


def _print_wayback_result(result: dict) -> None:
    """Render Wayback Machine results with a snapshot table."""
    if result.get("skipped") or result.get("error"):
        print_osint_result(result)
        return

    details = result.get("details", {})
    source  = result.get("source", "Wayback Machine")

    # Summary table
    summary = Table(
        title=source,
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
        title_style="bold white",
        border_style="cyan",
        expand=False,
        show_lines=True,
    )
    summary.add_column("Field", style="bold white", no_wrap=True, min_width=26)
    summary.add_column("Value", min_width=48)

    skip_keys = {"Recent Snapshots"}
    for key, value in details.items():
        if key in skip_keys:
            continue
        if isinstance(value, list):
            val_str = "\n".join(f"  • {v}" for v in value) if value else "[dim]None[/dim]"
        else:
            val_str = str(value) if value else "[dim]N/A[/dim]"
        if "URL" in key or "url" in key:
            val_str = f"[dim]{val_str}[/dim]"
        summary.add_row(str(key), val_str)

    console.print(summary)
    console.print()

    # Snapshot table
    snapshots = details.get("Recent Snapshots", [])
    if snapshots:
        snap_table = Table(
            title="Recent Archived Snapshots",
            box=box.SIMPLE_HEAD,
            show_header=True,
            header_style="bold cyan",
            border_style="dim",
        )
        snap_table.add_column("Date",   min_width=16, no_wrap=True)
        snap_table.add_column("Status", min_width=6,  justify="center")
        snap_table.add_column("Type",   min_width=8)
        snap_table.add_column("Size",   min_width=8)
        snap_table.add_column("Wayback URL", style="dim")

        for snap in snapshots:
            parts = snap.split(" | ")
            if len(parts) < 5:
                continue
            date, status, mime, size, url = parts[0], parts[1], parts[2], parts[3], parts[4]
            sc_style = "green" if status == "200" else ("yellow" if status in ("301", "302") else "red")
            snap_table.add_row(
                date,
                f"[{sc_style}]{status}[/{sc_style}]",
                mime,
                size,
                url[:80],
            )

        console.print(snap_table)
        console.print()


def print_exposed_files_result(result: dict) -> None:
    """Specialised renderer for exposed files check results."""
    if result.get("error"):
        print_osint_result(result)
        return

    details = result.get("details", {})
    domain  = details.get("Target Domain", "unknown")

    severity_styles = {
        "CRITICAL": ("red",         "red"),
        "HIGH":     ("yellow",      "dark_orange"),
        "MEDIUM":   ("dark_orange", "dark_orange"),
        "LOW":      ("dim",         "dim"),
        "INFO":     ("dim cyan",    "dim"),
    }

    for sev in _SEVERITY_ORDER:
        paths = details.get(f"{sev} Paths", [])
        if not paths:
            continue

        style, border = severity_styles[sev]
        t = Table(
            title=f"{sev} — {len(paths)} finding{'s' if len(paths) != 1 else ''}",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold white",
            border_style=border,
            title_style=f"bold {style}",
        )
        t.add_column("Path", min_width=35)
        t.add_column("Status", min_width=30)
        for entry in paths:
            if "  —  " in entry:
                path_part, status_part = entry.split("  —  ", 1)
                t.add_row(f"[{style}]{path_part}[/{style}]", status_part)
            else:
                t.add_row(f"[{style}]{entry}[/{style}]", "")
        console.print(t)
        console.print()

    # Robots.txt disallowed
    disallowed = details.get("Robots.txt Disallowed", [])
    if disallowed:
        rt = Table(
            title="Paths hidden in robots.txt (worth investigating)",
            box=box.SIMPLE_HEAD,
            header_style="bold cyan",
            border_style="dim",
        )
        rt.add_column("#", style="dim", min_width=4)
        rt.add_column("Disallowed Path", min_width=40)
        for i, p in enumerate(disallowed, 1):
            rt.add_row(str(i), p)
        console.print(rt)
        console.print()

    # Summary panel
    total_crit = int(details.get("Critical Findings", 0))
    total_high = int(details.get("High Findings", 0))
    total_med  = int(details.get("Medium Findings", 0))
    total_low  = int(details.get("Low Findings", 0))
    total_info = int(details.get("Info Findings", 0))
    total_exp  = int(details.get("Exposed / Accessible", "0").split()[0])

    if total_crit > 0:
        verdict = "[bold red]CRITICAL EXPOSURE[/bold red]"
        v_border = "red"
    elif total_high > 0:
        verdict = "[bold dark_orange]EXPOSED[/bold dark_orange]"
        v_border = "dark_orange"
    elif total_med > 0 or total_low > 0:
        verdict = "[bold yellow]MINOR EXPOSURE[/bold yellow]"
        v_border = "yellow"
    else:
        verdict = "[bold green]CLEAN[/bold green]"
        v_border = "green"

    console.print(Panel(
        f"  Target         : [bold]{domain}[/bold]\n"
        f"  Paths Checked  : {details.get('Total Paths Checked', '?')}\n"
        f"  Total Exposed  : {total_exp}\n\n"
        f"  🔴 CRITICAL : {total_crit}\n"
        f"  🟠 HIGH     : {total_high}\n"
        f"  🟡 MEDIUM   : {total_med}\n"
        f"  🔵 LOW      : {total_low}\n"
        f"  ℹ  INFO     : {total_info}\n\n"
        f"  Verdict        : {verdict}",
        title="[bold white]Exposed Files Summary[/bold white]",
        border_style=v_border,
        box=box.ROUNDED,
        padding=(1, 2),
    ))
    console.print()


def print_metadata_result(result: dict) -> None:
    """Specialised renderer for metadata extraction results."""
    if result.get("error"):
        print_osint_result(result)
        return

    details = result.get("details", {})
    risks   = details.get("Privacy Risks", [])

    # Privacy risk summary
    if risks:
        risk_lines = []
        for r in risks:
            if r.startswith("[CRITICAL]"):
                risk_lines.append(f"[bold red]{r}[/bold red]")
            elif r.startswith("[HIGH]"):
                risk_lines.append(f"[red]{r}[/red]")
            elif r.startswith("[MEDIUM]"):
                risk_lines.append(f"[yellow]{r}[/yellow]")
            else:
                risk_lines.append(f"[dim]{r}[/dim]")
        console.print(Panel(
            "\n".join(risk_lines),
            title="[bold red]⚠  Privacy Risk Findings[/bold red]",
            border_style="red",
            padding=(1, 2),
        ))
    else:
        console.print(Panel(
            "[bold green]No privacy risks detected in metadata.[/bold green]",
            border_style="green",
        ))
    console.print()

    # All metadata fields table
    all_meta = details.get("All Metadata Fields", {})
    if all_meta:
        meta_table = Table(
            title="Extracted Metadata",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold cyan",
            border_style="cyan",
            show_lines=True,
        )
        meta_table.add_column("Field", style="bold white", no_wrap=True, min_width=30)
        meta_table.add_column("Value", min_width=48)

        sensitive_keys = {
            "Author", "GPS Latitude", "GPS Longitude", "GPS Position",
            "Serial Number", "Company", "Last Modified By",
        }
        for k, v in all_meta.items():
            if not v or str(v) in ("", "N/A", "None"):
                continue
            val_str = str(v)[:120]
            if any(sk.lower() in k.lower() for sk in sensitive_keys):
                meta_table.add_row(k, f"[yellow]{val_str}[/yellow]")
            else:
                meta_table.add_row(k, val_str)

        console.print(meta_table)
        console.print()

    # Key fields summary
    key_fields = [
        ("File URL / Path",     "cyan"),
        ("File Type",           "white"),
        ("File Size",           "white"),
        ("Extraction Tool",     "dim"),
        ("Author",              "yellow"),
        ("Creator",             "yellow"),
        ("Company",             "yellow"),
        ("Created",             "white"),
        ("Modified",            "white"),
        ("GPS Coordinates",     "red"),
        ("Camera / Device",     "white"),
        ("Serial Number",       "red"),
        ("Privacy Risks Count", "red"),
    ]

    summary_table = Table(
        title="Key Metadata Summary",
        box=box.ROUNDED,
        header_style="bold cyan",
        border_style="magenta",
        show_lines=True,
    )
    summary_table.add_column("Field", style="bold white", min_width=26, no_wrap=True)
    summary_table.add_column("Value", min_width=48)

    for key, colour in key_fields:
        if key == "Privacy Risks Count":
            val = str(details.get("Total Risk Findings", "0"))
        else:
            val = str(details.get(key, "N/A"))
        if not val or val in ("N/A", "None", ""):
            continue
        summary_table.add_row(key, f"[{colour}]{val}[/{colour}]")

    console.print(summary_table)
    console.print()


def print_full_recon_summary(domain: str, results: list[dict]) -> None:
    """Print a consolidated summary panel after full_domain_recon() completes."""
    # Aggregate
    emails_found:    list[str] = []
    subdomains_found: list[str] = []
    first_archived:  str = "N/A"
    tech_count:      int = 0
    exposed_critical: int = 0
    exposed_high:    int = 0

    for r in results:
        if r.get("skipped") or r.get("error"):
            continue
        d   = r.get("details", {})
        src = r.get("source", "")

        if "Harvester" in src or "harvest" in src.lower():
            emails_found     = d.get("Email List", [])
            subdomains_found = d.get("Subdomain List", [])
        elif "Wayback" in src:
            first_archived = d.get("First Archived", "N/A")
        elif "Tech" in src or "BuiltWith" in src or "Wappalyzer" in src:
            try:
                tech_count = int(d.get("Total Unique Technologies", d.get("Total Technologies", "0")))
            except (ValueError, TypeError):
                tech_count = 0
        elif "Exposed" in src:
            try:
                exposed_critical = int(d.get("Critical Findings", 0))
                exposed_high     = int(d.get("High Findings",     0))
            except (ValueError, TypeError):
                pass

    # Risk level
    if exposed_critical > 0:
        risk_level  = "CRITICAL"
        risk_style  = "bold red"
        action_text = ("Immediate remediation required. Remove exposed critical files,\n"
                       "  revoke and rotate any exposed credentials or keys.")
    elif exposed_high > 0 or len(emails_found) > 10:
        risk_level  = "HIGH"
        risk_style  = "bold red"
        action_text = ("Review and remediate high-severity findings. Audit exposed\n"
                       "  admin panels and remove unnecessary public paths.")
    elif len(subdomains_found) > 20 or tech_count > 15:
        risk_level  = "MEDIUM"
        risk_style  = "bold yellow"
        action_text = ("Review discovered subdomains for shadow IT. Validate all\n"
                       "  exposed paths are intentional.")
    elif first_archived != "N/A":
        risk_level  = "LOW"
        risk_style  = "yellow"
        action_text = ("Minor findings only. Review subdomain inventory and keep\n"
                       "  tech stack updated.")
    else:
        risk_level  = "INFO"
        risk_style  = "dim"
        action_text = ("No significant findings. Continue regular recon cycles\n"
                       "  to detect new exposure.")

    crit_display = (f"[bold red]{exposed_critical}[/bold red]" if exposed_critical > 0
                    else str(exposed_critical))
    high_display = (f"[yellow]{exposed_high}[/yellow]" if exposed_high > 0
                    else str(exposed_high))

    body = (
        f"\n  Target Domain        : [bold cyan]{domain}[/bold cyan]\n"
        f"  Scan Time            : {datetime.now().strftime('%Y-%m-%d %H:%M')}\n"
        f"  Overall Risk         : [{risk_style}]{risk_level}[/{risk_style}]\n\n"
        f"  ── Key Findings ─────────────────────────────────────────────\n"
        f"  Emails Harvested      : {len(emails_found)}\n"
        f"  Subdomains Discovered : {len(subdomains_found)}\n"
        f"  Technologies Detected : {tech_count}\n"
        f"  First Archived        : {first_archived}\n"
        f"  Critical Exposures    : {crit_display}\n"
        f"  High Exposures        : {high_display}\n\n"
        f"  ── Recommended Actions ───────────────────────────────────────\n"
        f"  {action_text}\n"
    )

    console.print(Panel(
        body,
        title="[bold white]OSINT RECON SUMMARY[/bold white]",
        border_style=risk_style.split()[-1] if risk_style != "dim" else "dim",
        box=box.DOUBLE_EDGE,
        padding=(0, 2),
    ))
    console.print()
