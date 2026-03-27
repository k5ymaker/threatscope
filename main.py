"""
main.py — ThreatScope v1.0 entry point.

Presents a rich interactive terminal menu and dispatches user selections to
the appropriate intelligence module functions.  Option 9 runs all relevant
checks concurrently via ThreadPoolExecutor and produces a consolidated IOC
report with optional JSON export.

Run from the project root:
    python main.py
"""

from __future__ import annotations

import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import urlparse

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

# ---------------------------------------------------------------------------
# Project-relative imports
# ---------------------------------------------------------------------------
# Ensure the project root (directory of this file) is on sys.path so that
# "config" and "modules" are always importable regardless of CWD.
_ROOT = os.path.dirname(os.path.abspath(__file__))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from modules import dns_tools, ip_intel, url_intel, utils  # noqa: E402
from modules.nmap_menus import show_nmap_menu  # noqa: E402
from modules.web_fingerprint_menus import show_web_fingerprint_menu  # noqa: E402
from modules.hash_menus import show_hash_menu  # noqa: E402
from modules.osint_menus import show_osint_menu  # noqa: E402

try:
    from modules.dependency_menus import show_dependency_menu as _show_dependency_menu
except ImportError:
    _show_dependency_menu = None  # type: ignore[assignment]

try:
    from modules.email_intel import handle_email_menu as _handle_email_menu
except ImportError:
    _handle_email_menu = None  # type: ignore[assignment]

try:
    from modules.subdomain_menus import handle_subdomain_menu as _handle_subdomain_menu
except ImportError:
    _handle_subdomain_menu = None  # type: ignore[assignment]

try:
    from modules.cve_intel import handle_cve_menu as _handle_cve_menu
except ImportError:
    _handle_cve_menu = None  # type: ignore[assignment]

try:
    from modules.ssl_analyzer import handle_ssl_menu as _handle_ssl_menu
except ImportError:
    _handle_ssl_menu = None  # type: ignore[assignment]

try:
    from modules.threat_feeds import handle_feeds_menu as _handle_feeds_menu
except ImportError:
    _handle_feeds_menu = None  # type: ignore[assignment]

try:
    from modules.mitre_attack import handle_mitre_menu as _handle_mitre_menu
except ImportError:
    _handle_mitre_menu = None  # type: ignore[assignment]

console = Console()


# ---------------------------------------------------------------------------
# Banner & Menu
# ---------------------------------------------------------------------------

_BANNER = r"""
  ████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗███████╗ ██████╗ ██████╗ ██████╗ ███████╗
     ██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝██╔════╝██╔════╝██╔════╝██╔═══██╗██╔══██╗███████╗
     ██║   ███████║██████╔╝█████╗  ███████║   ██║   ███████╗██║     ██║     ██║   ██║██████╔╝██╔════╝
     ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║   ╚════██║██║     ██║     ██║   ██║██╔═══╝ ███████╗
     ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║   ███████║╚██████╗╚██████╗╚██████╔╝██║     ╚════██║
     ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝  ╚═╝   ╚══════╝ ╚═════╝ ╚═════╝ ╚═════╝ ╚═╝     ███████║
                                                                                                ╚══════╝"""

_BANNER_SIMPLE = r"""
  _____ _                    _    ____
 |_   _| |__  _ __ ___  __ _| |_ / ___|  ___ ___  _ __   ___
   | | | '_ \| '__/ _ \/ _` | __\___ \ / __/ _ \| '_ \ / _ \
   | | | | | | | |  __/ (_| | |_ ___) | (_| (_) | |_) |  __/
   |_| |_| |_|_|  \___|\__,_|\__|____/ \___\___/| .__/ \___|
                                                  |_|
"""

_TAGLINE = "Terminal-based Threat Intelligence  ·  Investigate URLs, IPs & Domains"
_AUTHOR  = "by  arunjitk"
_VERSION = "v1.0"

# Menu entries: (key, icon, label, sources)
# Use key="─" for visual separator rows
_MENU_ITEMS = [
    ("1", "󰖂", "URL Reputation Check",    "VirusTotal · PhishTank · Google Safe Browsing · APIVoid"),
    ("2", "󰐇", "URL Scan & Analysis",     "URLScan.io live browser scan"),
    ("─", "", "IP INTELLIGENCE", ""),
    ("3", "󱒋", "IP Reputation",           "AbuseIPDB · VirusTotal · GreyNoise · DNSBL"),
    ("4", "󰍉", "IP Geolocation & Info",   "IPInfo · AlienVault OTX"),
    ("5", "󰣆", "Shodan Lookup",           "Open ports · Service banners · CVEs"),
    ("─", "", "DNS & WHOIS", ""),
    ("6", "󰩠", "DNS Lookup",              "A · AAAA · MX · TXT · NS · CNAME · SOA"),
    ("7", "󰌷", "Reverse DNS Lookup",      "PTR record resolution"),
    ("8", "󰋼", "WHOIS Information",       "Registrar · Dates · Nameservers"),
    ("─", "", "REPORTS", ""),
    ("9", "󰐊", "Full IOC Report",         "All checks concurrently + JSON export"),
    ("─", "", "ADVANCED TOOLS", ""),
    ("N", "󰙵", "Nmap Scanner",            "Port scan · Vuln scripts · OS detection"),
    ("W", "󰖟", "Web Fingerprint",         "WhatWeb · Wappalyzer · WafW00f"),
    ("H", "󰡭", "Hash & File Intel",       "MalwareBazaar · VirusTotal · Hybrid Analysis · ThreatFox"),
    ("O", "󰐙", "OSINT Recon",            "Email harvest · Tech stack · Wayback · Exposed files · Metadata"),
    ("─", "", "EXTENDED INTELLIGENCE", ""),
    ("E", "󰀓", "Email Intelligence",      "HIBP · EmailRep · Holehe · SPF/DKIM/DMARC audit"),
    ("S", "󰕒", "Subdomain & ASN Recon",  "crt.sh · HackerTarget · BGPView · RIPEstat · SecurityTrails"),
    ("C", "󱑷", "CVE Intelligence",        "NVD NIST · CISA KEV · searchsploit · Vulners · EPSS"),
    ("T", "󰢻", "SSL/TLS Analyzer",       "Cert info · Qualys SSL Labs grade · cipher analysis"),
    ("F", "󰈊", "Live Threat Feeds",      "URLhaus · ThreatFox · Feodo Tracker · SSL Blacklist"),
    ("M", "󰰑", "MITRE ATT&CK Mapper",   "Technique · Group · Software · Tactic explorer"),
    ("─", "", "UTILITIES", ""),
    ("D", "󰏗", "Dependency Manager",     "Check · install · verify all tools and API keys"),
    ("0", "󰈆", "Exit",                    ""),
]

# Colour scheme per menu key group
_KEY_STYLES = {
    "1": "bold bright_cyan",
    "2": "bold bright_cyan",
    "3": "bold bright_green",
    "4": "bold bright_green",
    "5": "bold bright_green",
    "6": "bold bright_yellow",
    "7": "bold bright_yellow",
    "8": "bold bright_yellow",
    "9": "bold bright_red",
    "N": "bold bright_magenta",
    "W": "bold bright_blue",
    "H": "bold orange1",
    "O": "bold bright_blue",
    "E": "bold magenta",
    "S": "bold bright_magenta",
    "C": "bold red",
    "T": "bold green",
    "F": "bold bright_red",
    "M": "bold bright_yellow",
    "D": "bold bright_white",
    "0": "dim",
}


def print_banner() -> None:
    """Print the ThreatScope ASCII banner with styled tagline and author credit."""
    # Gradient-style banner: each line shifts colour
    banner_colours = [
        "bold bright_cyan",
        "bold cyan",
        "bold bright_cyan",
        "bold cyan",
        "bold bright_cyan",
        "bold cyan",
        "bold bright_cyan",
    ]
    banner_lines = _BANNER_SIMPLE.split("\n")
    coloured_banner = Text()
    colour_idx = 0
    for line in banner_lines:
        style = banner_colours[colour_idx % len(banner_colours)]
        coloured_banner.append(line + "\n", style=style)
        if line.strip():
            colour_idx += 1

    console.print(coloured_banner, justify="center")

    # Tagline + author panel with double-edge border
    tagline_text = Text(justify="center")
    tagline_text.append("⚡ ", style="bold yellow")
    tagline_text.append(_TAGLINE, style="bold white")
    tagline_text.append("  ⚡\n", style="bold yellow")
    tagline_text.append(_AUTHOR, style="italic bold red")
    tagline_text.append("  ·  ", style="dim")
    tagline_text.append(_VERSION, style="bold dim cyan")

    console.print(
        Panel(
            tagline_text,
            border_style="bright_cyan",
            box=box.DOUBLE_EDGE,
            padding=(0, 6),
        )
    )
    console.print()


def display_menu() -> None:
    """Render the main interactive menu as a styled rich Table."""
    table = Table(
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style="bold bright_white on grey23",
        border_style="bright_cyan",
        title_style="bold bright_white",
        expand=False,
        padding=(0, 2),
        show_edge=True,
        show_lines=False,
    )
    table.add_column("  KEY", style="bold", no_wrap=True,  min_width=7,  justify="center")
    table.add_column("MODULE",              no_wrap=True,  min_width=26)
    table.add_column("SOURCES / DESCRIPTION",              min_width=52, style="dim")

    for key, _icon, label, sources in _MENU_ITEMS:
        # Separator row
        if key == "─":
            table.add_row(
                "",
                f"[bold dim]─── {label} ───[/bold dim]",
                "",
            )
            continue

        key_style  = _KEY_STYLES.get(key, "bold white")
        key_cell   = f"[{key_style}] {key} [/{key_style}]"

        if key == "0":
            label_cell   = f"[dim]{label}[/dim]"
            sources_cell = ""
        elif key == "9":
            label_cell   = f"[bold bright_red]{label}[/bold bright_red]"
            sources_cell = f"[dim]{sources}[/dim]"
        else:
            label_cell   = f"[bold white]{label}[/bold white]"
            sources_cell = f"[dim]{sources}[/dim]"

        table.add_row(key_cell, label_cell, sources_cell)

    # Wrap table in a panel for a clean bordered box
    console.print(
        Panel(
            table,
            title="[bold bright_white on grey23]  THREATSCOPE — MAIN MENU  [/bold bright_white on grey23]",
            border_style="bright_cyan",
            box=box.DOUBLE_EDGE,
            padding=(0, 1),
        )
    )
    console.print()


# ---------------------------------------------------------------------------
# Input helpers
# ---------------------------------------------------------------------------

def prompt_url() -> str:
    """Prompt for and validate a URL, looping until a valid one is entered."""
    while True:
        val = Prompt.ask("[bold]Enter URL[/bold] [dim](e.g. https://example.com)[/dim]").strip()
        if utils.validate_url(val):
            return val
        console.print("[bold red]  Invalid URL. Must start with http:// or https://[/bold red]")


def prompt_ip() -> str:
    """Prompt for and validate an IP address, looping until valid."""
    while True:
        val = Prompt.ask("[bold]Enter IP address[/bold]").strip()
        if utils.validate_ip(val):
            return val
        console.print("[bold red]  Invalid IP address.[/bold red]")


def prompt_domain() -> str:
    """Prompt for and validate a domain name, looping until valid."""
    while True:
        val = Prompt.ask("[bold]Enter domain[/bold] [dim](e.g. example.com)[/dim]").strip()
        if utils.validate_domain(val):
            return val
        console.print("[bold red]  Invalid domain format.[/bold red]")


def prompt_ioc() -> str:
    """Prompt for a free-form IOC (URL, IP, or domain) — no strict validation."""
    return Prompt.ask(
        "[bold]Enter IOC[/bold] [dim](URL, IP address, or domain)[/dim]"
    ).strip()


# ---------------------------------------------------------------------------
# Per-option handlers
# ---------------------------------------------------------------------------

def handle_url_reputation() -> None:
    """Option 1 — URL reputation check across VirusTotal, PhishTank, GSB, APIVoid."""
    url = prompt_url()
    utils.print_section_header(f"URL Reputation: {url}")

    for fn in (
        url_intel.check_virustotal_url,
        url_intel.check_phishtank,
        url_intel.check_google_safe_browsing,
        url_intel.check_apivoid_url,
    ):
        result = fn(url)
        if result.get("skipped"):
            utils.print_skipped(result["source"])
        else:
            utils.print_result_table(result, result["source"])


def handle_url_scan() -> None:
    """Option 2 — URLScan.io live browser scan."""
    url = prompt_url()
    utils.print_section_header(f"URL Scan: {url}")
    result = url_intel.scan_urlscan(url)
    if result.get("skipped"):
        utils.print_skipped(result["source"])
    else:
        utils.print_result_table(result, result["source"])


def handle_ip_reputation() -> None:
    """Option 3 — IP reputation, blacklist, and DNSBL check."""
    ip = prompt_ip()
    utils.print_section_header(f"IP Reputation: {ip}")

    for fn in (
        ip_intel.check_virustotal_ip,
        ip_intel.check_abuseipdb,
        ip_intel.check_greynoise_ip,
        dns_tools.spamhaus_dnsbl_check,
    ):
        result = fn(ip)
        if result.get("skipped"):
            utils.print_skipped(result["source"])
        else:
            utils.print_result_table(result, result["source"])


def handle_ip_geo() -> None:
    """Option 4 — IP geolocation and network metadata."""
    ip = prompt_ip()
    utils.print_section_header(f"IP Geolocation: {ip}")

    for fn in (ip_intel.get_ipinfo, ip_intel.check_alienvault_ip):
        result = fn(ip)
        if result.get("skipped"):
            utils.print_skipped(result["source"])
        else:
            utils.print_result_table(result, result["source"])


def handle_shodan() -> None:
    """Option 5 — Shodan host lookup (open ports, services, CVEs)."""
    ip = prompt_ip()
    utils.print_section_header(f"Shodan Lookup: {ip}")
    result = ip_intel.lookup_shodan_ip(ip)
    if result.get("skipped"):
        utils.print_skipped(result["source"])
    else:
        utils.print_result_table(result, result["source"])


def handle_dns_lookup() -> None:
    """Option 6 — DNS record lookup (A, AAAA, MX, NS, TXT, CNAME, SOA)."""
    domain = prompt_domain()
    utils.print_section_header(f"DNS Lookup: {domain}")
    result = dns_tools.dns_lookup(domain)
    utils.print_result_table(result, result["source"])


def handle_reverse_dns() -> None:
    """Option 7 — Reverse DNS (PTR) lookup."""
    ip = prompt_ip()
    utils.print_section_header(f"Reverse DNS: {ip}")
    result = dns_tools.reverse_dns_lookup(ip)
    utils.print_result_table(result, result["source"])


def handle_whois() -> None:
    """Option 8 — WHOIS information for a domain or IP."""
    ioc = Prompt.ask("[bold]Enter domain or IP[/bold]").strip()
    utils.print_section_header(f"WHOIS: {ioc}")
    result = dns_tools.get_whois(ioc)
    utils.print_result_table(result, result["source"])


# ---------------------------------------------------------------------------
# Option 9 — Full IOC Report
# ---------------------------------------------------------------------------

def _build_task_list(ioc: str, ioc_type: str) -> list[tuple]:
    """
    Return a list of (callable, arg) pairs appropriate for the detected IOC type.
    """
    tasks: list[tuple] = []

    if ioc_type == "url":
        domain = urlparse(ioc).netloc or ioc
        tasks = [
            (url_intel.check_virustotal_url,       ioc),
            (url_intel.check_phishtank,             ioc),
            (url_intel.check_google_safe_browsing,  ioc),
            (url_intel.scan_urlscan,                ioc),
            (url_intel.check_apivoid_url,           ioc),
            (dns_tools.dns_lookup,                  domain),
            (dns_tools.get_whois,                   domain),
        ]

    elif ioc_type == "ip":
        tasks = [
            (ip_intel.check_virustotal_ip,   ioc),
            (ip_intel.check_abuseipdb,       ioc),
            (ip_intel.check_greynoise_ip,    ioc),
            (ip_intel.check_alienvault_ip,   ioc),
            (ip_intel.lookup_shodan_ip,      ioc),
            (ip_intel.get_ipinfo,            ioc),
            (dns_tools.reverse_dns_lookup,   ioc),
            (dns_tools.spamhaus_dnsbl_check, ioc),
        ]

    elif ioc_type == "domain":
        tasks = [
            (dns_tools.dns_lookup,                  ioc),
            (dns_tools.get_whois,                   ioc),
            (url_intel.check_virustotal_url,         f"http://{ioc}"),
            (url_intel.check_phishtank,              f"http://{ioc}"),
            (url_intel.check_google_safe_browsing,   f"http://{ioc}"),
        ]

    return tasks


def _print_verdict_banner(agg: dict) -> None:
    """Print a full-width verdict banner with colour-coded risk level."""
    verdict = agg["verdict"]
    style   = utils.verdict_style(verdict)

    lines = [
        f"[{style}]  VERDICT: {verdict}  [/{style}]",
        f"",
        f"Confidence : {agg['confidence']}% of active sources flagged this IOC",
        f"Flagged By : {', '.join(agg['flagged_by']) if agg['flagged_by'] else 'None'}",
        f"Clean On   : {', '.join(agg['clean_sources']) if agg['clean_sources'] else 'None'}",
        f"Skipped    : {', '.join(agg['skipped_sources']) if agg['skipped_sources'] else 'None'}",
        f"",
        f"[dim]{agg['summary']}[/dim]",
    ]

    # Recommended next steps
    advice_map = {
        "CLEAN":    "[green]IOC appears clean. Continue monitoring as threat landscapes change.[/green]",
        "LOW":      "[yellow]Low risk detected. Consider passive monitoring and review flagged sources.[/yellow]",
        "MEDIUM":   "[yellow]Medium risk. Investigate flagged sources and consider blocking as a precaution.[/yellow]",
        "HIGH":     "[red]High risk. Strongly recommend blocking and immediate investigation.[/red]",
        "CRITICAL": "[bold red]CRITICAL. Block immediately. Escalate to incident response team.[/bold red]",
        "UNKNOWN":  "[dim]Could not determine risk — no APIs returned usable data. Check your API keys.[/dim]",
    }
    lines += ["", "Recommended Action:", advice_map.get(verdict, "")]

    console.print(
        Panel(
            "\n".join(lines),
            title="[bold white]THREATSCOPE — FULL IOC REPORT[/bold white]",
            border_style=style.split()[-1] if "red" in style else ("yellow" if "yellow" in style else "green"),
            box=box.DOUBLE_EDGE,
            padding=(1, 4),
        )
    )


def _export_report(ioc: str, results: list[dict], agg: dict) -> None:
    """Serialise results to a timestamped JSON file in the reports/ directory."""
    reports_dir = os.path.join(_ROOT, "reports")
    os.makedirs(reports_dir, exist_ok=True)

    safe_ioc  = ioc.replace("://", "_").replace("/", "_").replace(".", "_")[:60]
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename  = os.path.join(reports_dir, f"{timestamp}_{safe_ioc}.json")

    export_data = {
        "generated_at": datetime.now().isoformat(),
        "ioc":          ioc,
        "verdict":      agg,
        "results":      results,
    }

    # Make details JSON-serialisable (convert any non-serialisable types to str)
    def _sanitise(obj):  # noqa: ANN001, ANN202
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
        json.dump(_sanitise(export_data), fh, indent=2, ensure_ascii=False)

    console.print(f"\n[bold green]Report exported → {filename}[/bold green]")


def handle_full_ioc_report() -> None:
    """
    Option 9 — Full IOC Report.

    Auto-detects the IOC type, runs all relevant checks concurrently using
    a ThreadPoolExecutor, aggregates results, and prints a final verdict banner.
    Offers optional JSON export.
    """
    ioc      = prompt_ioc()
    ioc_type = utils.detect_input_type(ioc)

    if ioc_type == "unknown":
        console.print(
            "[bold red]Could not identify input as a URL, IP address, or domain.[/bold red]"
        )
        return

    utils.print_section_header(f"Full IOC Report — {ioc}  [{ioc_type.upper()}]")

    task_list = _build_task_list(ioc, ioc_type)
    if not task_list:
        console.print("[dim]No tasks to run for this IOC type.[/dim]")
        return

    all_results: list[dict] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console,
        transient=True,
    ) as progress:
        prog_task = progress.add_task("Running checks…", total=len(task_list))

        with ThreadPoolExecutor(max_workers=6) as executor:
            future_map = {
                executor.submit(fn, arg): (fn.__name__, arg)
                for fn, arg in task_list
            }

            for future in as_completed(future_map):
                fn_name, _ = future_map[future]
                try:
                    result = future.result()
                    if result:
                        all_results.append(result)
                except Exception as exc:  # noqa: BLE001
                    all_results.append({
                        "source":  fn_name,
                        "skipped": False,
                        "error":   True,
                        "flagged": False,
                        "risk_score": None,
                        "details": {"Error": str(exc)},
                    })
                progress.update(prog_task, advance=1)

    # Print individual results
    console.print()
    utils.print_section_header("Per-Source Results")
    for result in all_results:
        if result.get("skipped"):
            utils.print_skipped(result.get("source", "Unknown"))
        else:
            utils.print_result_table(result, result.get("source", "Unknown"))

    # Aggregate and print verdict
    agg = utils.aggregate_risk_score(all_results)
    console.print()
    _print_verdict_banner(agg)

    # Optional export
    console.print()
    choice = Prompt.ask(
        "[yellow]Export full report to JSON?[/yellow]",
        choices=["y", "n"],
        default="n",
    )
    if choice == "y":
        _export_report(ioc, all_results, agg)


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def _unavailable(name: str) -> None:
    """Shown when an optional module could not be imported."""
    console.print(f"\n[bold red]Module '{name}' is unavailable.[/bold red]")
    console.print("[dim]Check that all dependencies are installed: run option [D] Dependency Manager.[/dim]\n")


_HANDLERS = {
    "1": handle_url_reputation,
    "2": handle_url_scan,
    "3": handle_ip_reputation,
    "4": handle_ip_geo,
    "5": handle_shodan,
    "6": handle_dns_lookup,
    "7": handle_reverse_dns,
    "8": handle_whois,
    "9": handle_full_ioc_report,
    "n": lambda: show_nmap_menu(),
    "w": lambda: show_web_fingerprint_menu(),
    "h": lambda: show_hash_menu(),
    "o": lambda: show_osint_menu(),
    "e": lambda: _handle_email_menu() if _handle_email_menu else _unavailable("Email Intelligence"),
    "s": lambda: _handle_subdomain_menu() if _handle_subdomain_menu else _unavailable("Subdomain & ASN Recon"),
    "c": lambda: _handle_cve_menu() if _handle_cve_menu else _unavailable("CVE Intelligence"),
    "t": lambda: _handle_ssl_menu() if _handle_ssl_menu else _unavailable("SSL/TLS Analyzer"),
    "f": lambda: _handle_feeds_menu() if _handle_feeds_menu else _unavailable("Live Threat Feeds"),
    "m": lambda: _handle_mitre_menu() if _handle_mitre_menu else _unavailable("MITRE ATT&CK Mapper"),
    "d": lambda: _show_dependency_menu() if _show_dependency_menu else _unavailable("Dependency Manager"),
}


def main() -> None:
    """Application entry point — display banner, then loop."""
    print_banner()

    # Quick dependency health hint
    if _show_dependency_menu is not None:
        try:
            from modules.dependency_checker import run_all_checks
            _dep_summary = run_all_checks()
            _missing_req = len(_dep_summary.get("missing_required", []))
            _missing_opt = len(_dep_summary.get("missing_optional", []))
            _missing_key = len(_dep_summary.get("missing_api_keys", []))
            if _missing_req > 0:
                console.print(
                    f"[bold red]⚠  {_missing_req} required dependencies missing.[/bold red] "
                    f"[dim]Run [D] Dependency Manager to install.[/dim]"
                )
            elif _missing_opt > 0 or _missing_key > 0:
                console.print(
                    f"[yellow]ℹ  {_missing_opt} optional tools · {_missing_key} API keys not configured.[/yellow] "
                    f"[dim]Run [D] for details.[/dim]"
                )
            else:
                console.print("[bold green]✓  All dependencies satisfied.[/bold green]")
            console.print()
        except Exception:
            pass

    while True:
        display_menu()
        choice = Prompt.ask(
            "[bold yellow]Select option[/bold yellow]",
            choices=(
                [str(i) for i in range(10)]
                + ["n", "N", "w", "W", "h", "H", "o", "O",
                   "e", "E", "s", "S", "c", "C", "t", "T",
                   "f", "F", "m", "M", "d", "D"]
            ),
            show_choices=False,
        )
        choice = choice.lower()

        if choice == "0":
            console.print("\n[bold blue]Goodbye. Stay safe out there.[/bold blue]\n")
            break

        handler = _HANDLERS.get(choice)
        if handler:
            try:
                handler()
            except KeyboardInterrupt:
                console.print("\n[dim]Interrupted — returning to menu.[/dim]")

        Prompt.ask(
            "\n[dim]Press Enter to return to the menu[/dim]",
            default="",
            show_default=False,
        )
        console.clear()
        print_banner()


if __name__ == "__main__":
    main()
