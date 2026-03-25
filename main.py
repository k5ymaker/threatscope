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

from config import display_api_status  # noqa: E402
from modules import dns_tools, ip_intel, url_intel, utils  # noqa: E402

console = Console()


# ---------------------------------------------------------------------------
# Banner & Menu
# ---------------------------------------------------------------------------

_BANNER = r"""
  _____ _                    _    ____
 |_   _| |__  _ __ ___  __ _| |_ / ___|  ___ ___  _ __   ___
   | | | '_ \| '__/ _ \/ _` | __\___ \ / __/ _ \| '_ \ / _ \
   | | | | | | | |  __/ (_| | |_ ___) | (_| (_) | |_) |  __/
   |_| |_| |_|_|  \___|\__,_|\__|____/ \___\___/| .__/ \___|
                                                  |_|
"""

_TAGLINE = "Terminal-based Threat Intelligence · Investigate URLs, IPs & Domains"

_MENU_ITEMS = [
    ("1", "URL Reputation Check          (VirusTotal · PhishTank · GSB · APIVoid)"),
    ("2", "URL Scan & Analysis           (URLScan.io live browser scan)"),
    ("3", "IP Reputation / Blacklist     (AbuseIPDB · VirusTotal · DNSBL)"),
    ("4", "IP Geolocation & Info         (IPInfo · AlienVault OTX)"),
    ("5", "IP Shodan Lookup              (open ports, banners, CVEs)"),
    ("6", "DNS Lookup                    (A · AAAA · MX · TXT · NS · SOA)"),
    ("7", "Reverse DNS Lookup            (PTR record)"),
    ("8", "WHOIS Information             (registrar · dates · nameservers)"),
    ("9", "Full IOC Report               (all checks concurrently + export)"),
    ("0", "Exit"),
]


def print_banner() -> None:
    """Print the ThreatScope ASCII banner."""
    console.print(f"[bold cyan]{_BANNER}[/bold cyan]")
    console.print(
        Panel(
            Text(_TAGLINE, style="italic dim", justify="center"),
            border_style="cyan",
            box=box.ROUNDED,
            padding=(0, 4),
        )
    )
    console.print()


def display_menu() -> None:
    """Render the main interactive menu using a rich Table."""
    table = Table(
        title="THREATSCOPE MENU",
        box=box.ROUNDED,
        show_header=False,
        border_style="blue",
        title_style="bold white",
        expand=False,
        padding=(0, 1),
    )
    table.add_column("Key",  style="bold yellow", no_wrap=True, min_width=5)
    table.add_column("Action", style="white", min_width=60)

    for key, action in _MENU_ITEMS:
        table.add_row(f"[{key}]", action)

    console.print(table)
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
}


def main() -> None:
    """Application entry point — display banner, show API status, then loop."""
    print_banner()
    display_api_status()

    while True:
        display_menu()
        choice = Prompt.ask(
            "[bold yellow]Select option[/bold yellow]",
            choices=[str(i) for i in range(10)],
            show_choices=False,
        )

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
