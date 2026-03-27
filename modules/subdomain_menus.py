"""
subdomain_menus.py — Interactive Rich menus for subdomain enumeration and ASN intelligence.

Wraps all slow network calls with _animated_task() for a live spinner UI,
and offers CSV/TXT/JSON export after every enumeration result.
"""

from __future__ import annotations

import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rich import box
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

from modules.utils import console, print_result_table, print_section_header
from modules.subdomain_recon import (
    _animated_task,
    asn_lookup_bgpview,
    enumerate_subdomains_crtsh,
    enumerate_subdomains_hackertarget,
    export_subdomains,
    ripestat_lookup,
    scan_sublist3r,
    securitytrails_lookup,
    SUBLIST3R_AVAILABLE,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _pause() -> None:
    """Wait for Enter before redrawing the menu."""
    Prompt.ask("\n[dim]Press Enter to return to the menu[/dim]", default="", show_default=False)


def _display_result(result: dict, title: str) -> None:
    """Display a module result — skipped / error / table."""
    if result.get("skipped"):
        reason = result.get("details", {}).get("reason", "No API key")
        console.print(f"  [dim]○ {title}: SKIPPED — {reason}[/dim]\n")
        return
    if result.get("error"):
        err = result.get("details", {}).get("Error", "Unknown error")
        console.print(f"  [bold red]✗ {title}: ERROR — {err}[/bold red]\n")
        return
    print_result_table(result, title)


# ---------------------------------------------------------------------------
# Export prompt
# ---------------------------------------------------------------------------

def prompt_export(
    domain: str,
    subdomains: list,
    source: str,
    extra_data: dict | None = None,
) -> None:
    """
    Ask the user to export a subdomain list to CSV, TXT, or JSON.

    Silently returns if subdomains is empty.
    """
    if not subdomains:
        return

    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    table.add_column("Key", style="bold white", min_width=4)
    table.add_column("Format")
    table.add_row("[bold cyan]1[/bold cyan]", "CSV")
    table.add_row("[bold cyan]2[/bold cyan]", "TXT")
    table.add_row("[bold cyan]3[/bold cyan]", "JSON")
    table.add_row("[bold cyan]0[/bold cyan]", "[dim]Skip[/dim]")

    console.print(f"\n[bold cyan]Export {len(subdomains)} subdomain(s)?[/bold cyan]")
    console.print(table)

    choice = Prompt.ask("[bold cyan]Select format[/bold cyan]", default="0").strip()
    fmt_map = {"1": "csv", "2": "txt", "3": "json"}
    if choice not in fmt_map:
        return

    fmt  = fmt_map[choice]
    path = export_subdomains(domain, subdomains, source, fmt, extra_data)

    if path.startswith("Export failed"):
        console.print(f"[bold red]{path}[/bold red]\n")
    else:
        console.print(
            Panel(
                f"[bold green]✓  Exported {len(subdomains)} subdomains ({fmt.upper()})[/bold green]\n"
                f"[dim]{path}[/dim]",
                box=box.ROUNDED,
                border_style="green",
                padding=(0, 1),
            )
        )


# ---------------------------------------------------------------------------
# Sublist3r sub-menu
# ---------------------------------------------------------------------------

def show_sublist3r_menu() -> None:
    """Sub-menu for Sublist3r enumeration modes."""
    if not SUBLIST3R_AVAILABLE:
        console.print(
            Panel(
                "[bold red]Sublist3r is not installed.[/bold red]\n\n"
                "[dim]Install with one of:\n"
                "  pip install sublist3r\n"
                "  sudo apt install sublist3r  (Kali/Debian/Ubuntu)[/dim]",
                title="[bold red]Not Available[/bold red]",
                box=box.ROUNDED,
                border_style="red",
                padding=(0, 1),
            )
        )
        _pause()
        return

    while True:
        console.print("\n[bold cyan]Sublist3r Enumeration[/bold cyan]")
        console.print("  [white]1[/white]  Quick scan     (10 threads, no brute force)")
        console.print("  [white]2[/white]  Standard scan  (20 threads, no brute force)")
        console.print("  [white]3[/white]  Full scan + Brute Force  [bold red](requires authorisation)[/bold red]")
        console.print("  [white]0[/white]  Back\n")

        choice = Prompt.ask("[bold cyan]Select option[/bold cyan]", default="0").strip()

        if choice == "0":
            break

        elif choice in ("1", "2", "3"):
            domain = Prompt.ask("[bold cyan]Enter domain[/bold cyan]").strip()
            if not domain:
                console.print("[yellow]Invalid input.[/yellow]")
                continue

            threads   = 10 if choice == "1" else 20
            use_brute = False

            if choice == "3":
                console.print(
                    Panel(
                        "[bold red]WARNING: Brute-force mode sends a very large number of DNS requests.\n"
                        "Only run against domains you own or have explicit written permission to test.[/bold red]",
                        box=box.ROUNDED,
                        border_style="red",
                        padding=(0, 1),
                    )
                )
                confirm = Prompt.ask(
                    "[bold red]Type YES to confirm brute-force scan[/bold red]",
                    default="no",
                ).strip()
                if confirm != "YES":
                    console.print("[yellow]Brute-force scan cancelled.[/yellow]")
                    continue
                use_brute = True

            brute_tag = " + brute" if use_brute else ""
            desc = f"Sublist3r scan for {domain} ({threads} threads{brute_tag})"
            result = _animated_task(desc, scan_sublist3r, domain, threads, use_brute)
            _display_result(result, f"Sublist3r: {domain}")

            subdomains = result.get("subdomains", [])
            if subdomains:
                prompt_export(domain, subdomains, "sublist3r")

            _pause()

        else:
            console.print("[yellow]Invalid option.[/yellow]")


# ---------------------------------------------------------------------------
# Main subdomain menu
# ---------------------------------------------------------------------------

def handle_subdomain_menu() -> None:
    """Interactive subdomain/ASN intelligence menu."""
    while True:
        console.print("\n[bold cyan]Subdomain & ASN Intelligence[/bold cyan]")
        console.print("  [white]1[/white]  Enumerate subdomains — crt.sh")
        console.print("  [white]2[/white]  Enumerate subdomains — HackerTarget")
        console.print("  [white]3[/white]  ASN / IP lookup — BGPView")
        console.print("  [white]4[/white]  IP / Prefix lookup — RIPEstat")
        console.print("  [white]5[/white]  Subdomain lookup — SecurityTrails")
        console.print("  [white]6[/white]  Sublist3r Enumeration")
        console.print("  [white]7[/white]  Full subdomain report (crt.sh + HackerTarget + SecurityTrails + Sublist3r)")
        console.print("  [white]0[/white]  Back\n")

        choice = Prompt.ask("[bold cyan]Select option[/bold cyan]", default="0").strip()

        if choice == "0":
            break

        elif choice == "1":
            domain = Prompt.ask("[bold cyan]Enter domain[/bold cyan]").strip()
            if not domain:
                console.print("[yellow]Invalid input.[/yellow]")
                continue
            result = _animated_task(f"Querying crt.sh for {domain}", enumerate_subdomains_crtsh, domain)
            _display_result(result, f"crt.sh: {domain}")
            if result.get("subdomains"):
                prompt_export(domain, result["subdomains"], "crtsh")
            _pause()

        elif choice == "2":
            domain = Prompt.ask("[bold cyan]Enter domain[/bold cyan]").strip()
            if not domain:
                console.print("[yellow]Invalid input.[/yellow]")
                continue
            result = _animated_task(f"Querying HackerTarget for {domain}", enumerate_subdomains_hackertarget, domain)
            _display_result(result, f"HackerTarget: {domain}")
            if result.get("subdomains"):
                prompt_export(domain, result["subdomains"], "hackertarget")
            _pause()

        elif choice == "3":
            target = Prompt.ask("[bold cyan]Enter IP or ASN (e.g. 8.8.8.8 or AS15169)[/bold cyan]").strip()
            if not target:
                console.print("[yellow]Invalid input.[/yellow]")
                continue
            result = _animated_task(f"BGPView lookup: {target}", asn_lookup_bgpview, target)
            _display_result(result, f"BGPView: {target}")
            _pause()

        elif choice == "4":
            target = Prompt.ask("[bold cyan]Enter IP or prefix (e.g. 8.8.8.0/24)[/bold cyan]").strip()
            if not target:
                console.print("[yellow]Invalid input.[/yellow]")
                continue
            result = _animated_task(f"RIPEstat lookup: {target}", ripestat_lookup, target)
            _display_result(result, f"RIPEstat: {target}")
            _pause()

        elif choice == "5":
            domain = Prompt.ask("[bold cyan]Enter domain[/bold cyan]").strip()
            if not domain:
                console.print("[yellow]Invalid input.[/yellow]")
                continue
            result = _animated_task(f"Querying SecurityTrails for {domain}", securitytrails_lookup, domain)
            _display_result(result, f"SecurityTrails: {domain}")
            if result.get("subdomains"):
                prompt_export(domain, result["subdomains"], "securitytrails")
            _pause()

        elif choice == "6":
            show_sublist3r_menu()

        elif choice == "7":
            domain = Prompt.ask("[bold cyan]Enter domain[/bold cyan]").strip()
            if not domain:
                console.print("[yellow]Invalid input.[/yellow]")
                continue

            def _run_full_report():
                all_subs: set[str] = set()
                report: dict = {}
                # Run crt.sh, HackerTarget, SecurityTrails concurrently
                with ThreadPoolExecutor(max_workers=3) as executor:
                    futures = {
                        executor.submit(enumerate_subdomains_crtsh,       domain): "crt.sh",
                        executor.submit(enumerate_subdomains_hackertarget, domain): "HackerTarget",
                        executor.submit(securitytrails_lookup,             domain): "SecurityTrails",
                    }
                    for future in as_completed(futures):
                        name = futures[future]
                        try:
                            res = future.result()
                            report[name] = res
                            if not res.get("skipped") and not res.get("error"):
                                all_subs.update(res.get("subdomains", []))
                        except Exception as exc:
                            report[name] = {
                                "source": name, "skipped": False,
                                "error": True, "flagged": False,
                                "details": {"Error": str(exc)},
                            }
                # Run Sublist3r sequentially (manages its own subprocess)
                if SUBLIST3R_AVAILABLE:
                    try:
                        s3r = scan_sublist3r(domain, threads=10, use_brute=False)
                        report["Sublist3r"] = s3r
                        if not s3r.get("skipped") and not s3r.get("error"):
                            all_subs.update(s3r.get("subdomains", []))
                    except Exception as exc:
                        report["Sublist3r"] = {
                            "source": "Sublist3r", "skipped": False,
                            "error": True, "flagged": False,
                            "details": {"Error": str(exc)},
                        }
                return report, sorted(all_subs)

            report, merged = _animated_task(
                f"Full subdomain report for {domain}",
                _run_full_report,
            )

            print_section_header(f"Subdomain Report: {domain}")
            for name, res in report.items():
                _display_result(res, name)

            console.print(
                f"\n[bold green]Total unique subdomains across all sources:[/bold green] {len(merged)}\n"
            )

            if merged:
                prompt_export(domain, merged, "full_report")

            _pause()

        else:
            console.print("[yellow]Invalid option.[/yellow]")
