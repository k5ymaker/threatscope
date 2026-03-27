"""
dependency_menus.py — Interactive Rich menus for dependency checking and installation.

Provides a menu-driven interface for reviewing system dependencies, API key
status, and triggering auto-installation of missing components.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rich import box
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

from modules.utils import console
from modules.dependency_checker import (
    CURRENT_OS,
    DEPENDENCY_REGISTRY,
    API_KEY_URLS,
    get_install_command,
    run_all_checks,
    run_single_install,
)

REQUEST_TIMEOUT = 15


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _pause() -> None:
    """Wait for Enter before redrawing the menu."""
    Prompt.ask("\n[dim]Press Enter to return to the menu[/dim]", default="", show_default=False)


# ---------------------------------------------------------------------------
# Menu entry point
# ---------------------------------------------------------------------------

def show_dependency_menu() -> None:
    """Main dependency management menu loop."""
    checks: dict = {}

    # Run initial checks with spinner
    with Progress(SpinnerColumn(), TextColumn("[cyan]Scanning dependencies..."), transient=True, console=console) as progress:
        progress.add_task("scan")
        checks = run_all_checks()

    while True:
        _print_health_summary(checks)
        console.print("\n[bold cyan]Dependency Manager[/bold cyan]")
        console.print("  [white]1[/white]  Full dependency report")
        console.print("  [white]2[/white]  Install all missing (auto)")
        console.print("  [white]3[/white]  Install single dependency")
        console.print("  [white]4[/white]  Show manual install commands")
        console.print("  [white]5[/white]  API key registration URLs")
        console.print("  [white]6[/white]  Show missing required only")
        console.print("  [white]7[/white]  Show missing API keys")
        console.print("  [white]8[/white]  Re-scan dependencies")
        console.print("  [white]9[/white]  API key & tool status")
        console.print("  [white]0[/white]  Back\n")

        choice = Prompt.ask("[bold cyan]Select option[/bold cyan]", default="0").strip()

        if choice == "0":
            break
        elif choice == "1":
            handle_full_report(checks)
            _pause()
        elif choice == "2":
            handle_install_missing(checks)
            checks = _rescan()
            _pause()
        elif choice == "3":
            handle_install_single(checks)
            checks = _rescan()
        elif choice == "4":
            handle_show_commands(checks)
            _pause()
        elif choice == "5":
            _show_api_urls()
            _pause()
        elif choice == "6":
            _show_missing_required(checks)
            _pause()
        elif choice == "7":
            _show_missing_api_keys(checks)
            _pause()
        elif choice == "8":
            checks = _rescan()
            console.print("[bold green]✓  Re-scan complete.[/bold green]\n")
        elif choice == "9":
            handle_full_report(checks)
            try:
                import sys as _sys, os as _os
                _sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
                from config import display_api_status
                display_api_status()
            except Exception as exc:
                console.print(f"[bold red]Error loading API status:[/bold red] {exc}")
            _pause()
        else:
            console.print("[yellow]Invalid option.[/yellow]")


# ---------------------------------------------------------------------------
# Helper: rescan
# ---------------------------------------------------------------------------

def _rescan() -> dict:
    with Progress(SpinnerColumn(), TextColumn("[cyan]Re-scanning..."), transient=True, console=console) as progress:
        progress.add_task("scan")
        return run_all_checks()


# ---------------------------------------------------------------------------
# Health summary line
# ---------------------------------------------------------------------------

def _print_health_summary(checks: dict) -> None:
    summary = checks.get("summary", {})
    missing_req = summary.get("missing_required", 0)
    missing_opt = summary.get("missing_optional", 0)
    api_cfg     = summary.get("api_keys_configured", 0)
    api_miss    = summary.get("api_keys_missing", 0)
    installed   = summary.get("installed", 0)
    os_name     = checks.get("os", CURRENT_OS)
    py_ver      = checks.get("python_version", "?")

    if missing_req == 0:
        colour = "bold green"
        status = "All required deps installed"
    elif missing_req <= 2:
        colour = "bold yellow"
        status = f"{missing_req} required dep(s) missing"
    else:
        colour = "bold red"
        status = f"{missing_req} required deps missing"

    line = (
        f"[{colour}]{status}[/{colour}]  "
        f"[dim]| OS: {os_name} | Python {py_ver} | "
        f"Installed: {installed} | Optional missing: {missing_opt} | "
        f"API keys: {api_cfg} configured, {api_miss} missing[/dim]"
    )
    console.print(Panel(line, box=box.ROUNDED, border_style="cyan", padding=(0, 1)))


# ---------------------------------------------------------------------------
# Option 1: Full report
# ---------------------------------------------------------------------------

def handle_full_report(checks: dict) -> None:
    """Display all dependencies in categorised Rich Tables."""
    results = checks.get("results", [])

    # Split by type
    python_pkgs = [r for r in results if r["type"] == "python_pkg"]
    binaries    = [r for r in results if r["type"] == "binary"]
    api_keys    = [r for r in results if r["type"] == "api_key"]

    for section_name, items in [
        ("Python Packages", python_pkgs),
        ("System Binaries", binaries),
        ("API Keys",        api_keys),
    ]:
        table = Table(
            title=section_name,
            box=box.ROUNDED,
            header_style="bold cyan",
            show_lines=True,
            expand=False,
        )
        table.add_column("Name",        style="bold white", min_width=22)
        table.add_column("Status",      min_width=14, justify="center")
        table.add_column("Required By", min_width=22)
        table.add_column("Optional",    min_width=8,  justify="center")
        table.add_column("Description", min_width=36)

        for item in items:
            installed = item.get("installed", False)
            optional  = item.get("optional", False)

            if installed:
                status_str = "[bold green]INSTALLED[/bold green]"
            elif optional:
                status_str = "[yellow]MISSING[/yellow]"
            else:
                status_str = "[bold red]MISSING[/bold red]"

            opt_str      = "[dim]yes[/dim]" if optional else "[white]no[/white]"
            required_by  = ", ".join(item.get("required_by", []))
            description  = item.get("description", "")

            table.add_row(item["name"], status_str, required_by, opt_str, description)

        console.print(table)
        console.print()


# ---------------------------------------------------------------------------
# Option 2: Install all missing
# ---------------------------------------------------------------------------

def handle_install_missing(checks: dict) -> None:
    """Auto-install all missing non-optional dependencies."""
    missing = checks.get("missing_required", [])
    if not missing:
        console.print("[bold green]No missing required dependencies.[/bold green]")
        return

    console.print(f"\n[bold yellow]Found {len(missing)} missing required dep(s). Attempting install...[/bold yellow]\n")

    for item in missing:
        key = item.get("key", "")
        name = item.get("name", key)
        console.print(f"  [cyan]Installing:[/cyan] {name}")

        with Progress(SpinnerColumn(), TextColumn(f"  Running install for {name}..."), transient=True, console=console) as progress:
            progress.add_task("install")
            success, msg = run_single_install(key)

        if success:
            console.print(f"  [bold green]OK:[/bold green] {name} installed.\n")
        else:
            console.print(f"  [bold red]FAILED:[/bold red] {msg}\n")


# ---------------------------------------------------------------------------
# Option 3: Install single
# ---------------------------------------------------------------------------

def handle_install_single(checks: dict) -> None:
    """Let the user pick any installable dependency (Python pkg or binary) to install."""
    results  = checks.get("results", [])
    # Show ALL python packages and binaries — installed or not — so there is always a list
    eligible = [r for r in results if r["type"] in ("python_pkg", "binary")]

    if not eligible:
        console.print("[yellow]No installable dependencies found in registry.[/yellow]")
        return

    table = Table(
        title="Installable Dependencies",
        box=box.ROUNDED,
        header_style="bold cyan",
        show_lines=False,
    )
    table.add_column("#",        min_width=4,  justify="right")
    table.add_column("Name",     min_width=22, style="bold white")
    table.add_column("Type",     min_width=12)
    table.add_column("Status",   min_width=14, justify="center")
    table.add_column("Optional", min_width=8,  justify="center")
    table.add_column("Required By", min_width=20, style="dim")

    for idx, item in enumerate(eligible, 1):
        installed = item.get("installed", False)
        optional  = item.get("optional", False)
        status    = "[bold green]INSTALLED[/bold green]" if installed else (
                    "[yellow]MISSING[/yellow]" if optional else "[bold red]MISSING[/bold red]")
        opt_str   = "[dim]yes[/dim]" if optional else "[white]no[/white]"
        req_by    = ", ".join(item.get("required_by", []))
        table.add_row(str(idx), item["name"], item["type"], status, opt_str, req_by)

    console.print(table)
    raw = Prompt.ask(
        "[bold cyan]Enter number to install/reinstall (or 0 to cancel)[/bold cyan]",
        default="0",
    ).strip()

    try:
        num = int(raw)
    except ValueError:
        console.print("[yellow]Invalid input.[/yellow]")
        return

    if num == 0:
        return
    if not (1 <= num <= len(eligible)):
        console.print("[yellow]Number out of range.[/yellow]")
        return

    item = eligible[num - 1]
    key  = item.get("key", "")
    name = item.get("name", key)
    cmd  = get_install_command(key)

    if not cmd or cmd.startswith("See documentation"):
        console.print(f"[yellow]No install command available for {name}.[/yellow]")
        return

    console.print(f"\n  [cyan]Command:[/cyan] {cmd}")
    console.print(f"  [cyan]Installing:[/cyan] {name}")
    with Progress(SpinnerColumn(), TextColumn(f"  Running install for {name}..."), transient=True, console=console) as progress:
        progress.add_task("install")
        success, msg = run_single_install(key)

    if success:
        console.print(f"  [bold green]✓  {name} installed successfully.[/bold green]\n")
    else:
        console.print(f"  [bold red]✗  {name} install failed:[/bold red] {msg}\n")


# ---------------------------------------------------------------------------
# Option 4: Show manual install commands
# ---------------------------------------------------------------------------

def handle_show_commands(checks: dict) -> None:
    """Print OS-appropriate install commands for all dependencies."""
    results = checks.get("results", [])
    non_api = [r for r in results if r["type"] != "api_key"]

    table = Table(
        title=f"Install Commands ({CURRENT_OS})",
        box=box.ROUNDED,
        header_style="bold cyan",
        show_lines=True,
        expand=False,
    )
    table.add_column("Name",    style="bold white", min_width=22)
    table.add_column("Status",  min_width=12, justify="center")
    table.add_column("Command", min_width=52)

    for item in non_api:
        key       = item.get("key", "")
        cmd       = get_install_command(key)
        installed = item.get("installed", False)
        status    = "[green]OK[/green]" if installed else "[red]MISSING[/red]"
        table.add_row(item["name"], status, cmd)

    console.print(table)
    console.print()


# ---------------------------------------------------------------------------
# Option 5: API key URLs
# ---------------------------------------------------------------------------

def _show_api_urls() -> None:
    table = Table(
        title="API Key Registration URLs",
        box=box.ROUNDED,
        header_style="bold cyan",
        show_lines=True,
    )
    table.add_column("Service", style="bold white", min_width=24)
    table.add_column("Registration URL", min_width=52)

    for service, url in API_KEY_URLS.items():
        table.add_row(service, f"[blue]{url}[/blue]")

    console.print(table)
    console.print()


# ---------------------------------------------------------------------------
# Option 6: Missing required only
# ---------------------------------------------------------------------------

def _show_missing_required(checks: dict) -> None:
    missing = checks.get("missing_required", [])
    if not missing:
        console.print("[bold green]No missing required dependencies.[/bold green]\n")
        return

    table = Table(title="Missing Required Dependencies", box=box.ROUNDED, header_style="bold cyan", show_lines=True)
    table.add_column("Name",        style="bold red",  min_width=22)
    table.add_column("Type",        min_width=12)
    table.add_column("Required By", min_width=28)
    table.add_column("Install Command", min_width=44)

    for item in missing:
        cmd = get_install_command(item.get("key", ""))
        table.add_row(item["name"], item["type"], ", ".join(item.get("required_by", [])), cmd)

    console.print(table)
    console.print()


# ---------------------------------------------------------------------------
# Option 7: Missing API keys
# ---------------------------------------------------------------------------

def _show_missing_api_keys(checks: dict) -> None:
    missing = checks.get("missing_api_keys", [])
    if not missing:
        console.print("[bold green]All API keys are configured.[/bold green]\n")
        return

    table = Table(title="Missing API Keys", box=box.ROUNDED, header_style="bold cyan", show_lines=True)
    table.add_column("Service",     style="bold yellow", min_width=24)
    table.add_column("Required By", min_width=24)
    table.add_column("Optional",    min_width=8, justify="center")
    table.add_column("Register URL", min_width=48)

    for item in missing:
        key      = item.get("api_key_cfg", item.get("key", ""))
        url      = API_KEY_URLS.get(key, "—")
        opt      = "[dim]yes[/dim]" if item.get("optional") else "[bold red]no[/bold red]"
        req_by   = ", ".join(item.get("required_by", []))
        table.add_row(item["name"], req_by, opt, f"[blue]{url}[/blue]")

    console.print(table)
    console.print()
