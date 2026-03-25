"""
web_fingerprint_menus.py — Web Application Fingerprinting menus for ThreatScope.

Provides the full Web Fingerprint sub-menu tree:
  show_web_fingerprint_menu()
    ├─ [1] WhatWeb Scan            (CMS / server / framework detection)
    ├─ [2] WhatWeb Advanced Scan   (cookie, proxy, UA, plugin options)
    ├─ [3] Tech Stack Fingerprint  (Wappalyzer)
    ├─ [4] WAF Detection           (WafW00f)
    └─ [5] Full Fingerprint Scan   (all three tools, concurrent)

Uses the shared console from modules/utils.py and follows the same rich
UI patterns as nmap_menus.py (Panels, Tables, Prompts, Spinners).
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime
from typing import Optional

from rich import box
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Shared console — never create a new Console() instance
from modules.utils import console, print_section_header, print_skipped  # noqa: E402
from modules.web_fingerprint import (  # noqa: E402
    INSTALL_HINTS,
    TOOL_STATUS,
    WAPPALYZER_BIN,
    WAPPALYZER_LIB,
    run_full_fingerprint,
    run_wafw00f,
    run_wappalyzer,
    run_whatweb,
    run_whatweb_custom,
)

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_UA_PRESETS = {
    "1": None,  # WhatWeb default
    "2": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "3": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
}

_CATEGORY_ORDER = [
    "CMS", "Web Server", "Framework", "Language", "CDN",
    "JS Library", "Analytics", "Security", "Email", "Other",
]

_WAPPALYZER_CATEGORY_ORDER = [
    "CMS", "Web servers", "JavaScript frameworks", "Programming languages",
    "Databases", "Security", "Analytics", "Tag managers", "CDN",
    "Ecommerce", "Font scripts", "Other",
]


def _prompt_target(prompt_text: str = "Enter target URL or domain") -> str:
    """Prompt for a scan target and return it. Accepts URLs, domains, and IPs."""
    return Prompt.ask(
        f"[bold]{prompt_text}[/bold] [dim](e.g. https://example.com or example.com)[/dim]"
    ).strip()


def _press_enter_to_continue() -> None:
    Prompt.ask(
        "\n[dim]Press Enter to return to the menu[/dim]",
        default="", show_default=False,
    )


def _run_with_spinner(fn, *args, label: str = "Scanning...") -> dict:
    """Execute a scan function with an animated spinner while it runs."""
    console.print(f"\n[yellow]⏳ Scanning... this may take a moment.[/yellow]")
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task(label, total=None)
        return fn(*args)


def _show_install_panel(tool_key: str) -> None:
    """Show an installation instructions panel for a missing tool."""
    hint = INSTALL_HINTS.get(tool_key, "")
    console.print(
        Panel(
            f"[bold red]○ {tool_key.capitalize()} is not installed[/bold red]\n\n"
            f"[white]{hint}[/white]\n\n"
            "[dim]After installing, restart ThreatScope for the tool to be detected.[/dim]",
            title=f"[bold red]Tool Unavailable — {tool_key.capitalize()}[/bold red]",
            border_style="red",
            padding=(1, 3),
        )
    )


def _safe_export_json(data: dict, target: str) -> None:
    """Save result dict to a timestamped JSON file in reports/."""
    try:
        _ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        reports_dir = os.path.join(_ROOT, "reports")
        os.makedirs(reports_dir, exist_ok=True)

        safe_target = re.sub(r"[^a-zA-Z0-9_\-]", "_", target)[:50]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = os.path.join(reports_dir, f"{timestamp}_fingerprint_{safe_target}.json")

        def _sanitise(obj):
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
    except Exception as exc:  # noqa: BLE001
        console.print(f"[bold red]Export failed: {exc}[/bold red]")


import re  # noqa: E402 (needed after function def)


# ===========================================================================
# Tool Status Panel
# ===========================================================================

def show_tool_status_panel() -> None:
    """
    Display a rich Table showing the installation status of all three tools.
    Called at the top of show_web_fingerprint_menu() on every loop iteration.
    """
    table = Table(
        title="Web Fingerprinting Tools — Status",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
        expand=False,
        padding=(0, 1),
    )
    table.add_column("Tool",       style="bold white",  min_width=14)
    table.add_column("Status",     min_width=12)
    table.add_column("Path / Note", style="dim",        min_width=40)

    tool_display = {
        "whatweb":    "WhatWeb",
        "wappalyzer": "Wappalyzer",
        "wafw00f":    "WafW00f",
    }

    missing: list[str] = []
    for key, label in tool_display.items():
        info = TOOL_STATUS[key]
        if info["available"]:
            status_markup = "[bold green]● READY[/bold green]"
            path_str = str(info["path"])
        else:
            status_markup = "[bold red]○ MISSING[/bold red]"
            path_str = f"[red]{INSTALL_HINTS.get(key, 'not found')}[/red]"
            missing.append(key)
        table.add_row(label, status_markup, path_str)

    console.print(table)

    if missing:
        console.print(
            "[dim]Missing tools will show as UNAVAILABLE in the menu. "
            "All other tools will run normally.[/dim]\n"
        )
    else:
        console.print("[dim]All tools are ready.[/dim]\n")


# ===========================================================================
# Top-level sub-menu
# ===========================================================================

def show_web_fingerprint_menu() -> None:
    """
    Top-level Web Fingerprint sub-menu. Called from main.py when user selects [W].
    Calls show_tool_status_panel() on each iteration, then shows the menu.
    Loops until the user selects 0 (Back to Main Menu).
    """
    while True:
        console.print()
        show_tool_status_panel()

        table = Table(
            title="WEB FINGERPRINT MENU",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold cyan",
            expand=False,
            padding=(0, 1),
        )
        table.add_column("Key",         style="bold yellow", no_wrap=True, min_width=5)
        table.add_column("Option",      style="white",       min_width=26)
        table.add_column("Tool(s)",     style="cyan",        min_width=20)
        table.add_column("Description", style="dim",         min_width=40)

        rows = [
            ("1", "WhatWeb Scan",           "WhatWeb",        "CMS, server, framework detection"),
            ("2", "WhatWeb Advanced Scan",  "WhatWeb",        "Cookie / proxy / UA / plugins"),
            ("3", "Tech Stack Fingerprint", "Wappalyzer",     "Full technology stack by category"),
            ("4", "WAF Detection",          "WafW00f",        "Identify Web Application Firewall"),
            ("5", "Full Fingerprint Scan",  "All 3 tools",    "Run all tools concurrently"),
        ]
        tool_map = {
            "1": "whatweb", "2": "whatweb",
            "3": "wappalyzer",
            "4": "wafw00f",
            "5": None,  # Full scan uses all
        }

        for key, option, tools, desc in rows:
            tkey = tool_map[key]
            unavailable = (
                tkey is not None and not TOOL_STATUS[tkey]["available"]
            ) or (
                tkey is None and not any(TOOL_STATUS[k]["available"] for k in TOOL_STATUS)
            )
            if unavailable:
                table.add_row(
                    f"[dim]{key}[/dim]",
                    f"[dim red]{option}  [UNAVAILABLE][/dim red]",
                    f"[dim]{tools}[/dim]",
                    f"[dim]{desc}[/dim]",
                )
            else:
                table.add_row(f"[{key}]", option, tools, desc)

        table.add_section()
        table.add_row("[0]", "[dim]Back to Main Menu[/dim]", "", "")
        console.print(table)
        console.print()

        choice = Prompt.ask(
            "[bold yellow]Select option[/bold yellow]",
            choices=["0", "1", "2", "3", "4", "5"],
            show_choices=False,
        )

        if choice == "0":
            break

        tkey = tool_map.get(choice)

        # Check availability for single-tool options
        if tkey and not TOOL_STATUS[tkey]["available"]:
            _show_install_panel(tkey)
            _press_enter_to_continue()
            continue

        # Check for full scan with zero tools available
        if choice == "5" and not any(TOOL_STATUS[k]["available"] for k in TOOL_STATUS):
            console.print(
                "[bold red]No fingerprinting tools are installed. "
                "Install at least one tool to run a scan.[/bold red]\n"
            )
            for k in TOOL_STATUS:
                _show_install_panel(k)
            _press_enter_to_continue()
            continue

        if choice == "1":
            handle_whatweb_scan()
        elif choice == "2":
            handle_whatweb_advanced_scan()
        elif choice == "3":
            handle_wappalyzer_scan()
        elif choice == "4":
            handle_wafw00f_scan()
        elif choice == "5":
            handle_full_fingerprint_scan()


# ===========================================================================
# Handler 1 — WhatWeb Scan
# ===========================================================================

def handle_whatweb_scan() -> None:
    """
    Prompt for target and aggression level, run WhatWeb, display results.
    Warns the user before running aggression levels 3 and 4.
    """
    target = _prompt_target()
    if not target:
        console.print("[bold red]Target cannot be empty.[/bold red]")
        return

    console.print()
    agg_table = Table(
        title="WhatWeb Aggression Level",
        box=box.ROUNDED,
        show_header=False,
        expand=False,
        padding=(0, 1),
    )
    agg_table.add_column("Key", style="bold yellow", min_width=4)
    agg_table.add_column("Level", style="white", min_width=50)
    agg_table.add_row("[1]", "Level 1 — Passive        (stealthy, single request)  [dim][recommended][/dim]")
    agg_table.add_row("[2]", "Level 2 — Passive+       (no redirect following)")
    agg_table.add_row("[3]", "Level 3 — Aggressive     (multiple requests per URL)")
    agg_table.add_row("[4]", "Level 4 — Heavy          (floods with requests)")
    console.print(agg_table)
    console.print()

    agg_choice = Prompt.ask(
        "[bold]Select aggression level[/bold] [dim](default: 1)[/dim]",
        choices=["1", "2", "3", "4"],
        default="1",
    )
    aggression = int(agg_choice)

    if aggression >= 3:
        console.print(
            f"\n[yellow]⚠  Aggression level {aggression} sends multiple requests and may "
            "trigger IDS/WAF alerts or rate limiting. Only use on systems you are "
            "authorised to test.[/yellow]\n"
        )
        confirm = Prompt.ask(
            "[bold yellow]Continue?[/bold yellow]", choices=["y", "n"], default="n"
        )
        if confirm.lower() != "y":
            console.print("[dim]Scan cancelled.[/dim]")
            return

    print_section_header(f"WhatWeb Scan — {target}  (aggression: {aggression})")
    result = _run_with_spinner(
        run_whatweb, target, aggression,
        label=f"Running WhatWeb (level {aggression}) against {target}...",
    )
    print_whatweb_result(result)
    _press_enter_to_continue()


# ===========================================================================
# Handler 2 — WhatWeb Advanced Scan
# ===========================================================================

def handle_whatweb_advanced_scan() -> None:
    """
    Collect advanced WhatWeb options via a form Panel, then run the scan.
    Supports custom UA presets, cookie strings, Burp proxy, and SSL bypass.
    """
    console.print(
        Panel(
            "[bold cyan]WhatWeb Advanced Options[/bold cyan]\n"
            "[dim]Complete each field or press Enter to use the default.[/dim]",
            border_style="cyan",
            padding=(0, 2),
        )
    )
    console.print()

    # Target
    target = _prompt_target()
    if not target:
        console.print("[bold red]Target cannot be empty.[/bold red]")
        return

    # Aggression
    agg_raw = Prompt.ask(
        "[bold]Aggression level[/bold] [dim][1-4, default: 1][/dim]",
        default="1",
    ).strip()
    try:
        aggression = max(1, min(4, int(agg_raw)))
    except ValueError:
        aggression = 1

    # User-Agent
    console.print(
        "\n[bold]User-Agent preset:[/bold]\n"
        "  [1] WhatWeb default\n"
        "  [2] Googlebot\n"
        "  [3] Mozilla Firefox 120\n"
        "  [4] Custom — enter manually\n"
    )
    ua_choice = Prompt.ask("[bold]Select UA[/bold]", choices=["1","2","3","4"], default="1")
    if ua_choice in _UA_PRESETS:
        user_agent = _UA_PRESETS[ua_choice]
    else:
        user_agent = Prompt.ask("[bold]Enter custom User-Agent[/bold]").strip() or None

    # Cookie
    cookies = Prompt.ask(
        "[bold]Cookie string[/bold] [dim](optional — e.g. PHPSESSID=abc123)[/dim]",
        default="",
    ).strip() or None

    # Proxy
    proxy = Prompt.ask(
        "[bold]Proxy[/bold] [dim](optional — e.g. 127.0.0.1:8080 for Burp Suite)[/dim]",
        default="",
    ).strip() or None

    # SSL
    ssl_raw = Prompt.ask(
        "[bold]Skip SSL verification?[/bold] [dim][y/N][/dim]",
        choices=["y","n","Y","N",""],
        default="n",
    ).lower()
    no_ssl_verify = ssl_raw == "y"

    # Auth/proxy note
    if cookies or proxy:
        console.print(
            "\n[cyan]ℹ  Cookie/proxy mode active — ensure you have authorisation "
            "for authenticated scanning.[/cyan]"
        )

    if aggression >= 3:
        console.print(
            f"\n[yellow]⚠  Aggression level {aggression} may trigger "
            "IDS/WAF alerts. Only use on authorised systems.[/yellow]"
        )
        confirm = Prompt.ask("[bold yellow]Continue?[/bold yellow]", choices=["y","n"], default="n")
        if confirm.lower() != "y":
            console.print("[dim]Scan cancelled.[/dim]")
            return

    # Summary before running
    console.print(
        Panel(
            f"[bold]Target:[/bold]     {target}\n"
            f"[bold]Aggression:[/bold] {aggression}\n"
            f"[bold]User-Agent:[/bold] {user_agent or 'WhatWeb default'}\n"
            f"[bold]Cookies:[/bold]    {'[set]' if cookies else 'None'}\n"
            f"[bold]Proxy:[/bold]      {proxy or 'None'}\n"
            f"[bold]SSL verify:[/bold] {'Skip' if no_ssl_verify else 'Enabled'}",
            title="[bold cyan]Scan Configuration[/bold cyan]",
            border_style="cyan",
            padding=(0, 2),
        )
    )
    go = Prompt.ask("[bold yellow]Proceed?[/bold yellow]", choices=["y","n"], default="y")
    if go.lower() != "y":
        console.print("[dim]Scan cancelled.[/dim]")
        return

    print_section_header(f"WhatWeb Advanced Scan — {target}")
    result = _run_with_spinner(
        run_whatweb_custom, target, aggression,
        user_agent or "", None, cookies, proxy, no_ssl_verify,
        label=f"Running WhatWeb (advanced) against {target}...",
    )
    print_whatweb_result(result)
    _press_enter_to_continue()


# ===========================================================================
# Handler 3 — Wappalyzer Fingerprint
# ===========================================================================

def handle_wappalyzer_scan() -> None:
    """
    Prompt for target, optionally select detection method, run Wappalyzer.
    """
    target = _prompt_target()
    if not target:
        console.print("[bold red]Target cannot be empty.[/bold red]")
        return

    console.print(
        "\n[cyan]ℹ  Wappalyzer works by fetching the target page and matching patterns "
        "in HTTP headers, HTML source, JavaScript, and cookies. "
        "No active probing or exploitation.[/cyan]\n"
    )

    print_section_header(f"Tech Stack Fingerprint — {target}")
    result = _run_with_spinner(
        run_wappalyzer, target,
        label=f"Analysing tech stack for {target}...",
    )
    print_wappalyzer_result(result)
    _press_enter_to_continue()


# ===========================================================================
# Handler 4 — WAF Detection
# ===========================================================================

def handle_wafw00f_scan() -> None:
    """
    Prompt for target and scan mode, run WafW00f, display results.
    """
    target = _prompt_target()
    if not target:
        console.print("[bold red]Target cannot be empty.[/bold red]")
        return

    console.print()
    mode_table = Table(
        title="WAF Scan Mode",
        box=box.ROUNDED,
        show_header=False,
        expand=False,
        padding=(0, 1),
    )
    mode_table.add_column("Key", style="bold yellow", min_width=4)
    mode_table.add_column("Mode", style="white", min_width=56)
    mode_table.add_row("[1]", "Standard scan     — stop at first WAF detected  [dim](fastest)[/dim]")
    mode_table.add_row("[2]", "Find all WAFs     — continue scanning after first match  [dim](-a)[/dim]")
    mode_table.add_row("[3]", "Test all WAF DB   — test against all fingerprints  [dim](-t, slowest)[/dim]")
    console.print(mode_table)
    console.print()

    mode = Prompt.ask(
        "[bold]Select mode[/bold] [dim](default: 1)[/dim]",
        choices=["1", "2", "3"],
        default="1",
    )

    find_all     = mode == "2"
    test_all_waf = mode == "3"

    if test_all_waf:
        console.print(
            "\n[yellow]⚠  Testing all fingerprints sends many probes and may take "
            "several minutes. Suitable for thorough authorised assessments.[/yellow]\n"
        )

    print_section_header(f"WAF Detection — {target}")
    result = _run_with_spinner(
        run_wafw00f, target, find_all, test_all_waf,
        label=f"Detecting WAF on {target}...",
    )
    print_wafw00f_result(result)

    if not result.get("error") and not result.get("skipped"):
        if not result.get("details", {}).get("waf_detected", True):
            console.print(
                Panel(
                    f"No WAF was detected on [bold]{target}[/bold]. This means:\n\n"
                    "  • Attack payloads reach the application directly\n"
                    "  • No bot or rate-limit protection may be in place\n"
                    "  • Standard exploitation techniques are more likely to succeed\n\n"
                    "[dim]Only relevant for authorised penetration testing engagements.[/dim]",
                    title="[bold yellow]⚠  Security Note[/bold yellow]",
                    border_style="yellow",
                    padding=(1, 3),
                )
            )

    _press_enter_to_continue()


# ===========================================================================
# Handler 5 — Full Fingerprint Scan
# ===========================================================================

def handle_full_fingerprint_scan() -> None:
    """
    Prompt for target, show which tools will run, run all three concurrently,
    display the merged report, and offer JSON export.
    """
    target = _prompt_target()
    if not target:
        console.print("[bold red]Target cannot be empty.[/bold red]")
        return

    # Show which tools will run
    lines: list[str] = []
    for key, label in [("whatweb", "WhatWeb"), ("wappalyzer", "Wappalyzer"), ("wafw00f", "WafW00f")]:
        if TOOL_STATUS[key]["available"]:
            extra = "  (aggression: 1)" if key == "whatweb" else ""
            lines.append(f"[green]✓ {label}{extra}[/green]")
        else:
            lines.append(f"[red]✗ {label}  [SKIPPED — not installed][/red]")

    console.print(
        Panel(
            "\n".join(lines),
            title="[bold cyan]Full Fingerprint Scan — Tools[/bold cyan]",
            border_style="cyan",
            padding=(0, 3),
        )
    )
    console.print()

    confirm = Prompt.ask("[bold yellow]Proceed?[/bold yellow]", choices=["y","n"], default="y")
    if confirm.lower() != "y":
        return

    print_section_header(f"Full Fingerprint Scan — {target}")
    console.print("[yellow]⏳ Running all tools concurrently — please wait...[/yellow]\n")

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        t1 = progress.add_task("WhatWeb...",    total=None)
        t2 = progress.add_task("Wappalyzer...", total=None)
        t3 = progress.add_task("WafW00f...",    total=None)
        result = run_full_fingerprint(target)
        progress.update(t1, completed=1, total=1)
        progress.update(t2, completed=1, total=1)
        progress.update(t3, completed=1, total=1)

    print_full_fingerprint_result(result)

    # Export offer
    console.print()
    export_choice = Prompt.ask(
        "[yellow]Export full fingerprint report to JSON?[/yellow]",
        choices=["y", "n"],
        default="n",
    )
    if export_choice.lower() == "y":
        _safe_export_json(result, target)

    _press_enter_to_continue()


# ===========================================================================
# Result rendering functions
# ===========================================================================

def print_whatweb_result(result: dict) -> None:
    """
    Render WhatWeb results with a rich technology summary table and security notes.

    Args:
        result: Return value of run_whatweb() or run_whatweb_custom().
    """
    if result.get("skipped"):
        print_skipped("WhatWeb")
        _show_install_panel("whatweb")
        return

    if result.get("error"):
        console.print(
            Panel(
                f"[bold red]{result.get('details', {}).get('Error', 'Unknown error')}[/bold red]",
                title="[bold red]WhatWeb — Error[/bold red]",
                border_style="red",
            )
        )
        return

    details      = result.get("details", {})
    target       = result.get("target", "N/A")
    http_status  = details.get("http_status")
    scan_time    = result.get("scan_time", "N/A")
    command      = result.get("command", "N/A")
    technologies = details.get("technologies", [])
    total_plugins = details.get("total_plugins", 0)

    # ── Header Panel ──────────────────────────────────────────────────────
    status_colour = "green" if str(http_status or "").startswith("2") else "yellow"
    console.print(
        Panel(
            f"[bold]HTTP Status:[/bold] [{status_colour}]{http_status or 'N/A'}[/{status_colour}]   "
            f"[bold]Scan Time:[/bold] {scan_time}   "
            f"[bold]Plugins:[/bold] {total_plugins} detected\n"
            f"[dim]Command: {command[:120]}[/dim]",
            title=f"[bold cyan]WhatWeb — {target}[/bold cyan]",
            border_style="cyan",
            box=box.ROUNDED,
            padding=(0, 2),
        )
    )

    # ── Technology Table ──────────────────────────────────────────────────
    if technologies:
        tech_table = Table(
            title="Detected Technologies",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold cyan",
            show_lines=True,
            expand=False,
        )
        tech_table.add_column("Category",   style="bold",       min_width=16, no_wrap=True)
        tech_table.add_column("Technology", min_width=24)
        tech_table.add_column("Version",    style="dim yellow", min_width=14)

        # Sort by category priority
        def _cat_sort_key(t: dict) -> int:
            return _CATEGORY_ORDER.index(t.get("category", "Other")) \
                if t.get("category", "Other") in _CATEGORY_ORDER \
                else len(_CATEGORY_ORDER)

        sorted_techs = sorted(technologies, key=_cat_sort_key)

        for tech in sorted_techs:
            cat  = tech.get("category", "Other")
            name = tech.get("name", "")
            ver  = tech.get("version", "") or "—"

            if cat == "CMS":
                name_markup = f"[bold yellow]{name}[/bold yellow]"
            elif cat == "Web Server":
                name_markup = f"[bold cyan]{name}[/bold cyan]"
            elif cat == "Framework":
                name_markup = f"[bold blue]{name}[/bold blue]"
            else:
                name_markup = name

            tech_table.add_row(cat, name_markup, ver)

        console.print(tech_table)
    else:
        console.print("  [dim]No technologies detected.[/dim]\n")

    # ── Email addresses ───────────────────────────────────────────────────
    emails = details.get("email_addresses", [])
    if emails:
        console.print(
            Panel(
                "[bold red]⚠ Email Addresses Exposed:[/bold red]\n" +
                "\n".join(f"  • {e}" for e in emails),
                border_style="red",
                padding=(0, 2),
            )
        )

    # ── Cookies ───────────────────────────────────────────────────────────
    cookies_list = details.get("cookies", [])
    if cookies_list:
        console.print(
            Panel(
                "Cookies Detected:\n" + "\n".join(f"  • {c}" for c in cookies_list[:8]),
                title="[bold]Cookies[/bold]",
                border_style="dim",
                padding=(0, 2),
            )
        )

    # ── Security Notes ────────────────────────────────────────────────────
    if result.get("flagged"):
        has_ver = [t for t in technologies if t.get("version")]
        notes   = []
        if has_ver:
            notes.append(
                f"• Version information exposed — [bold]{len(has_ver)}[/bold] "
                "technologies reveal version strings (aids targeted CVE matching)"
            )
        if emails:
            notes.append(f"• [bold]{len(emails)}[/bold] email address(es) found in page content")
        notes.append(
            f"• [bold]{total_plugins}[/bold] total technologies fingerprinted — "
            "reduces attacker ambiguity about the tech stack"
        )

        console.print(
            Panel(
                "\n".join(notes),
                title="[bold yellow]⚠ Security Notes[/bold yellow]",
                border_style="yellow",
                padding=(0, 2),
            )
        )

    console.print(f"  [dim]Total plugins detected: {total_plugins}[/dim]\n")


def print_wappalyzer_result(result: dict) -> None:
    """
    Render Wappalyzer results with a category-grouped technology table.

    Args:
        result: Return value of run_wappalyzer().
    """
    if result.get("skipped"):
        print_skipped("Wappalyzer")
        _show_install_panel("wappalyzer")
        return

    if result.get("error"):
        console.print(
            Panel(
                f"[bold red]{result.get('details', {}).get('Error', 'Unknown error')}[/bold red]",
                title="[bold red]Wappalyzer — Error[/bold red]",
                border_style="red",
            )
        )
        return

    details      = result.get("details", {})
    target       = result.get("target", "N/A")
    scan_time    = result.get("scan_time", "N/A")
    total        = details.get("total_technologies", 0)
    det_method   = details.get("detection_method", "N/A")
    summary      = details.get("summary_by_category", {})

    # ── Header Panel ──────────────────────────────────────────────────────
    console.print(
        Panel(
            f"[bold]{total}[/bold] technologies detected   "
            f"[bold]Method:[/bold] {det_method}   "
            f"[bold]Scan time:[/bold] {scan_time}",
            title=f"[bold cyan]Wappalyzer — {target}[/bold cyan]",
            border_style="cyan",
            box=box.ROUNDED,
            padding=(0, 2),
        )
    )

    if not summary:
        console.print("  [dim]No technologies detected.[/dim]\n")
        return

    # ── Category Table ────────────────────────────────────────────────────
    cat_table = Table(
        title="Technology Stack by Category",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
        show_lines=True,
        expand=False,
    )
    cat_table.add_column("Category",    style="bold white", min_width=28, no_wrap=True)
    cat_table.add_column("Technologies", min_width=52)

    def _cat_key(c: str) -> int:
        try:
            return _WAPPALYZER_CATEGORY_ORDER.index(c)
        except ValueError:
            return len(_WAPPALYZER_CATEGORY_ORDER)

    for cat in sorted(summary.keys(), key=_cat_key):
        items = summary[cat]
        tech_str = ", ".join(
            f"[white]{t.split()[0]}[/white][dim] {' '.join(t.split()[1:])}[/dim]".strip()
            if len(t.split()) > 1 else t
            for t in items
        )
        cat_table.add_row(cat, tech_str)

    console.print(cat_table)

    # ── Top categories mini-bar ───────────────────────────────────────────
    if summary:
        sorted_cats = sorted(summary.items(), key=lambda x: len(x[1]), reverse=True)[:5]
        max_count   = max(len(v) for _, v in sorted_cats) or 1

        bar_table = Table(box=None, show_header=False, padding=(0, 0))
        bar_table.add_column("Cat",   style="dim", min_width=28, no_wrap=True)
        bar_table.add_column("Bar",   min_width=20)
        bar_table.add_column("Count", style="dim", min_width=4, justify="right")

        for cat, techs in sorted_cats:
            filled = int((len(techs) / max_count) * 10)
            bar    = "█" * filled + "░" * (10 - filled)
            bar_table.add_row(cat[:26], f"[cyan]{bar}[/cyan]", str(len(techs)))

        console.print(bar_table)

    if result.get("flagged"):
        console.print(
            Panel(
                "• Technology version exposure aids targeted vulnerability research\n"
                "• Review detected frameworks/CMS against known CVE databases",
                title="[bold yellow]⚠ Security Notes[/bold yellow]",
                border_style="yellow",
                padding=(0, 2),
            )
        )

    console.print()


def print_wafw00f_result(result: dict) -> None:
    """
    Render WafW00f results with WAF detection banner and evasion notes.

    Args:
        result: Return value of run_wafw00f().
    """
    if result.get("skipped"):
        print_skipped("WafW00f")
        _show_install_panel("wafw00f")
        return

    if result.get("error"):
        console.print(
            Panel(
                f"[bold red]{result.get('details', {}).get('Error', 'Unknown error')}[/bold red]",
                title="[bold red]WafW00f — Error[/bold red]",
                border_style="red",
            )
        )
        return

    details      = result.get("details", {})
    target       = result.get("target", "N/A")
    scan_time    = result.get("scan_time", "N/A")
    command      = result.get("command", "N/A")
    waf_detected = details.get("waf_detected", False)
    waf_name     = details.get("waf_name")
    manufacturer = details.get("manufacturer")
    all_wafs     = details.get("all_wafs", [])
    evasion      = details.get("evasion_notes", [])
    no_waf_warn  = details.get("no_waf_warning", "")

    # ── WAF Detection Banner ──────────────────────────────────────────────
    if waf_detected and waf_name:
        border = "green" if waf_name != "Generic" else "red"
        content = (
            f"[bold green]🛡  WAF DETECTED[/bold green]\n\n"
            f"[bold]Name:[/bold]         {waf_name}\n"
            f"[bold]Manufacturer:[/bold] {manufacturer or waf_name}\n"
            f"[bold]Scan Time:[/bold]    {scan_time}"
        )
        console.print(
            Panel(content, title="[bold]WafW00f Detection Result[/bold]",
                  border_style=border, padding=(1, 3))
        )
    else:
        console.print(
            Panel(
                "[bold yellow]⚠  NO WAF DETECTED — Target appears unprotected[/bold yellow]\n\n"
                f"[bold]Scan Time:[/bold] {scan_time}",
                title="[bold]WafW00f Detection Result[/bold]",
                border_style="yellow",
                padding=(1, 3),
            )
        )

    # ── Evasion Notes ─────────────────────────────────────────────────────
    if waf_detected and evasion:
        notes_text = "\n".join(f"  • {n}" for n in evasion)
        console.print(
            Panel(
                notes_text + "\n\n[dim]For authorised penetration testing use only.[/dim]",
                title="[bold blue]Evasion & Bypass Notes[/bold blue]",
                border_style="blue",
                padding=(0, 2),
            )
        )

    # ── Multiple WAFs Table ───────────────────────────────────────────────
    detected_multiple = [w for w in all_wafs if w.get("detected")]
    if len(detected_multiple) > 1:
        waf_table = Table(title="All Detected WAFs", box=box.ROUNDED,
                          show_header=True, header_style="bold cyan", show_lines=True)
        waf_table.add_column("WAF Name",     style="green", min_width=24)
        waf_table.add_column("Manufacturer", style="dim",   min_width=28)
        for w in detected_multiple:
            waf_table.add_row(
                w.get("firewall", "Unknown"),
                w.get("manufacturer", "N/A"),
            )
        console.print(waf_table)

    # ── No-WAF Security Note ──────────────────────────────────────────────
    if no_waf_warn:
        console.print(
            Panel(
                f"[yellow]{no_waf_warn}[/yellow]",
                title="[bold yellow]Security Note[/bold yellow]",
                border_style="yellow",
                padding=(0, 2),
            )
        )

    console.print(f"\n  [dim]Command: {command} | Scan time: {scan_time}[/dim]\n")


def print_full_fingerprint_result(result: dict) -> None:
    """
    Render the consolidated full fingerprint report from all three tools.

    Args:
        result: Return value of run_full_fingerprint().
    """
    if result.get("error"):
        console.print(
            Panel(
                f"[bold red]{result.get('details', {}).get('Error', 'Unknown error')}[/bold red]",
                title="[bold red]Full Fingerprint — Error[/bold red]",
                border_style="red",
            )
        )
        return

    summary    = result.get("summary", {})
    target     = result.get("target", "N/A")
    scan_time  = result.get("scan_time", "N/A")
    sub_results = result.get("results", {})

    cms           = summary.get("cms") or "Not detected"
    web_server    = summary.get("web_server") or "Not detected"
    waf           = summary.get("waf")
    waf_detected  = summary.get("waf_detected", False)
    technologies  = summary.get("technologies", [])
    total_tech    = summary.get("total_technologies", 0)
    frameworks    = summary.get("frameworks", [])
    languages     = summary.get("languages", [])
    concerns      = summary.get("security_concerns", [])
    tools_run     = summary.get("tools_run", [])
    tools_skipped = summary.get("tools_skipped", [])

    waf_display = f"{waf}  🛡" if waf_detected and waf else "None detected"

    # ── Master Summary Panel ──────────────────────────────────────────────
    console.print(
        Panel(
            f"[bold]CMS:[/bold]          {cms}\n"
            f"[bold]Web Server:[/bold]   {web_server}\n"
            f"[bold]WAF:[/bold]          {waf_display}\n"
            f"[bold]Technologies:[/bold] {total_tech} detected\n"
            f"[bold]Scan Time:[/bold]    {scan_time} (3 tools, concurrent)\n"
            f"[bold]Tools Run:[/bold]    {' · '.join(tools_run) or 'None'}\n"
            f"[bold]Skipped:[/bold]      {' · '.join(tools_skipped) or 'None'}",
            title=f"[bold white]FULL FINGERPRINT REPORT — {target}[/bold white]",
            border_style="white",
            box=box.DOUBLE_EDGE,
            padding=(1, 4),
        )
    )

    # ── Merged Technology Table ───────────────────────────────────────────
    if technologies:
        # Build source attribution
        ww_names = {
            t.get("name", "").lower()
            for t in sub_results.get("whatweb", {}).get("details", {}).get("technologies", [])
        }
        wa_names = {
            t.get("name", "").lower()
            for t in sub_results.get("wappalyzer", {}).get("details", {}).get("technologies", [])
        }

        merged_table = Table(
            title=f"Merged Technology Stack ({len(technologies)} unique technologies)",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold cyan",
            show_lines=True,
            expand=False,
        )
        merged_table.add_column("Technology", min_width=24)
        merged_table.add_column("Version",    style="dim yellow", min_width=14)
        merged_table.add_column("Source",     style="dim",        min_width=8)
        merged_table.add_column("Category",   style="dim",        min_width=14)

        for tech_str in technologies[:40]:
            parts    = tech_str.strip().split(None, 1)
            name_raw = parts[0]
            ver      = parts[1] if len(parts) > 1 else ""
            norm     = name_raw.lower()
            in_ww    = norm in ww_names
            in_wa    = norm in wa_names
            if in_ww and in_wa:
                src = "WW+WA"
            elif in_ww:
                src = "WW"
            elif in_wa:
                src = "WA"
            else:
                src = "?"
            category = _CATEGORY_ORDER[0] if "cms" in norm else _map_cat_guess(name_raw)
            merged_table.add_row(name_raw, ver or "—", src, category)

        console.print(merged_table)

    # ── WAF Status ────────────────────────────────────────────────────────
    if waf_detected and waf:
        console.print(f"[bold green]🛡 Protected by {waf}[/bold green]\n")
    else:
        console.print("[bold red]⚠  No WAF — Target appears unprotected[/bold red]\n")

    # ── Per-tool Panels ───────────────────────────────────────────────────
    for key, label, print_fn in [
        ("whatweb",    "WhatWeb Details",    print_whatweb_result),
        ("wappalyzer", "Wappalyzer Details", print_wappalyzer_result),
        ("wafw00f",    "WafW00f Details",    print_wafw00f_result),
    ]:
        sub = sub_results.get(key, {})
        if not sub.get("skipped"):
            console.print(Panel(Text(""), title=f"[bold cyan]{label}[/bold cyan]",
                                border_style="cyan", padding=(0, 0)))
            print_fn(sub)

    # ── Security Concerns ─────────────────────────────────────────────────
    if concerns:
        console.print(
            Panel(
                "\n".join(f"  • {c}" for c in concerns),
                title="[bold red]⚠ Security Concerns[/bold red]",
                border_style="red",
                padding=(0, 2),
            )
        )
    else:
        console.print(
            Panel(
                "[bold green]✓ No immediate security concerns flagged.[/bold green]",
                title="Security Assessment",
                border_style="green",
                padding=(0, 2),
            )
        )

    # ── Analyst Notes ─────────────────────────────────────────────────────
    analyst_notes: list[str] = []
    cms_lower = (summary.get("cms") or "").lower()
    if "wordpress" in cms_lower:
        analyst_notes.append(
            "WordPress version exposure facilitates CVE targeting — "
            "run whatweb <target> -a3 to confirm version"
        )
    if not waf_detected and not sub_results.get("wafw00f", {}).get("skipped"):
        analyst_notes.append(
            "No WAF detected — consider running WafW00f with -t flag "
            "for exhaustive check before concluding truly unprotected"
        )
    if waf and "cloudflare" in waf.lower():
        analyst_notes.append(
            "Cloudflare detected — origin IP may be exposed via "
            "Shodan/Censys SSL certificate history search"
        )
    for tech in sub_results.get("whatweb", {}).get("details", {}).get("technologies", []):
        if "PHP" in tech.get("name", "") and tech.get("version"):
            analyst_notes.append(
                f"PHP {tech['version']} version fingerprinting enables version-specific "
                "exploit targeting — check for known PHP CVEs for this version"
            )
            break

    if analyst_notes:
        console.print(
            Panel(
                "\n".join(f"  • {n}" for n in analyst_notes[:5]),
                title="[bold dim]Analyst Notes[/bold dim]",
                border_style="dim",
                padding=(0, 2),
            )
        )

    console.print()


def _map_cat_guess(name: str) -> str:
    """Quick category guess for merged table when full category mapping is unavailable."""
    n = name.lower()
    if any(x in n for x in ("wordpress", "joomla", "drupal", "magento")):
        return "CMS"
    if any(x in n for x in ("nginx", "apache", "iis", "litespeed")):
        return "Web Server"
    if any(x in n for x in ("php", "python", "ruby", "java", "node")):
        return "Language"
    if any(x in n for x in ("jquery", "react", "angular", "vue", "bootstrap")):
        return "JS Library"
    if any(x in n for x in ("cloudflare", "akamai", "fastly")):
        return "CDN"
    return "Other"
