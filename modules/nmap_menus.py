"""
nmap_menus.py — Interactive Nmap menus for ThreatScope.

Provides the full Nmap sub-menu tree:
  show_nmap_menu()
    ├─ [1] Generic port scan
    ├─ [2] Vulnerability scan (105 NSE scripts across 12 categories)
    └─ [3] Common scan types (SYN, UDP, OS, aggressive, etc.)

Uses the same rich console object from utils.py and follows the exact
same UI patterns as the rest of ThreatScope (Panels, Tables, Prompts).
"""

from __future__ import annotations

import os
import re
import sys
from typing import Callable

from rich import box
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

# Resolve project root so this module is importable standalone
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Shared console — never create a new Console() instance
from modules.utils import console, print_section_header  # noqa: E402
import modules.nmap_scanner as ns  # noqa: E402


# ---------------------------------------------------------------------------
# Type alias
# ---------------------------------------------------------------------------
# (script_name, ports, description, scanner_fn, is_destructive)
ScriptEntry = tuple[str, str, str, Callable, bool]

# Scripts that MUST trigger the destructive warning panel
_DESTRUCTIVE_SCRIPTS: frozenset[str] = frozenset([
    "smb-vuln-ms08-067",
    "smb-vuln-regsvc-dos",
    "smb-vuln-cve2009-3103",
    "ftp-vsftpd-backdoor",
    "ftp-proftpd-backdoor",
    "broadcast-avahi-dos",
    "clamav-exec",
    "distcc-cve2004-2687",
    "qconn-exec",
])


# ===========================================================================
# Internal helpers
# ===========================================================================

def _is_root() -> bool:
    """Return True if the current process has root / administrator privileges."""
    if sys.platform == "win32":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:  # noqa: BLE001
            return False
    return os.geteuid() == 0


def _show_destructive_warning(script_name: str) -> bool:
    """
    Display a red destructive-scan warning panel and require explicit YES.

    Args:
        script_name: The NSE script that triggered this warning.

    Returns:
        True if the user confirmed with YES, False to cancel.
    """
    console.print(
        Panel(
            f"[bold red]Script:[/bold red] {script_name}\n\n"
            "This script can [bold red]CRASH or DESTABILISE[/bold red] the target "
            "service, or [bold red]execute commands[/bold red] on the remote system.\n\n"
            "Only run this against systems you [bold]OWN[/bold] or have "
            "[bold]EXPLICIT WRITTEN AUTHORISATION[/bold] to test.\n\n"
            "[bold yellow]Type YES to confirm and proceed, or press Enter to cancel.[/bold yellow]",
            title="[bold red]⚠  DESTRUCTIVE SCAN WARNING[/bold red]",
            border_style="red",
            box=box.HEAVY,
            padding=(1, 3),
        )
    )
    answer = Prompt.ask("[bold red]Confirm[/bold red]", default="").strip()
    if answer.upper() != "YES":
        console.print("[dim]Scan cancelled — returning to menu.[/dim]\n")
        return False
    return True


def _prompt_target(prompt_text: str = "Enter target IP or hostname") -> str:
    """
    Prompt for a scan target and return it.
    Accepts IPs, hostnames, and CIDR ranges (e.g. 192.168.1.0/24).
    Returns empty string if user entered nothing.
    """
    val = Prompt.ask(f"[bold]{prompt_text}[/bold] [dim](IP, hostname, or CIDR)[/dim]").strip()
    return val


def _prompt_ports(default: str = "") -> str:
    """
    Prompt for a port specification and validate the format.
    Only digits, commas, and hyphens are accepted.
    """
    while True:
        hint = f" [dim](default: {default})[/dim]" if default else " [dim](e.g. 22,80,443 or 1-1024)[/dim]"
        val = Prompt.ask(f"[bold]Enter ports[/bold]{hint}", default=default).strip()
        if not val:
            val = default
        if re.match(r"^[\d,\-]+$", val):
            return val
        console.print("[bold red]  Invalid port format. Use digits, commas, and hyphens only.[/bold red]")


def _run_with_spinner(fn: Callable, target: str, label: str) -> dict:
    """
    Execute a scan function while displaying an animated spinner.

    Args:
        fn:     Scanner function to call with ``target`` as the sole argument.
        target: Scan target string.
        label:  Spinner description text.

    Returns:
        The dict returned by ``fn(target)``.
    """
    console.print(f"\n[yellow]⏳ Scanning... this may take several minutes depending on target.[/yellow]")
    result: dict = {}
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task(label, total=None)
        result = fn(target)
    return result


def _run_with_spinner_two_args(fn: Callable, arg1: str, arg2: str, label: str) -> dict:
    """Like _run_with_spinner but passes two arguments to fn."""
    console.print(f"\n[yellow]⏳ Scanning... this may take several minutes depending on target.[/yellow]")
    result: dict = {}
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task(label, total=None)
        result = fn(arg1, arg2)
    return result


def _warn_if_not_root(scan_type: str) -> None:
    """Print a yellow notice when a privileged scan is run without root."""
    if not _is_root():
        console.print(
            f"[yellow]⚠  {scan_type} works best with sudo/root — "
            "results may be incomplete without elevated privileges.[/yellow]\n"
        )


def _press_enter_to_continue() -> None:
    Prompt.ask("\n[dim]Press Enter to return to the menu[/dim]", default="", show_default=False)


# ===========================================================================
# Result renderers
# ===========================================================================

def print_nmap_port_table(result: dict, title: str = "Nmap Scan Results") -> None:
    """
    Render nmap port scan results as a colour-coded rich Table.

    Open ports are green, filtered are yellow, and a summary footer
    shows total open / filtered / closed counts.

    Args:
        result: Result dict from any generic or common scan function.
        title:  Table title string.
    """
    if result.get("error"):
        console.print(
            Panel(
                f"[bold red]{result.get('details', {}).get('Error', 'Unknown error')}[/bold red]",
                title=f"[bold red]{result.get('source', 'Nmap')} — Error[/bold red]",
                border_style="red",
            )
        )
        return

    details = result.get("details", {})
    open_ports: list[dict] = details.get("open_ports", [])
    target       = details.get("target", "N/A")
    host_state   = details.get("state", "unknown")
    filtered_ct  = details.get("filtered_ports", 0)
    closed_ct    = details.get("closed_ports", 0)
    scan_time    = details.get("scan_time", "N/A")
    nmap_command = details.get("nmap_command", "N/A")
    os_matches   = details.get("os_matches", [])

    # Host info panel
    state_colour = "green" if host_state == "up" else "red"
    console.print(
        Panel(
            f"[bold]Target:[/bold] {target}   "
            f"[bold]State:[/bold] [{state_colour}]{host_state}[/{state_colour}]   "
            f"[bold]Scan time:[/bold] {scan_time}",
            title=f"[bold cyan]{title}[/bold cyan]",
            border_style="cyan",
            box=box.ROUNDED,
            padding=(0, 2),
        )
    )

    if os_matches:
        os_table = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan", show_lines=False)
        os_table.add_column("OS Match", style="white")
        os_table.add_column("Accuracy", style="yellow", justify="right")
        for m in os_matches:
            os_table.add_row(m.get("name", "N/A"), f"{m.get('accuracy', 0)}%")
        console.print(os_table)

    if not open_ports:
        console.print(f"  [dim]No open ports found. Filtered: {filtered_ct}  Closed: {closed_ct}[/dim]\n")
    else:
        table = Table(
            title=f"Open Ports ({len(open_ports)} found)",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold cyan",
            show_lines=True,
            expand=False,
        )
        table.add_column("PORT",     style="bold white",  no_wrap=True, min_width=7)
        table.add_column("PROTO",    style="dim",         no_wrap=True, min_width=6)
        table.add_column("STATE",    no_wrap=True,        min_width=14)
        table.add_column("SERVICE",  style="cyan",        min_width=12)
        table.add_column("VERSION",  min_width=30)

        for p in open_ports:
            state_str = p.get("state", "open")
            if state_str == "open":
                state_markup = "[bold green]open[/bold green]"
            elif "filtered" in state_str:
                state_markup = "[yellow]open|filtered[/yellow]"
            else:
                state_markup = f"[dim]{state_str}[/dim]"

            product = p.get("product", "")
            version = p.get("version", "")
            ver_str = f"{product} {version}".strip() or "—"

            table.add_row(
                str(p.get("port", "?")),
                p.get("protocol", "tcp"),
                state_markup,
                p.get("service", "—"),
                ver_str,
            )

        # Summary footer row
        table.add_section()
        table.add_row(
            f"[dim]{len(open_ports)} open[/dim]",
            "",
            f"[dim]{filtered_ct} filtered[/dim]",
            f"[dim]{closed_ct} closed[/dim]",
            "",
        )

        console.print(table)

    console.print(f"  [dim]Command: {nmap_command}[/dim]\n")


def print_nmap_script_output(result: dict) -> None:
    """
    Render NSE script output in a rich Panel or Table.

    If script_output is a dict the entries are shown as a two-column table.
    If it is a string it is displayed inside a yellow-bordered Panel.
    Always appends the nmap command used in dim text.

    Args:
        result: Result dict from any ``scan_*`` NSE function.
    """
    if result.get("error"):
        console.print(
            Panel(
                f"[bold red]{result.get('details', {}).get('Error', 'Unknown error')}[/bold red]",
                title=f"[bold red]{result.get('source', 'Nmap')} — Error[/bold red]",
                border_style="red",
            )
        )
        return

    details      = result.get("details", {})
    script_name  = details.get("script_name", "NSE Script")
    target       = details.get("target", "N/A")
    open_ports   = details.get("open_ports", [])
    script_out   = details.get("script_output", "No output.")
    nmap_command = details.get("nmap_command", "N/A")
    flagged      = result.get("flagged", False)

    border = "red" if flagged else "cyan"
    status = "[bold red]VULNERABLE[/bold red]" if flagged else "[bold green]No issues detected[/bold green]"

    console.print(
        Panel(
            f"[bold]Script:[/bold] {script_name}   "
            f"[bold]Target:[/bold] {target}   "
            f"[bold]Status:[/bold] {status}",
            title=f"[bold cyan]{result.get('source', 'Nmap')}[/bold cyan]",
            border_style=border,
            box=box.ROUNDED,
            padding=(0, 2),
        )
    )

    # Compact port list
    if open_ports:
        port_list = ", ".join(
            f"[green]{p['port']}/{p.get('protocol','tcp')}[/green]" for p in open_ports[:20]
        )
        console.print(f"  [bold]Open ports:[/bold] {port_list}\n")

    # Script output display
    if isinstance(script_out, dict) and script_out:
        out_table = Table(
            box=box.ROUNDED,
            show_header=True,
            header_style="bold cyan",
            show_lines=True,
            expand=True,
        )
        out_table.add_column("Port / Script", style="bold white", min_width=30, no_wrap=True)
        out_table.add_column("Output", min_width=60)
        for key, val in script_out.items():
            val_str = str(val)
            colour = "bold red" if _is_output_flagged(val_str) else "white"
            if len(val_str) > 500:
                val_str = val_str[:497] + "..."
            out_table.add_row(str(key), f"[{colour}]{val_str}[/{colour}]")
        console.print(out_table)
    else:
        out_str = str(script_out) if script_out else "No script output returned."
        border_colour = "red" if _is_output_flagged(out_str) else "yellow"
        console.print(
            Panel(
                out_str,
                title="[bold]Script Output[/bold]",
                border_style=border_colour,
                box=box.ROUNDED,
                padding=(0, 2),
            )
        )

    console.print(f"\n  [dim]Nmap command: {nmap_command}[/dim]\n")


def _is_output_flagged(text: str) -> bool:
    """Return True if the text contains any vulnerability indicator keyword."""
    upper = text.upper()
    keywords = (
        "VULNERABLE", "EXPLOITABLE", "SUCCESS", "BACKDOOR", "BYPASS",
        "OVERFLOW", "INJECTION", "RCE", "CVE",
    )
    return any(kw in upper for kw in keywords)


# ===========================================================================
# Generic category menu engine
# ===========================================================================

def _show_script_category_menu(
    title: str,
    scripts: list[ScriptEntry],
) -> None:
    """
    Display a category script menu, handle selection, run scan, show results.

    Loops until the user selects 0 (Back).

    Args:
        title:   Category display title.
        scripts: List of (script_name, ports, description, fn, is_destructive).
    """
    while True:
        console.print()
        table = Table(
            title=title,
            box=box.ROUNDED,
            show_header=True,
            header_style="bold cyan",
            show_lines=True,
            expand=False,
        )
        table.add_column("Key",         style="bold yellow", no_wrap=True, min_width=5)
        table.add_column("Script",      style="cyan",        min_width=34, no_wrap=True)
        table.add_column("Ports",       style="dim",         min_width=14)
        table.add_column("Description", style="white",       min_width=46)

        for i, (sname, ports, desc, _fn, destructive) in enumerate(scripts, start=1):
            caution = " [bold red]⚠[/bold red]" if destructive else ""
            table.add_row(f"[{i}]", sname + caution, ports, desc)

        table.add_section()
        table.add_row("[0]", "[dim]Back[/dim]", "", "")
        console.print(table)
        console.print()

        valid = [str(i) for i in range(len(scripts) + 1)]
        choice = Prompt.ask(
            "[bold yellow]Select script[/bold yellow]",
            choices=valid,
            show_choices=False,
        )

        if choice == "0":
            break

        idx = int(choice) - 1
        script_name, ports, desc, fn, is_destructive = scripts[idx]

        # Prompt for target
        target = _prompt_target()
        if not target:
            console.print("[bold red]Target cannot be empty.[/bold red]")
            continue

        # Destructive warning gate
        if is_destructive:
            if not _show_destructive_warning(script_name):
                continue

        # Run scan
        result = _run_with_spinner(fn, target, f"Running {script_name} against {target}...")

        # Render result
        print_nmap_script_output(result)

        if result.get("flagged"):
            console.print(
                "[bold red]⚠  VULNERABILITY INDICATORS DETECTED — Review the output above carefully[/bold red]\n"
            )

        _press_enter_to_continue()


# ===========================================================================
# Top-level Nmap menu
# ===========================================================================

def show_nmap_menu() -> None:
    """
    Top-level Nmap sub-menu. Called from main.py when user selects [N].
    Loops until the user selects 0 (Back to Main Menu).
    """
    while True:
        console.print()
        table = Table(
            title="NMAP SCANNER",
            box=box.ROUNDED,
            show_header=False,
            border_style="blue",
            title_style="bold white",
            expand=False,
            padding=(0, 1),
        )
        table.add_column("Key",    style="bold yellow", no_wrap=True, min_width=5)
        table.add_column("Option", style="white",       min_width=60)

        table.add_row("[1]", "Nmap Scan           — Generic port scan (top 1000 ports)")
        table.add_row("[2]", "Vulnerability Scan  — NSE vulnerability scripts (105 scripts)")
        table.add_row("[3]", "Common Nmap Scans   — Predefined scan types")
        table.add_section()
        table.add_row("[0]", "[dim]Back to Main Menu[/dim]")
        console.print(table)
        console.print()

        choice = Prompt.ask(
            "[bold yellow]Select option[/bold yellow]",
            choices=["0", "1", "2", "3"],
            show_choices=False,
        )

        if choice == "0":
            break
        elif choice == "1":
            handle_generic_nmap_scan()
        elif choice == "2":
            show_vuln_scan_menu()
        elif choice == "3":
            show_common_scans_menu()


# ---------------------------------------------------------------------------
# Handler: Generic scan
# ---------------------------------------------------------------------------

def handle_generic_nmap_scan() -> None:
    """
    Prompt for a target, run a generic top-1000-port TCP scan,
    and render the results using print_nmap_port_table().
    """
    target = _prompt_target("Enter target IP, hostname, or CIDR")
    if not target:
        console.print("[bold red]Target cannot be empty.[/bold red]")
        return

    print_section_header(f"Nmap Generic Scan — {target}")
    result = _run_with_spinner(ns.generic_port_scan, target, f"Scanning {target} (top 1000 ports)...")
    print_nmap_port_table(result, f"Generic Scan — {target}")
    _press_enter_to_continue()


# ===========================================================================
# Common scans sub-menu
# ===========================================================================

def show_common_scans_menu() -> None:
    """
    Common scan-type sub-menu. Loops until the user selects 0 (Back).
    Root-required scans show a yellow advisory before execution.
    """
    while True:
        console.print()
        table = Table(
            title="COMMON NMAP SCANS",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold cyan",
            expand=False,
            padding=(0, 1),
        )
        table.add_column("Key",            style="bold yellow", no_wrap=True, min_width=5)
        table.add_column("Scan Type",      style="white",       min_width=32)
        table.add_column("Command",        style="cyan dim",    min_width=28)
        table.add_column("Notes",          style="dim",         min_width=20)

        rows = [
            ("[1]",  "Service / Version Detection",   "nmap -sV <target>",          ""),
            ("[2]",  "OS Detection",                  "nmap -O <target>",           "⚠ requires root"),
            ("[3]",  "Specific Ports Scan",           "nmap -p <ports> <target>",   ""),
            ("[4]",  "ACK Scan (Firewall Mapping)",   "nmap -sA <target>",          "⚠ requires root"),
            ("[5]",  "SYN / Stealth Scan",            "nmap -sS <target>",          "⚠ requires root"),
            ("[6]",  "UDP Scan",                      "nmap -sU <target>",          "⚠ requires root"),
            ("[7]",  "TCP SYN Ping (Discovery)",      "nmap -PS80,443 <target>",    ""),
            ("[8]",  "Aggressive Scan",               "nmap -A <target>",           "⚠ requires root"),
            ("[9]",  "Scan from File",                "nmap -iL <file>",            ""),
        ]
        for key, stype, cmd, notes in rows:
            note_markup = f"[yellow]{notes}[/yellow]" if notes else ""
            table.add_row(key, stype, cmd, note_markup)

        table.add_section()
        table.add_row("[0]", "[dim]Back[/dim]", "", "")
        console.print(table)
        console.print()

        choice = Prompt.ask(
            "[bold yellow]Select scan type[/bold yellow]",
            choices=[str(i) for i in range(10)],
            show_choices=False,
        )

        if choice == "0":
            break

        elif choice == "1":
            target = _prompt_target()
            if not target:
                continue
            print_section_header(f"Service Version Scan — {target}")
            result = _run_with_spinner(ns.service_version_scan, target, f"Version scan: {target}...")
            print_nmap_port_table(result, f"Service Version — {target}")
            _press_enter_to_continue()

        elif choice == "2":
            _warn_if_not_root("OS Detection")
            target = _prompt_target()
            if not target:
                continue
            print_section_header(f"OS Detection — {target}")
            result = _run_with_spinner(ns.os_detection_scan, target, f"OS detection: {target}...")
            print_nmap_port_table(result, f"OS Detection — {target}")
            _press_enter_to_continue()

        elif choice == "3":
            target = _prompt_target()
            if not target:
                continue
            ports = _prompt_ports()
            print_section_header(f"Specific Ports Scan — {target} — {ports}")
            result = _run_with_spinner_two_args(
                ns.specific_ports_scan, target, ports,
                f"Port scan [{ports}]: {target}...",
            )
            print_nmap_port_table(result, f"Specific Ports [{ports}] — {target}")
            _press_enter_to_continue()

        elif choice == "4":
            _warn_if_not_root("ACK Scan")
            target = _prompt_target()
            if not target:
                continue
            print_section_header(f"ACK Scan — {target}")
            result = _run_with_spinner(ns.ack_scan, target, f"ACK scan: {target}...")
            print_nmap_port_table(result, f"ACK Scan — {target}")
            _press_enter_to_continue()

        elif choice == "5":
            _warn_if_not_root("SYN Stealth Scan")
            target = _prompt_target()
            if not target:
                continue
            print_section_header(f"SYN Stealth Scan — {target}")
            result = _run_with_spinner(ns.syn_stealth_scan, target, f"SYN stealth scan: {target}...")
            print_nmap_port_table(result, f"SYN Stealth — {target}")
            _press_enter_to_continue()

        elif choice == "6":
            _warn_if_not_root("UDP Scan")
            target = _prompt_target()
            if not target:
                continue
            print_section_header(f"UDP Scan — {target}")
            result = _run_with_spinner(ns.udp_scan, target, f"UDP scan: {target}...")
            print_nmap_port_table(result, f"UDP Scan — {target}")
            _press_enter_to_continue()

        elif choice == "7":
            target = _prompt_target("Enter target IP, hostname, or CIDR (e.g. 192.168.1.0/24)")
            if not target:
                continue
            ping_ports_raw = Prompt.ask(
                "[bold]Ping ports[/bold] [dim](default: 80,443)[/dim]",
                default="80,443",
            ).strip()
            if not re.match(r"^[\d,\-]+$", ping_ports_raw):
                ping_ports_raw = "80,443"
            print_section_header(f"TCP SYN Ping Discovery — {target}")
            result = _run_with_spinner_two_args(
                ns.tcp_syn_ping, target, ping_ports_raw,
                f"TCP SYN ping ({ping_ports_raw}): {target}...",
            )
            from modules.utils import print_result_table
            print_result_table(result, result.get("source", "Nmap - TCP SYN Ping"))
            _press_enter_to_continue()

        elif choice == "8":
            _warn_if_not_root("Aggressive Scan")
            target = _prompt_target()
            if not target:
                continue
            print_section_header(f"Aggressive Scan — {target}")
            result = _run_with_spinner(ns.aggressive_scan, target, f"Aggressive scan: {target}...")
            print_nmap_port_table(result, f"Aggressive Scan — {target}")
            _press_enter_to_continue()

        elif choice == "9":
            file_path = Prompt.ask("[bold]Enter path to targets file[/bold]").strip()
            if not os.path.isfile(file_path):
                console.print(f"[bold red]File not found: {file_path}[/bold red]")
                continue
            print_section_header(f"Scan from File — {file_path}")
            result = _run_with_spinner(
                ns.scan_from_list, file_path,
                f"Scanning targets from {file_path}...",
            )
            print_nmap_port_table(result, f"File Scan — {file_path}")
            _press_enter_to_continue()


# ===========================================================================
# Vulnerability scan — top category menu
# ===========================================================================

def show_vuln_scan_menu() -> None:
    """
    Vulnerability category picker. Loops until the user selects 0 (Back to Nmap Menu).
    Dispatches to individual category sub-menus.
    """
    while True:
        console.print()
        table = Table(
            title="VULNERABILITY SCAN — SELECT CATEGORY",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold cyan",
            expand=False,
            padding=(0, 1),
        )
        table.add_column("Key",      style="bold yellow", no_wrap=True, min_width=6)
        table.add_column("Category", style="white",       min_width=36)
        table.add_column("Scripts",  style="cyan",        min_width=9, justify="right")

        rows = [
            ("[1]",  "Run ALL vuln scripts (--script vuln)",  "1"),
            ("[2]",  "SMB / Windows",                        "15"),
            ("[3]",  "HTTP / Web",                           "46"),
            ("[4]",  "SSL / TLS",                             "8"),
            ("[5]",  "FTP",                                   "4"),
            ("[6]",  "SMTP",                                  "3"),
            ("[7]",  "Databases  (MySQL / MS SQL)",           "2"),
            ("[8]",  "RDP / VNC",                             "2"),
            ("[9]",  "IPMI / Hardware",                       "2"),
            ("[10]", "IRC",                                   "2"),
            ("[11]", "Misc Services",                        "11"),
            ("[12]", "CVE Database (Vulners)",                "1"),
        ]
        for key, cat, count in rows:
            table.add_row(key, cat, count)

        table.add_section()
        table.add_row("[0]", "[dim]Back to Nmap Menu[/dim]", "")
        console.print(table)
        console.print()

        choice = Prompt.ask(
            "[bold yellow]Select category[/bold yellow]",
            choices=[str(i) for i in range(13)],
            show_choices=False,
        )

        if choice == "0":
            break
        elif choice == "1":
            _handle_vuln_all()
        elif choice == "2":
            show_vuln_smb_menu()
        elif choice == "3":
            show_vuln_http_menu()
        elif choice == "4":
            show_vuln_ssl_menu()
        elif choice == "5":
            show_vuln_ftp_menu()
        elif choice == "6":
            show_vuln_smtp_menu()
        elif choice == "7":
            show_vuln_db_menu()
        elif choice == "8":
            show_vuln_rdp_vnc_menu()
        elif choice == "9":
            show_vuln_ipmi_menu()
        elif choice == "10":
            show_vuln_irc_menu()
        elif choice == "11":
            show_vuln_misc_menu()
        elif choice == "12":
            show_vuln_cve_db_menu()


def _handle_vuln_all() -> None:
    """Run --script vuln (all vuln-category scripts) with a 600-second timeout."""
    target = _prompt_target()
    if not target:
        return

    console.print(
        Panel(
            "[yellow]⚠  Running ALL NSE vuln-category scripts. "
            "This is slow, loud, and will take [bold]up to 10 minutes[/bold].\n"
            "Only run against systems you own or have authorisation to test.[/yellow]",
            title="[bold yellow]⚠  ALL VULN SCRIPTS[/bold yellow]",
            border_style="yellow",
            padding=(0, 2),
        )
    )
    answer = Prompt.ask("[bold yellow]Proceed?[/bold yellow]", choices=["y", "n"], default="n")
    if answer.lower() != "y":
        return

    print_section_header(f"All Vuln Scripts — {target}")
    console.print("[yellow]⏳ This may take up to 10 minutes. Do not interrupt...[/yellow]\n")

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task(f"Running --script vuln against {target}...", total=None)
        result = ns.scan_vuln_all(target)

    print_nmap_script_output(result)

    if result.get("flagged"):
        console.print(
            "[bold red]⚠  VULNERABILITY INDICATORS DETECTED — Review the output above carefully[/bold red]\n"
        )

    _press_enter_to_continue()


# ===========================================================================
# Category sub-menus
# ===========================================================================

def show_vuln_smb_menu() -> None:
    """SMB / Windows vulnerability scripts sub-menu (15 scripts)."""
    scripts: list[ScriptEntry] = [
        ("smb-vuln-ms17-010",          "445",     "EternalBlue / WannaCry RCE (MS17-010)",            ns.scan_smb_vuln_ms17_010,          False),
        ("smb-double-pulsar-backdoor", "445",     "DoublePulsar SMB backdoor detection",              ns.scan_smb_double_pulsar_backdoor,  False),
        ("smb-vuln-ms08-067",          "139,445", "MS08-067 NetAPI RCE",                              ns.scan_smb_vuln_ms08_067,           True),
        ("smb-vuln-conficker",         "139,445", "Conficker worm detection",                         ns.scan_smb_vuln_conficker,          False),
        ("smb-vuln-cve-2017-7494",     "139,445", "SambaCry RCE (CVE-2017-7494)",                     ns.scan_smb_vuln_cve_2017_7494,      False),
        ("smb-vuln-cve-2012-1182",     "139,445", "Samba heap overflow (CVE-2012-1182)",              ns.scan_smb_vuln_cve_2012_1182,      False),
        ("samba-vuln-cve-2012-1182",   "139,445", "Samba heap overflow — alt check",                 ns.scan_samba_vuln_cve_2012_1182,    False),
        ("smb-vuln-ms06-025",          "139,445", "RAS RPC MS06-025",                                 ns.scan_smb_vuln_ms06_025,           False),
        ("smb-vuln-ms07-029",          "139,445", "DNS RPC MS07-029",                                 ns.scan_smb_vuln_ms07_029,           False),
        ("smb-vuln-ms10-054",          "139,445", "SMB remote memory corruption MS10-054",            ns.scan_smb_vuln_ms10_054,           False),
        ("smb-vuln-ms10-061",          "139,445", "Printer Spooler impersonation MS10-061",           ns.scan_smb_vuln_ms10_061,           False),
        ("smb-vuln-regsvc-dos",        "139,445", "regsvc null deref DoS",                            ns.scan_smb_vuln_regsvc_dos,         True),
        ("smb-vuln-cve2009-3103",      "445",     "Windows SMBv2 DoS (CVE-2009-3103)",                ns.scan_smb_vuln_cve2009_3103,       True),
        ("smb-vuln-webexec",           "139,445", "Cisco WebExService RCE",                           ns.scan_smb_vuln_webexec,            False),
        ("smb2-vuln-uptime",           "445",     "Infer missing patches via SMB2 uptime",            ns.scan_smb2_vuln_uptime,            False),
    ]
    _show_script_category_menu("SMB / WINDOWS VULNERABILITY SCRIPTS", scripts)


def show_vuln_http_menu() -> None:
    """HTTP / Web vulnerability scripts sub-menu (46 scripts)."""
    scripts: list[ScriptEntry] = [
        ("http-shellshock",                   "80,443,8080",  "Shellshock RCE (CVE-2014-6271)",              ns.scan_http_shellshock,                   False),
        ("http-vuln-cve2017-5638",            "80,443,8080",  "Apache Struts RCE (CVE-2017-5638)",           ns.scan_http_vuln_cve2017_5638,            False),
        ("http-vuln-cve2015-1635",            "80",           "Windows HTTP.sys RCE (MS15-034)",             ns.scan_http_vuln_cve2015_1635,            False),
        ("http-vuln-cve2014-3704",            "80,443",       "Drupageddon SQL injection",                   ns.scan_http_vuln_cve2014_3704,            False),
        ("http-vuln-cve2013-0156",            "80,443,3000",  "Rails object injection RCE/DoS",              ns.scan_http_vuln_cve2013_0156,            False),
        ("http-vuln-cve2015-1427",            "9200",         "Elasticsearch Groovy RCE",                    ns.scan_http_vuln_cve2015_1427,            False),
        ("http-vuln-cve2017-8917",            "80,443",       "Joomla! SQLi (CVE-2017-8917)",                ns.scan_http_vuln_cve2017_8917,            False),
        ("http-vuln-cve2017-5689",            "16992,16993",  "Intel AMT privilege escalation",              ns.scan_http_vuln_cve2017_5689,            False),
        ("http-sql-injection",                "80,443",       "Generic SQL injection spider",                ns.scan_http_sql_injection,                False),
        ("http-csrf",                         "80,443",       "CSRF vulnerability detection",                ns.scan_http_csrf,                         False),
        ("http-dombased-xss",                 "80,443",       "DOM-based XSS sinks",                        ns.scan_http_dombased_xss,                 False),
        ("http-stored-xss",                   "80,443",       "Stored XSS via unfiltered input",             ns.scan_http_stored_xss,                   False),
        ("http-phpself-xss",                  "80,443",       "PHP_SELF XSS",                               ns.scan_http_phpself_xss,                  False),
        ("http-iis-webdav-vuln",              "80,443",       "IIS WebDAV auth bypass (MS09-020)",           ns.scan_http_iis_webdav_vuln,              False),
        ("http-vuln-cve2010-0738",            "8080,8443",    "JBoss JMX auth bypass",                      ns.scan_http_vuln_cve2010_0738,            False),
        ("http-vuln-cve2012-1823",            "80,443",       "PHP-CGI code/source disclosure",              ns.scan_http_vuln_cve2012_1823,            False),
        ("http-vuln-cve2014-8877",            "80,443",       "WordPress CM Download RCE",                   ns.scan_http_vuln_cve2014_8877,            False),
        ("http-vuln-cve2017-1001000",         "80,443",       "WordPress 4.7.x content injection",           ns.scan_http_vuln_cve2017_1001000,         False),
        ("http-wordpress-users",              "80,443",       "WordPress user enumeration",                  ns.scan_http_wordpress_users,              False),
        ("http-adobe-coldfusion-apsa1301",    "80,443,8500",  "ColdFusion auth bypass",                     ns.scan_http_adobe_coldfusion_apsa1301,    False),
        ("http-vuln-cve2010-2861",            "80,443,8500",  "ColdFusion dir traversal (admin hash)",       ns.scan_http_vuln_cve2010_2861,            False),
        ("http-axis2-dir-traversal",          "80,443,8080",  "Apache Axis2 dir traversal",                  ns.scan_http_axis2_dir_traversal,          False),
        ("http-enum",                         "80,443,8080",  "Common web paths enumeration",                ns.scan_http_enum,                         False),
        ("http-git",                          "80,443,8080",  "Exposed .git directory",                     ns.scan_http_git,                          False),
        ("http-passwd",                       "80,443",       "/etc/passwd traversal",                      ns.scan_http_passwd,                       False),
        ("http-trace",                        "80,443",       "HTTP TRACE enabled (XST risk)",               ns.scan_http_trace,                        False),
        ("http-method-tamper",                "80,443",       "HTTP verb tampering auth bypass",             ns.scan_http_method_tamper,                False),
        ("http-aspnet-debug",                 "80,443",       "ASP.NET DEBUG enabled",                      ns.scan_http_aspnet_debug,                 False),
        ("http-cookie-flags",                 "80,443",       "Missing httponly/secure cookie flags",        ns.scan_http_cookie_flags,                 False),
        ("http-cross-domain-policy",          "80,443",       "Permissive crossdomain policy",              ns.scan_http_cross_domain_policy,          False),
        ("http-internal-ip-disclosure",       "80,443",       "Internal IP address leakage",                ns.scan_http_internal_ip_disclosure,       False),
        ("http-jsonp-detection",              "80,443",       "JSONP endpoints (SOP bypass risk)",           ns.scan_http_jsonp_detection,              False),
        ("http-fileupload-exploiter",         "80,443",       "Insecure file upload exploit",               ns.scan_http_fileupload_exploiter,         False),
        ("http-frontpage-login",              "80,443",       "Anonymous FrontPage login",                  ns.scan_http_frontpage_login,              False),
        ("http-vuln-cve2006-3392",            "10000",        "Webmin file disclosure",                     ns.scan_http_vuln_cve2006_3392,            False),
        ("http-vuln-cve2009-3960",            "80,443",       "Adobe XML External Entity (XXE)",            ns.scan_http_vuln_cve2009_3960,            False),
        ("http-vuln-cve2011-3192",            "80,443",       "Apache range header DoS",                    ns.scan_http_vuln_cve2011_3192,            False),
        ("http-vuln-cve2011-3368",            "80,443",       "Apache reverse proxy bypass",                ns.scan_http_vuln_cve2011_3368,            False),
        ("http-vuln-cve2013-6786",            "80",           "RomPager redirect/XSS",                      ns.scan_http_vuln_cve2013_6786,            False),
        ("http-vuln-cve2013-7091",            "80,443",       "Zimbra 0-day (pre-7.2.6)",                   ns.scan_http_vuln_cve2013_7091,            False),
        ("http-vuln-cve2014-2126",            "443",          "Cisco ASA ASDM privilege escalation",        ns.scan_http_vuln_cve2014_2126,            False),
        ("http-vuln-cve2014-2127",            "443",          "Cisco ASA SSL VPN privilege escalation",     ns.scan_http_vuln_cve2014_2127,            False),
        ("http-vuln-cve2014-2128",            "443",          "Cisco ASA SSL VPN auth bypass",              ns.scan_http_vuln_cve2014_2128,            False),
        ("http-vuln-cve2014-2129",            "5060",         "Cisco ASA SIP DoS",                          ns.scan_http_vuln_cve2014_2129,            False),
        ("http-vuln-misfortune-cookie",       "80",           "RomPager Misfortune Cookie",                 ns.scan_http_vuln_misfortune_cookie,       False),
        ("http-vuln-wnr1000-creds",           "80",           "Netgear WNR1000 credential disclosure",      ns.scan_http_vuln_wnr1000_creds,           False),
    ]
    _show_script_category_menu("HTTP / WEB VULNERABILITY SCRIPTS  (46 scripts)", scripts)


def show_vuln_ssl_menu() -> None:
    """SSL / TLS vulnerability scripts sub-menu (8 scripts)."""
    scripts: list[ScriptEntry] = [
        ("ssl-heartbleed",    "443,8443", "Heartbleed (CVE-2014-0160)",             ns.scan_ssl_heartbleed,    False),
        ("ssl-poodle",        "443,8443", "POODLE SSLv3 (CVE-2014-3566)",           ns.scan_ssl_poodle,        False),
        ("sslv2-drown",       "443,8443", "SSLv2 / DROWN attack",                   ns.scan_sslv2_drown,       False),
        ("ssl-ccs-injection", "443,8443", "CCS Injection (CVE-2014-0224)",          ns.scan_ssl_ccs_injection, False),
        ("ssl-dh-params",     "443,8443", "Weak Diffie-Hellman params (Logjam)",    ns.scan_ssl_dh_params,     False),
        ("tls-ticketbleed",   "443",      "F5 Ticketbleed (CVE-2016-9244)",         ns.scan_tls_ticketbleed,   False),
        ("ssl-known-key",     "443,8443", "Known bad / compromised keys",           ns.scan_ssl_known_key,     False),
        ("ssl-cert-intaddr",  "443,8443", "Private IPs exposed in public certs",    ns.scan_ssl_cert_intaddr,  False),
    ]
    _show_script_category_menu("SSL / TLS VULNERABILITY SCRIPTS", scripts)


def show_vuln_ftp_menu() -> None:
    """FTP vulnerability scripts sub-menu (4 scripts)."""
    scripts: list[ScriptEntry] = [
        ("ftp-vsftpd-backdoor",   "21", "vsFTPd 2.3.4 backdoor",               ns.scan_ftp_vsftpd_backdoor,   True),
        ("ftp-proftpd-backdoor",  "21", "ProFTPD 1.3.3c backdoor",             ns.scan_ftp_proftpd_backdoor,  True),
        ("ftp-vuln-cve2010-4221", "21", "ProFTPD TELNET_IAC overflow",         ns.scan_ftp_vuln_cve2010_4221, False),
        ("ftp-libopie",           "21", "FTPd OPIE stack overflow",            ns.scan_ftp_libopie,           False),
    ]
    _show_script_category_menu("FTP VULNERABILITY SCRIPTS", scripts)


def show_vuln_smtp_menu() -> None:
    """SMTP vulnerability scripts sub-menu (3 scripts)."""
    scripts: list[ScriptEntry] = [
        ("smtp-vuln-cve2010-4344", "25,465,587", "Exim heap overflow / privilege escalation",    ns.scan_smtp_vuln_cve2010_4344, False),
        ("smtp-vuln-cve2011-1720", "25,465,587", "Postfix + Cyrus SASL memory corruption",       ns.scan_smtp_vuln_cve2011_1720, False),
        ("smtp-vuln-cve2011-1764", "25,465,587", "Exim DKIM format string RCE",                  ns.scan_smtp_vuln_cve2011_1764, False),
    ]
    _show_script_category_menu("SMTP VULNERABILITY SCRIPTS", scripts)


def show_vuln_db_menu() -> None:
    """Database vulnerability scripts sub-menu (2 scripts)."""
    scripts: list[ScriptEntry] = [
        ("mysql-vuln-cve2012-2122", "3306", "MySQL auth bypass (CVE-2012-2122)", ns.scan_mysql_vuln_cve2012_2122, False),
        ("ms-sql-info",             "1433", "MS SQL Server enumeration",         ns.scan_ms_sql_info,             False),
    ]
    _show_script_category_menu("DATABASE VULNERABILITY SCRIPTS", scripts)


def show_vuln_rdp_vnc_menu() -> None:
    """RDP / VNC vulnerability scripts sub-menu (2 scripts)."""
    scripts: list[ScriptEntry] = [
        ("rdp-vuln-ms12-020",   "3389",      "RDP MS12-020 DoS / info disclosure", ns.scan_rdp_vuln_ms12_020,   False),
        ("realvnc-auth-bypass", "5900,5901", "RealVNC auth bypass (CVE-2006-2369)", ns.scan_realvnc_auth_bypass, False),
    ]
    _show_script_category_menu("RDP / VNC VULNERABILITY SCRIPTS", scripts)


def show_vuln_ipmi_menu() -> None:
    """IPMI / Hardware vulnerability scripts sub-menu (2 scripts)."""
    scripts: list[ScriptEntry] = [
        ("ipmi-cipher-zero",      "623",   "IPMI 2.0 cipher zero auth bypass",                    ns.scan_ipmi_cipher_zero,      False),
        ("supermicro-ipmi-conf",  "49152", "Supermicro IPMI clear-text config download",           ns.scan_supermicro_ipmi_conf,  False),
    ]
    _show_script_category_menu("IPMI / HARDWARE VULNERABILITY SCRIPTS", scripts)


def show_vuln_irc_menu() -> None:
    """IRC vulnerability scripts sub-menu (2 scripts)."""
    scripts: list[ScriptEntry] = [
        ("irc-unrealircd-backdoor", "6667",      "UnrealIRCd backdoor timing test",        ns.scan_irc_unrealircd_backdoor, False),
        ("irc-botnet-channels",     "6667,6697", "IRC botnet channel detection",            ns.scan_irc_botnet_channels,     False),
    ]
    _show_script_category_menu("IRC VULNERABILITY SCRIPTS", scripts)


def show_vuln_misc_menu() -> None:
    """Misc services vulnerability scripts sub-menu (11 scripts)."""
    scripts: list[ScriptEntry] = [
        ("distcc-cve2004-2687",  "3632",  "distcc daemon RCE (CVE-2004-2687)",       ns.scan_distcc_cve2004_2687,     True),
        ("clamav-exec",          "3310",  "ClamAV unauthenticated RCE",              ns.scan_clamav_exec,             True),
        ("rmi-vuln-classloader", "1099",  "Java RMI remote classloader RCE",         ns.scan_rmi_vuln_classloader,    False),
        ("qconn-exec",           "8000",  "QNX QCONN unauthenticated exec",          ns.scan_qconn_exec,              True),
        ("puppet-naivesigning",  "8140",  "Puppet CA naive CSR auto-signing",        ns.scan_puppet_naivesigning,     False),
        ("netbus-auth-bypass",   "12345", "NetBus auth bypass (no password)",        ns.scan_netbus_auth_bypass,      False),
        ("wdb-version",          "17185", "VxWorks WDB agent info / vulns",          ns.scan_wdb_version,             False),
        ("broadcast-avahi-dos",  "mcast", "Avahi NULL UDP DoS (CVE-2011-1002)",      ns.scan_broadcast_avahi_dos,     True),
        ("dns-update",           "53",    "Unauthenticated dynamic DNS update",      ns.scan_dns_update,              False),
        ("firewall-bypass",      "any",   "Helper-based firewall vuln detection",    ns.scan_firewall_bypass,         False),
        ("afp-path-vuln",        "548",   "Mac OS X AFP dir traversal (CVE-2010-0533)", ns.scan_afp_path_vuln,        False),
    ]
    _show_script_category_menu("MISC SERVICES VULNERABILITY SCRIPTS", scripts)


def show_vuln_cve_db_menu() -> None:
    """
    Vulners CVE database sub-menu (1 script).
    Informs user that -sV is automatically included before running.
    """
    while True:
        console.print()
        table = Table(
            title="CVE DATABASE — VULNERS",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold cyan",
            show_lines=True,
            expand=False,
        )
        table.add_column("Key",         style="bold yellow", no_wrap=True, min_width=5)
        table.add_column("Script",      style="cyan",        min_width=20)
        table.add_column("Ports",       style="dim",         min_width=16)
        table.add_column("Description", style="white",       min_width=40)

        table.add_row("[1]", "vulners", "all (needs -sV)", "CVE / CVSS lookup via Vulners DB")
        table.add_section()
        table.add_row("[0]", "[dim]Back[/dim]", "", "")
        console.print(table)

        console.print(
            Panel(
                "[cyan]ℹ  The [bold]vulners[/bold] script requires service version detection "
                "([bold]-sV[/bold]) to generate CPE data for vulnerability matching.\n"
                "This scan will [bold]automatically include -sV[/bold] and may take "
                "longer than a standard NSE script scan.[/cyan]",
                title="[bold cyan]ℹ  Information[/bold cyan]",
                border_style="cyan",
                padding=(0, 2),
            )
        )
        console.print()

        choice = Prompt.ask(
            "[bold yellow]Select[/bold yellow]",
            choices=["0", "1"],
            show_choices=False,
        )

        if choice == "0":
            break

        target = _prompt_target()
        if not target:
            continue

        print_section_header(f"Vulners CVE Scan — {target}")
        result = _run_with_spinner(ns.scan_vulners, target, f"Running vulners (-sV) against {target}...")
        print_nmap_script_output(result)

        if result.get("flagged"):
            console.print(
                "[bold red]⚠  VULNERABILITY INDICATORS DETECTED — Review the output above carefully[/bold red]\n"
            )

        _press_enter_to_continue()
