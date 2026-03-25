"""
hash_menus.py — Interactive menus and result rendering for hash & file intelligence.

All UI output uses the shared console from modules/utils.py.
Menu patterns follow the same rich Table/Panel/Prompt style as main.py.
"""

from __future__ import annotations

import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from rich import box
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from modules.utils import console, print_section_header  # noqa: E402
from modules.hash_intel import (  # noqa: E402
    check_virustotal_hash,
    check_malwarebazaar,
    check_hybrid_analysis,
    check_malshare,
    check_threatfox,
    upload_to_virustotal,
    upload_to_hybrid_analysis,
    compute_file_hashes,
    detect_hash_type,
    _HA_ENVIRONMENTS,
)

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ---------------------------------------------------------------------------
# Top-level menu
# ---------------------------------------------------------------------------

def show_hash_menu() -> None:
    """Called from main.py when user selects [H]. Loops until Back."""
    while True:
        console.print(
            Panel(
                Text(
                    "Hash & File Intelligence\n"
                    "[dim]Investigate file hashes and upload samples for malware analysis[/dim]",
                    justify="center",
                ),
                border_style="magenta",
                box=box.ROUNDED,
                padding=(0, 4),
            )
        )

        table = Table(
            box=box.SIMPLE,
            show_header=True,
            header_style="bold cyan",
            expand=False,
            padding=(0, 2),
        )
        table.add_column("Key",     style="bold yellow", no_wrap=True, min_width=5)
        table.add_column("Option",  style="white",       min_width=32)
        table.add_column("Sources", style="dim",         min_width=48)

        table.add_row("[1]", "Hash Lookup",           "All 5 sources concurrently")
        table.add_row("[2]", "File Upload & Scan",    "VirusTotal + Hybrid Analysis")
        table.add_row("[3]", "Malware Family Lookup", "MalwareBazaar + ThreatFox")
        table.add_row("[4]", "YARA Match Check",      "MalwareBazaar YARA results")
        table.add_row("[5]", "Quick Hash Check",      "Single fastest source (MalwareBazaar)")
        table.add_row("[0]", "Back to Main Menu",     "")
        console.print(table)
        console.print()

        choice = Prompt.ask(
            "[bold yellow]Select option[/bold yellow]",
            choices=["0", "1", "2", "3", "4", "5"],
            show_choices=False,
        )

        if choice == "0":
            break

        handler = {
            "1": handle_hash_lookup,
            "2": handle_file_upload,
            "3": handle_malware_family_lookup,
            "4": handle_yara_check,
            "5": handle_quick_hash_check,
        }.get(choice)

        if handler:
            try:
                handler()
            except KeyboardInterrupt:
                console.print("\n[dim]Interrupted — returning to hash menu.[/dim]")

        Prompt.ask(
            "\n[dim]Press Enter to continue[/dim]",
            default="",
            show_default=False,
        )


# ---------------------------------------------------------------------------
# Hash validation helper
# ---------------------------------------------------------------------------

def _prompt_hash(prompt_text: str = "Enter hash (MD5 / SHA1 / SHA256)") -> tuple[str, str]:
    """
    Prompt for a hash, validate format, return (hash_str, hash_type).

    Loops until valid input is provided.
    """
    while True:
        h  = Prompt.ask(f"[bold]{prompt_text}[/bold]").strip()
        ht = detect_hash_type(h)
        if ht != "unknown":
            return h, ht
        console.print(
            "[bold red]✗ Invalid hash format. Must be MD5 (32), SHA1 (40), "
            "or SHA256 (64) hex characters.[/bold red]"
        )


# ---------------------------------------------------------------------------
# Option 1 — Full Hash Lookup
# ---------------------------------------------------------------------------

def handle_hash_lookup(prefilled_hash: str = "") -> None:
    """
    Prompt for a hash string, auto-detect type, run all 5 sources concurrently.

    Args:
        prefilled_hash: Optional pre-validated hash to skip the prompt.
    """
    if prefilled_hash and detect_hash_type(prefilled_hash) != "unknown":
        hash_str  = prefilled_hash
        hash_type = detect_hash_type(hash_str)
    else:
        hash_str, hash_type = _prompt_hash()

    console.print(f"[dim]Detected hash type: [bold]{hash_type.upper()}[/bold][/dim]")
    if hash_type in ("md5", "sha1"):
        console.print(
            "[yellow]ℹ  Note: Some APIs only accept SHA256. MD5/SHA1 hashes may return "
            "fewer results from Hybrid Analysis.[/yellow]"
        )
    console.print()

    all_results: list[dict] = []

    _fns = [
        check_virustotal_hash,
        check_malwarebazaar,
        check_hybrid_analysis,
        check_malshare,
        check_threatfox,
    ]

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Querying threat intelligence sources...", total=len(_fns))

        with ThreadPoolExecutor(max_workers=5) as executor:
            future_map = {executor.submit(fn, hash_str): fn for fn in _fns}
            for future in as_completed(future_map):
                try:
                    result = future.result()
                    if result:
                        all_results.append(result)
                except Exception as exc:  # noqa: BLE001
                    fn = future_map[future]
                    all_results.append({
                        "source":  fn.__name__,
                        "skipped": False,
                        "error":   True,
                        "flagged": False,
                        "details": {"Error": str(exc)},
                    })
                progress.update(task, advance=1)

    print_section_header(f"Hash Intelligence Results — {hash_str[:16]}...")
    for result in all_results:
        if result.get("skipped"):
            print_hash_skipped(result["source"])
        elif result.get("error"):
            print_hash_error(result)
        else:
            print_hash_result(result)

    print_hash_verdict_summary(all_results, hash_str)

    # JSON export
    console.print()
    export = Prompt.ask(
        "[yellow]Export results to JSON?[/yellow]",
        choices=["y", "n"],
        default="n",
    )
    if export == "y":
        _export_hash_report(hash_str, all_results)


def _export_hash_report(hash_str: str, results: list[dict]) -> None:
    """Export hash results to a timestamped JSON file in reports/."""
    reports_dir = os.path.join(_ROOT, "reports")
    os.makedirs(reports_dir, exist_ok=True)

    safe_hash = hash_str[:16]
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename  = os.path.join(reports_dir, f"hash_{safe_hash}_{timestamp}.json")

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

    export_data = {
        "generated_at": datetime.now().isoformat(),
        "hash":         hash_str,
        "results":      _sanitise(results),
    }

    with open(filename, "w", encoding="utf-8") as fh:
        json.dump(export_data, fh, indent=2, ensure_ascii=False)

    console.print(f"\n[bold green]Report exported → {filename}[/bold green]")


# ---------------------------------------------------------------------------
# Option 2 — File Upload & Scan
# ---------------------------------------------------------------------------

def handle_file_upload() -> None:
    """Allow user to upload a local file for sandbox analysis."""
    # Step 1 — File path input
    while True:
        file_path = Prompt.ask("[bold]Enter full path to file for analysis[/bold]").strip()
        if os.path.isfile(file_path):
            break
        console.print(f"[bold red]✗ File not found: {file_path}[/bold red]")

    # Step 2 — Compute hashes
    with Progress(
        SpinnerColumn(),
        TextColumn("[cyan]Computing file hashes..."),
        console=console,
        transient=True,
    ) as p:
        p.add_task("hashing", total=None)
        try:
            hashes = compute_file_hashes(file_path)
        except Exception as exc:  # noqa: BLE001
            console.print(f"[bold red]Error computing hashes: {exc}[/bold red]")
            return

    info_lines = "\n".join([
        f"  Filename  : {hashes['filename']}",
        f"  Size      : {hashes['file_size_human']}",
        f"  MD5       : {hashes['md5']}",
        f"  SHA1      : {hashes['sha1']}",
        f"  SHA256    : {hashes['sha256']}",
    ])
    console.print(
        Panel(
            info_lines,
            title="[bold white]File Information[/bold white]",
            border_style="cyan",
            box=box.ROUNDED,
        )
    )
    console.print()

    # Step 3 — Pre-check with MalwareBazaar
    sha256_val = hashes["sha256"]
    with Progress(
        SpinnerColumn(),
        TextColumn("[cyan]Checking MalwareBazaar..."),
        console=console,
        transient=True,
    ) as p:
        p.add_task("check", total=None)
        mb_result = check_malwarebazaar(sha256_val)

    if mb_result.get("flagged"):
        details = mb_result.get("details", {})
        sig     = details.get("Malware Signature", "unknown")
        tags    = details.get("Tags", "")
        console.print(
            Panel(
                f"[bold red]⚠  This file is ALREADY KNOWN MALWARE in MalwareBazaar.[/bold red]\n\n"
                f"  Signature : [bold red]{sig}[/bold red]\n"
                f"  Tags      : {tags}",
                border_style="red",
                box=box.HEAVY,
            )
        )
        proceed = Prompt.ask(
            "File is already known malware. Upload to sandbox anyway?",
            choices=["y", "n"],
            default="n",
        )
        if proceed == "n":
            print_hash_result(mb_result)
            return

    # Step 4 — Select upload destination
    console.print("\n[bold]Select upload destination:[/bold]")
    dest_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    dest_table.add_column("Key",    style="bold yellow")
    dest_table.add_column("Option", style="white")
    dest_table.add_row("[1]", "VirusTotal only")
    dest_table.add_row("[2]", "Hybrid Analysis only")
    dest_table.add_row("[3]", "Both (VirusTotal + Hybrid Analysis)")
    dest_table.add_row("[0]", "Cancel")
    console.print(dest_table)

    dest_choice = Prompt.ask("Select", choices=["0", "1", "2", "3"], show_choices=False)
    if dest_choice == "0":
        return

    # Step 5 — Sandbox environment selection (if HA chosen)
    env_id = 160
    if dest_choice in ("2", "3"):
        console.print("\n[bold]Select sandbox environment:[/bold]")
        env_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        env_table.add_column("Key",         style="bold yellow")
        env_table.add_column("Environment", style="white")
        env_table.add_row("[1]", "Windows 10 64-bit  (recommended)")
        env_table.add_row("[2]", "Windows 7 64-bit")
        env_table.add_row("[3]", "Windows 7 32-bit")
        env_table.add_row("[4]", "Linux Ubuntu 64-bit")
        env_table.add_row("[5]", "Android")
        console.print(env_table)

        env_choice = Prompt.ask(
            "Select environment",
            choices=["1", "2", "3", "4", "5"],
            default="1",
            show_choices=False,
        )
        env_id = {"1": 160, "2": 120, "3": 110, "4": 300, "5": 200}[env_choice]

    # Step 6 — Upload warning
    console.print(
        Panel(
            "[yellow]⚠  WARNING: Uploading a file sends it to an external service.\n"
            "Do NOT upload files containing passwords, private keys, PII,\n"
            "or any sensitive data. Uploaded files may be visible to other users\n"
            "of these services depending on your account type.[/yellow]",
            border_style="yellow",
            box=box.ROUNDED,
        )
    )
    confirm = Prompt.ask("Confirm upload?", choices=["y", "n"], default="n")
    if confirm == "n":
        return

    # Step 7 — Upload with progress
    upload_results: list[dict] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        if dest_choice in ("1", "3"):
            vt_task = progress.add_task(
                "Uploading to VirusTotal... this may take 2–5 minutes", total=None
            )
            vt_result = upload_to_virustotal(file_path)
            upload_results.append(vt_result)
            progress.remove_task(vt_task)

        if dest_choice in ("2", "3"):
            ha_task = progress.add_task(
                "Uploading to Hybrid Analysis sandbox... this may take 2–5 minutes", total=None
            )
            ha_result = upload_to_hybrid_analysis(file_path, environment_id=env_id)
            upload_results.append(ha_result)
            progress.remove_task(ha_task)

    for r in upload_results:
        if r.get("skipped"):
            print_hash_skipped(r["source"])
        elif r.get("error"):
            print_hash_error(r)
        else:
            print_hash_result(r)

    # Step 8 — Offer full hash lookup
    console.print()
    run_full = Prompt.ask(
        "Run full hash lookup against all sources using computed SHA256?",
        choices=["y", "n"],
        default="n",
    )
    if run_full == "y":
        handle_hash_lookup(prefilled_hash=sha256_val)


# ---------------------------------------------------------------------------
# Option 3 — Malware Family Lookup
# ---------------------------------------------------------------------------

def handle_malware_family_lookup() -> None:
    """Look up a hash specifically for malware family classification."""
    hash_str, hash_type = _prompt_hash()

    results: list[dict] = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]Querying MalwareBazaar and ThreatFox..."),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("", total=2)
        with ThreadPoolExecutor(max_workers=2) as executor:
            future_mb = executor.submit(check_malwarebazaar, hash_str)
            future_tf = executor.submit(check_threatfox,     hash_str)
            for future in as_completed([future_mb, future_tf]):
                try:
                    results.append(future.result())
                except Exception as exc:  # noqa: BLE001
                    results.append({
                        "source":  "lookup",
                        "skipped": False,
                        "error":   True,
                        "flagged": False,
                        "details": {"Error": str(exc)},
                    })
                progress.update(task, advance=1)

    mb = next((r for r in results if r.get("source") == "MalwareBazaar"), {})
    tf = next((r for r in results if r.get("source") == "ThreatFox"),     {})

    mb_sig   = mb.get("details", {}).get("Malware Signature", "Not found") if mb.get("flagged") else "Not found"
    mb_tags  = mb.get("details", {}).get("Tags",       "N/A") if mb.get("flagged") else "N/A"
    mb_seen  = mb.get("details", {}).get("First Seen", "N/A") if mb.get("flagged") else "N/A"

    tf_fam   = tf.get("details", {}).get("Malware Families", "Not found") if tf.get("flagged") else "Not found"
    tf_types = tf.get("details", {}).get("Threat Types",     "N/A")       if tf.get("flagged") else "N/A"
    tf_conf  = tf.get("details", {}).get("Max Confidence",   "N/A")       if tf.get("flagged") else "N/A"

    combined_family = mb_sig if mb_sig != "Not found" else (tf_fam if tf_fam != "Not found" else "Unknown")
    is_malicious    = mb.get("flagged", False) or tf.get("flagged", False)
    verdict_str     = "[bold red]MALICIOUS[/bold red]" if is_malicious else "[dim]UNKNOWN[/dim]"

    sig_line = (
        f"    Signature  : [bold red]{mb_sig}[/bold red]"
        if mb_sig != "Not found"
        else f"    Signature  : {mb_sig}"
    )
    fam_line = (
        f"    Families   : [bold red]{tf_fam}[/bold red]"
        if tf_fam != "Not found"
        else f"    Families   : {tf_fam}"
    )

    lines = "\n".join([
        f"  Hash       : {hash_str}",
        f"  Hash Type  : {hash_type.upper()}",
        "",
        "  [bold]MalwareBazaar:[/bold]",
        sig_line,
        f"    Tags       : {mb_tags}",
        f"    First Seen : {mb_seen}",
        "",
        "  [bold]ThreatFox:[/bold]",
        fam_line,
        f"    Threat Type: {tf_types}",
        f"    Confidence : {tf_conf}",
        "",
        "  [dim]── Combined Assessment ──────────────────────────[/dim]",
        f"    Known Malware Family: [bold]{combined_family}[/bold]",
        f"    Verdict:              {verdict_str}",
    ])

    console.print(
        Panel(
            lines,
            title="[bold white]Malware Family Report[/bold white]",
            border_style="red" if is_malicious else "cyan",
            box=box.ROUNDED,
            padding=(1, 2),
        )
    )


# ---------------------------------------------------------------------------
# Option 4 — YARA Match Check
# ---------------------------------------------------------------------------

def handle_yara_check() -> None:
    """Check which YARA rules a sample matches using MalwareBazaar."""
    hash_str, _ = _prompt_hash()

    with Progress(
        SpinnerColumn(),
        TextColumn("[cyan]Querying MalwareBazaar..."),
        console=console,
        transient=True,
    ) as p:
        p.add_task("", total=None)
        result = check_malwarebazaar(hash_str)

    if result.get("error"):
        print_hash_error(result)
        return

    details   = result.get("details", {})
    yara_list = details.get("YARA Matches", [])

    if not result.get("flagged"):
        console.print("[yellow]Hash not found in MalwareBazaar — no YARA data available.[/yellow]")
        return

    table = Table(
        title=f"YARA Rule Matches — {hash_str[:16]}...",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
        title_style="bold white",
        expand=False,
    )
    table.add_column("#",         style="dim",        min_width=4)
    table.add_column("Rule Name", style="bold white", min_width=40)

    if not yara_list or yara_list == ["None"]:
        console.print("[dim]No YARA rules matched for this sample.[/dim]")
    else:
        for i, rule_name in enumerate(yara_list, 1):
            table.add_row(str(i), rule_name)
        console.print(table)

    console.print()
    console.print(f"  Malware Signature : [bold red]{details.get('Malware Signature', 'N/A')}[/bold red]")
    console.print(f"  File Type         : {details.get('File Type', 'N/A')}")
    console.print(f"  Tags              : {details.get('Tags', 'N/A')}")
    console.print()
    console.print("[dim]YARA rule data sourced from MalwareBazaar (abuse.ch)[/dim]")


# ---------------------------------------------------------------------------
# Option 5 — Quick Hash Check
# ---------------------------------------------------------------------------

def handle_quick_hash_check(prefilled_hash: str = "") -> None:
    """
    Fastest single-source check using MalwareBazaar only.

    Designed for rapid triage during incident response.

    Args:
        prefilled_hash: Optional pre-validated hash to skip the prompt.
    """
    if prefilled_hash and detect_hash_type(prefilled_hash) != "unknown":
        hash_str = prefilled_hash
    else:
        hash_str, _ = _prompt_hash()

    with Progress(
        SpinnerColumn(),
        TextColumn("[cyan]Checking MalwareBazaar..."),
        console=console,
        transient=True,
    ) as p:
        p.add_task("", total=None)
        result = check_malwarebazaar(hash_str)

    details = result.get("details", {})

    if result.get("flagged"):
        yara_list  = details.get("YARA Matches", [])
        yara_count = len(yara_list) if (yara_list and yara_list != ["None"]) else 0
        console.print(
            Panel(
                "\n".join([
                    f"  Hash      : {hash_str}",
                    f"  Family    : [bold red]{details.get('Malware Signature', 'unknown')}[/bold red]",
                    f"  Tags      : {details.get('Tags', 'N/A')}",
                    f"  First Seen: {details.get('First Seen', 'N/A')}",
                    f"  YARA Hits : {yara_count} rules matched",
                    f"  URL       : [dim]{details.get('Sample URL', 'N/A')}[/dim]",
                ]),
                title="[bold red]⚠  MALICIOUS — MalwareBazaar[/bold red]",
                border_style="red",
                box=box.HEAVY,
                padding=(0, 2),
            )
        )
    else:
        status = details.get("Status", "Not found in MalwareBazaar database")
        console.print(
            Panel(
                "\n".join([
                    f"  Hash   : {hash_str}",
                    f"  Status : {status}",
                    "  Note   : Absence does not confirm the file is safe",
                    "           — run a full hash lookup for more coverage",
                ]),
                title="[bold green]✓ NOT FOUND — MalwareBazaar[/bold green]",
                border_style="green",
                box=box.ROUNDED,
                padding=(0, 2),
            )
        )

    console.print()
    run_full = Prompt.ask(
        "Run full lookup against all 5 sources?",
        choices=["y", "n"],
        default="n",
    )
    if run_full == "y":
        handle_hash_lookup(prefilled_hash=hash_str)


# ---------------------------------------------------------------------------
# Rendering functions
# ---------------------------------------------------------------------------

def print_hash_result(result: dict) -> None:
    """
    Render a single API result dict as a rich Table with source-specific formatting.

    List values are rendered as numbered sub-lists. Source-specific colour rules
    apply to key fields (Malicious count, Verdict, Threat Score, Malware Signature).
    """
    source  = result.get("source", "Unknown")
    flagged = result.get("flagged", False)
    details = result.get("details", {})
    border  = "red" if flagged else "green"

    table = Table(
        title=source,
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
        title_style="bold white",
        expand=False,
        show_lines=True,
        border_style=border,
    )
    table.add_column("Field", style="bold white", no_wrap=True, min_width=26)
    table.add_column("Value", min_width=52)

    for key, value in details.items():
        if value is None or value == "":
            table.add_row(str(key), "[dim]N/A[/dim]")
            continue

        # Render list values as numbered sub-lists
        if isinstance(value, list):
            if not value or value == ["None"]:
                cell = "[dim]None[/dim]"
            else:
                cell = "\n".join(f"  {i + 1}. {v}" for i, v in enumerate(value))
            table.add_row(str(key), cell)
            continue

        val_str = str(value)

        # Source-specific field styling
        if source == "VirusTotal":
            if key == "Malicious":
                style = "bold red" if not val_str.startswith("0 /") else "bold green"
            elif key == "Suspicious":
                style = "yellow" if not val_str.startswith("0 /") else "dim"
            elif any(x in key for x in ("URL", "Report", "VT")):
                style = "dim"
            else:
                style = "white"

        elif source == "MalwareBazaar":
            if key == "Malware Signature":
                style = "bold red"
            elif any(x in key for x in ("URL", "Sample")):
                style = "dim"
            else:
                style = "white"

        elif source == "Hybrid Analysis":
            if key == "Verdict":
                v_lower = val_str.lower()
                if "malicious" in v_lower:
                    style = "bold red"
                elif "suspicious" in v_lower:
                    style = "bold yellow"
                elif "no" in v_lower or "white" in v_lower:
                    style = "green"
                else:
                    style = "white"
            elif key == "Threat Score":
                try:
                    score_num = int(val_str.split("/")[0].strip())
                    style = "red" if score_num >= 75 else ("yellow" if score_num >= 50 else "green")
                except ValueError:
                    style = "white"
            elif any(x in key for x in ("URL", "Report", "HA")):
                style = "dim"
            else:
                style = "white"

        elif source == "ThreatFox":
            if key == "Malware Families" and val_str not in ("Unknown", "N/A"):
                style = "bold red"
            elif any(x in key for x in ("URL", "ThreatFox")):
                style = "dim"
            else:
                style = "white"

        else:  # Malshare and generic
            if any(x in key for x in ("URL", "Sample")):
                style = "dim"
            else:
                style = "white"

        # Truncate very long values
        display = val_str if len(val_str) <= 120 else val_str[:117] + "..."
        table.add_row(str(key), f"[{style}]{display}[/{style}]")

    console.print(table)
    console.print()


def print_hash_skipped(source: str) -> None:
    """Print a dim one-liner for skipped APIs — matching print_skipped() in utils.py."""
    console.print(f"  [dim]○ {source}: SKIPPED — no API key configured[/dim]")


def print_hash_error(result: dict) -> None:
    """Print a yellow warning panel for errored API results."""
    source  = result.get("source", "Unknown")
    message = result.get("details", {}).get("Error", "Unknown error")
    console.print(
        Panel(
            f"[yellow]⚠  {source}: {message}[/yellow]",
            border_style="yellow",
            box=box.ROUNDED,
            padding=(0, 2),
        )
    )
    console.print()


def print_hash_verdict_summary(results: list[dict], hash_str: str) -> None:
    """
    Print a consolidated verdict banner after all sources complete.

    Determines verdict from flagged/clean/skipped source counts and renders
    a DOUBLE_EDGE Panel with recommended action text.
    """
    flagged_sources: list[str] = []
    clean_sources:   list[str] = []
    skipped_sources: list[str] = []
    not_found:       list[str] = []

    for r in results:
        src = r.get("source", "Unknown")
        if r.get("skipped"):
            skipped_sources.append(src)
        elif r.get("error"):
            skipped_sources.append(f"{src} (error)")
        elif r.get("flagged"):
            flagged_sources.append(src)
        else:
            status = str(r.get("details", {}).get("Status", "")).lower()
            if "not found" in status or "no result" in status:
                not_found.append(src)
            else:
                clean_sources.append(src)

    n_flagged = len(flagged_sources)
    n_clean   = len(clean_sources)

    if n_flagged >= 2:
        verdict  = "CONFIRMED MALICIOUS"
        v_style  = "bold red"
        border   = "red"
        action   = (
            "Block immediately. Quarantine any systems that\n"
            "           executed this file. Escalate to IR team."
        )
    elif n_flagged == 1:
        verdict  = "LIKELY MALICIOUS"
        v_style  = "red"
        border   = "red"
        action   = (
            "Treat as malicious. Investigate execution context.\n"
            "           Check for lateral movement."
        )
    elif n_flagged == 0 and n_clean >= 2:
        verdict  = "LOW RISK / CLEAN"
        v_style  = "bold green"
        border   = "green"
        action   = (
            "No malicious indicators found. Continue monitoring.\n"
            "           Sample may be newly emerged — absence is not proof\n"
            "           of safety."
        )
    else:
        verdict  = "UNKNOWN"
        v_style  = "dim"
        border   = "cyan"
        action   = (
            "Insufficient data. Configure API keys for better\n"
            "           coverage. Consider uploading sample for sandbox\n"
            "           analysis (option 2)."
        )

    # Extract malware family from first flagged result
    malware_family = "Unknown"
    for r in results:
        if r.get("flagged"):
            d = r.get("details", {})
            for field in ("Malware Signature", "Malware Families", "Malware Family Tags"):
                val = d.get(field, "")
                if val and val not in ("N/A", "None", "Unknown") and val != ["None"]:
                    malware_family = ", ".join(val) if isinstance(val, list) else str(val)
                    break
        if malware_family != "Unknown":
            break

    flagged_str  = " · ".join(flagged_sources) if flagged_sources else "None"
    notfound_str = " · ".join(not_found)        if not_found       else "None"
    skipped_str  = " · ".join(skipped_sources)  if skipped_sources  else "None"

    malware_line = (
        f"   Malware     : [bold red]{malware_family}[/bold red]"
        if malware_family != "Unknown"
        else "   Malware     : Unknown"
    )

    lines = "\n".join([
        f"   Hash        : {hash_str}",
        f"   Verdict     : [{v_style}]{verdict}[/{v_style}]",
        malware_line,
        "",
        f"   Flagged by  : {flagged_str}",
        f"   Not found   : {notfound_str}",
        f"   Skipped     : {skipped_str}",
        "",
        "   Recommended Action:",
        f"   {action}",
    ])

    console.print(
        Panel(
            lines,
            title="[bold white]HASH INTELLIGENCE VERDICT[/bold white]",
            border_style=border,
            box=box.DOUBLE_EDGE,
            padding=(1, 2),
        )
    )
    console.print()
