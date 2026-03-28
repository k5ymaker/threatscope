"""
subdomain_recon.py — Subdomain enumeration, ASN lookup, and DNS intelligence.

Each function:
  - Returns a structured dict: source, skipped, error, flagged, details.
  - Never raises exceptions to the caller.
"""

from __future__ import annotations

import csv
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Optional

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import CONFIG  # noqa: E402

from modules.utils import console, print_result_table, print_section_header

REQUEST_TIMEOUT = 20

# ---------------------------------------------------------------------------
# Sublist3r availability detection
# ---------------------------------------------------------------------------

SUBLIST3R_BIN: Optional[str] = shutil.which("sublist3r") or shutil.which("Sublist3r")
SUBLIST3R_LIB: bool          = importlib.util.find_spec("sublist3r") is not None
SUBLIST3R_AVAILABLE: bool    = bool(SUBLIST3R_BIN) or SUBLIST3R_LIB

# Root of the project (two levels up from this file)
_PROJECT_ROOT = Path(__file__).parent.parent

# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _skipped_result(source: str, reason: str = "No API key configured") -> dict:
    return {"source": source, "skipped": True, "error": False, "flagged": False, "details": {"reason": reason}}


def _error_result(source: str, message: str) -> dict:
    return {"source": source, "skipped": False, "error": True, "flagged": False, "details": {"Error": message}}


def _not_found_result(source: str, message: str) -> dict:
    return {"source": source, "skipped": False, "error": False, "flagged": False, "details": {"Status": message}}


# ---------------------------------------------------------------------------
# 1. crt.sh certificate transparency
# ---------------------------------------------------------------------------

def enumerate_subdomains_crtsh(domain: str) -> dict:
    """
    Enumerate subdomains via crt.sh certificate transparency logs.

    Args:
        domain: Target domain (e.g. example.com).

    Returns:
        Structured result dict with deduplicated subdomain list.
    """
    source = "crt.sh"
    url    = f"https://crt.sh/?q=%.{domain}&output=json"

    try:
        resp = requests.get(url, timeout=REQUEST_TIMEOUT, headers={"Accept": "application/json"})
        resp.raise_for_status()
        data = resp.json()

        subdomains: set[str] = set()
        for entry in data:
            name_value = entry.get("name_value", "")
            for name in name_value.splitlines():
                name = name.strip().lstrip("*.")
                if name and domain in name:
                    subdomains.add(name.lower())

        sorted_subs = sorted(subdomains)
        count       = len(sorted_subs)

        if count == 0:
            return _not_found_result(source, f"No subdomains found for {domain}.")

        details: dict = {
            "Domain":           domain,
            "Subdomains Found": count,
            "Source":           "Certificate Transparency (crt.sh)",
        }
        for i, sub in enumerate(sorted_subs[:30], 1):
            details[f"  Sub {i:02d}"] = sub
        if count > 30:
            details["..."] = f"(+{count - 30} more — use export)"

        return {
            "source":     source,
            "skipped":    False,
            "error":      False,
            "flagged":    False,
            "subdomains": sorted_subs,
            "details":    details,
        }

    except requests.exceptions.RequestException as exc:
        return _error_result(source, str(exc))
    except (ValueError, KeyError) as exc:
        return _error_result(source, f"Parse error: {exc}")


# ---------------------------------------------------------------------------
# 2. HackerTarget subdomain finder
# ---------------------------------------------------------------------------

def enumerate_subdomains_hackertarget(domain: str) -> dict:
    """
    Enumerate subdomains via HackerTarget's free API.

    Args:
        domain: Target domain.

    Returns:
        Structured result dict with subdomain list.
    """
    source = "HackerTarget"
    url    = f"https://api.hackertarget.com/hostsearch/?q={domain}"

    try:
        resp = requests.get(url, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        text = resp.text.strip()

        if "error" in text.lower() or "API count exceeded" in text:
            return _error_result(source, text[:200])

        subdomains: list[str] = []
        for line in text.splitlines():
            parts = line.split(",")
            if parts and domain in parts[0]:
                subdomains.append(parts[0].strip().lower())

        subdomains = sorted(set(subdomains))
        count      = len(subdomains)

        if count == 0:
            return _not_found_result(source, f"No subdomains found for {domain}.")

        details: dict = {
            "Domain":           domain,
            "Subdomains Found": count,
            "Source":           "HackerTarget hostsearch",
        }
        for i, sub in enumerate(subdomains[:25], 1):
            details[f"  Sub {i:02d}"] = sub
        if count > 25:
            details["..."] = f"(+{count - 25} more)"

        return {
            "source":     source,
            "skipped":    False,
            "error":      False,
            "flagged":    False,
            "subdomains": subdomains,
            "details":    details,
        }

    except requests.exceptions.RequestException as exc:
        return _error_result(source, str(exc))


# ---------------------------------------------------------------------------
# 3. BGPView ASN / IP lookup
# ---------------------------------------------------------------------------

def asn_lookup_bgpview(ip_or_asn: str) -> dict:
    """
    Look up ASN or IP information via BGPView API.

    Args:
        ip_or_asn: IP address or ASN (e.g. "8.8.8.8" or "AS15169" or "15169").

    Returns:
        Structured result dict with ASN/prefix data.
    """
    source  = "BGPView"
    cleaned = ip_or_asn.strip().upper().lstrip("AS")

    # Determine endpoint
    if ip_or_asn.strip().upper().startswith("AS") or ip_or_asn.strip().isdigit():
        asn_num = cleaned.lstrip("0") or "0"
        url     = f"https://api.bgpview.io/asn/{asn_num}"
        query_type = "asn"
    else:
        url        = f"https://api.bgpview.io/ip/{ip_or_asn.strip()}"
        query_type = "ip"

    try:
        resp = requests.get(url, timeout=REQUEST_TIMEOUT, headers={"Accept": "application/json"})

        if resp.status_code == 404:
            return _not_found_result(source, f"No data found for {ip_or_asn}.")

        resp.raise_for_status()
        data = resp.json()

        if data.get("status") != "ok":
            return _error_result(source, data.get("status_message", "Unknown error"))

        payload = data.get("data", {})
        details: dict = {"Query": ip_or_asn}

        if query_type == "asn":
            details["ASN"]          = payload.get("asn", "")
            details["Name"]         = payload.get("name", "")
            details["Description"]  = payload.get("description_short", "")
            details["Country Code"] = payload.get("country_code", "")
            details["Website"]      = payload.get("website", "")
            details["RIR"]          = payload.get("rir_allocation", {}).get("rir_name", "")
        else:
            prefixes = payload.get("prefixes", [])
            if prefixes:
                p = prefixes[0]
                details["IP"]           = ip_or_asn
                details["Prefix"]       = p.get("prefix", "")
                details["ASN"]          = p.get("asn", {}).get("asn", "")
                details["ASN Name"]     = p.get("asn", {}).get("name", "")
                details["Country Code"] = p.get("country_code", "")
                details["Description"]  = p.get("description", "")
            else:
                details["IP"]  = ip_or_asn
                details["Note"] = "No prefix data returned"

        return {
            "source":  source,
            "skipped": False,
            "error":   False,
            "flagged": False,
            "details": details,
        }

    except requests.exceptions.RequestException as exc:
        return _error_result(source, str(exc))


# ---------------------------------------------------------------------------
# 4. RIPEstat lookup
# ---------------------------------------------------------------------------

def ripestat_lookup(ip_or_prefix: str) -> dict:
    """
    Query RIPEstat for IP/prefix routing and geolocation data.

    Args:
        ip_or_prefix: IP address or CIDR prefix (e.g. "8.8.8.0/24").

    Returns:
        Structured result dict with routing data.
    """
    source = "RIPEstat"
    base   = "https://stat.ripe.net/data"

    try:
        # Overview (prefix + ASN)
        overview_resp = requests.get(
            f"{base}/prefix-overview/data.json?resource={ip_or_prefix}",
            timeout=REQUEST_TIMEOUT,
        )
        overview_resp.raise_for_status()
        overview = overview_resp.json().get("data", {})

        # Geolocation
        geo_resp = requests.get(
            f"{base}/geoloc/data.json?resource={ip_or_prefix}",
            timeout=REQUEST_TIMEOUT,
        )
        geo_resp.raise_for_status()
        geo_data = geo_resp.json().get("data", {}).get("locations", [{}])
        geo      = geo_data[0] if geo_data else {}

        asns = overview.get("asns", [])
        asn_info = asns[0] if asns else {}

        details: dict = {
            "Resource":    ip_or_prefix,
            "Prefix":      overview.get("resource", ""),
            "ASN":         asn_info.get("asn", ""),
            "ASN Holder":  asn_info.get("holder", ""),
            "Is Announced": "yes" if overview.get("is_less_specific") or asns else "no",
            "Country":     geo.get("country", ""),
            "City":        geo.get("city", ""),
            "Latitude":    geo.get("latitude", ""),
            "Longitude":   geo.get("longitude", ""),
        }

        return {
            "source":  source,
            "skipped": False,
            "error":   False,
            "flagged": False,
            "details": details,
        }

    except requests.exceptions.RequestException as exc:
        return _error_result(source, str(exc))
    except (KeyError, IndexError, ValueError) as exc:
        return _error_result(source, f"Parse error: {exc}")


# ---------------------------------------------------------------------------
# 5. SecurityTrails
# ---------------------------------------------------------------------------

def securitytrails_lookup(domain: str) -> dict:
    """
    Query SecurityTrails for subdomain enumeration and DNS history.

    Args:
        domain: Target domain.

    Returns:
        Structured result dict with subdomains and DNS data.
    """
    source = "SecurityTrails"
    key    = CONFIG.get("securitytrails")
    if not key:
        return _skipped_result(source)

    headers = {"apikey": key, "Accept": "application/json"}

    try:
        resp = requests.get(
            f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        )

        if resp.status_code in (401, 403):
            return _error_result(source, "Invalid SecurityTrails API key.")

        if resp.status_code == 429:
            return _error_result(source, "Rate limit hit (429).")

        resp.raise_for_status()
        data       = resp.json()
        sub_list   = data.get("subdomains", [])
        count      = data.get("subdomain_count", len(sub_list))

        full_subs  = sorted([f"{s}.{domain}" for s in sub_list])

        details: dict = {
            "Domain":           domain,
            "Subdomains Found": count,
            "Source":           "SecurityTrails",
        }
        for i, sub in enumerate(full_subs[:25], 1):
            details[f"  Sub {i:02d}"] = sub
        if len(full_subs) > 25:
            details["..."] = f"(+{len(full_subs) - 25} more)"

        return {
            "source":     source,
            "skipped":    False,
            "error":      False,
            "flagged":    False,
            "subdomains": full_subs,
            "details":    details,
        }

    except requests.exceptions.RequestException as exc:
        return _error_result(source, str(exc))


# ---------------------------------------------------------------------------
# Animated task helper
# ---------------------------------------------------------------------------

def _animated_task(description: str, fn, *args, **kwargs):
    """
    Run fn(*args, **kwargs) inside a Rich animated progress block.

    Prints a dim green confirmation line when done.
    Returns whatever fn returns.
    """
    from rich.progress import (
        BarColumn,
        Progress,
        SpinnerColumn,
        TextColumn,
        TimeElapsedColumn,
    )

    start = time.perf_counter()

    with Progress(
        SpinnerColumn(spinner_name="dots12", style="bold cyan"),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=28, style="cyan", complete_style="bright_cyan"),
        TextColumn("[dim]{task.percentage:>3.0f}%[/dim]"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
        refresh_per_second=15,
    ) as progress:
        task = progress.add_task(description, total=None)
        result = fn(*args, **kwargs)
        progress.update(task, completed=100, total=100)

    elapsed = time.perf_counter() - start
    console.print(f"  [dim green]✓  {description} — done ({elapsed:.1f}s)[/dim green]")
    return result


# ---------------------------------------------------------------------------
# Export helper
# ---------------------------------------------------------------------------

def export_subdomains(
    domain: str,
    subdomains: list,
    source: str,
    fmt: str,
    extra_data=None,
) -> str:
    """
    Export a subdomain list to the reports/ directory.

    Args:
        domain:     Target domain.
        subdomains: List of subdomain strings.
        source:     Short source tag (e.g. "crtsh", "hackertarget").
        fmt:        One of "txt", "csv", "json".
        extra_data: Optional metadata dict written into JSON exports.

    Returns:
        Absolute path string on success, or "Export failed: {reason}" on error.
    """
    reports_dir = _PROJECT_ROOT / "reports"
    try:
        reports_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return f"Export failed: {exc}"

    timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_domain = domain.replace(".", "_")
    filename    = reports_dir / f"subdomains_{safe_domain}_{source}_{timestamp}.{fmt}"

    try:
        if fmt == "txt":
            with open(filename, "w", encoding="utf-8") as fh:
                for sub in subdomains:
                    fh.write(sub + "\n")

        elif fmt == "csv":
            exported_at = datetime.now().isoformat()
            with open(filename, "w", newline="", encoding="utf-8") as fh:
                writer = csv.writer(fh)
                writer.writerow(["subdomain", "domain", "source", "exported_at"])
                for sub in subdomains:
                    writer.writerow([sub, domain, source, exported_at])

        elif fmt == "json":
            export_data = {
                "domain":      domain,
                "source":      source,
                "exported_at": datetime.now().isoformat(),
                "count":       len(subdomains),
                "subdomains":  subdomains,
                "metadata":    extra_data,
            }
            with open(filename, "w", encoding="utf-8") as fh:
                json.dump(export_data, fh, indent=2, ensure_ascii=False)

        else:
            return f"Export failed: unknown format '{fmt}'"

        return str(filename.resolve())

    except OSError as exc:
        return f"Export failed: {exc}"


# ---------------------------------------------------------------------------
# Sublist3r integration
# ---------------------------------------------------------------------------

def _read_sublist3r_output(tmp_path: Optional[str]) -> list:
    """Read and deduplicate lines from a Sublist3r -o output file."""
    if not tmp_path or not os.path.exists(tmp_path):
        return []
    try:
        with open(tmp_path, "r", encoding="utf-8") as fh:
            return sorted({line.strip() for line in fh if line.strip()})
    except OSError:
        return []


def scan_sublist3r(
    domain: str,
    threads: int = 10,
    use_brute: bool = False,
) -> dict:
    """
    Enumerate subdomains using Sublist3r (binary or Python module fallback).

    Runs without a hard timeout — press Ctrl+C at any time to cancel.
    On cancellation, any subdomains already written to the output file are
    returned as partial results rather than discarded.

    Args:
        domain:    Target domain.
        threads:   Thread count (capped 1–30).
        use_brute: Enable Sublist3r brute-force mode.

    Returns:
        Standard 5-key result dict.
    """
    source = "Sublist3r"

    if not SUBLIST3R_AVAILABLE:
        return _skipped_result(
            source,
            "Sublist3r not installed. Install with:\n"
            "  pip install sublist3r\n"
            "  OR: sudo apt install sublist3r\n"
            "  OR: git clone https://github.com/aboul3la/Sublist3r.git",
        )

    threads  = min(max(1, threads), 30)
    tmp_path = None
    proc     = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False, encoding="utf-8"
        ) as tmp:
            tmp_path = tmp.name

        if SUBLIST3R_BIN:
            cmd  = [SUBLIST3R_BIN, "-d", domain, "-t", str(threads), "-o", tmp_path]
            mode = "binary"
        else:
            cmd  = [sys.executable, "-m", "sublist3r", "-d", domain, "-t", str(threads), "-o", tmp_path]
            mode = "module"

        if use_brute:
            cmd.append("-b")

        # Use Popen so KeyboardInterrupt can cleanly kill the child process
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            _stdout, _stderr = proc.communicate()
        except KeyboardInterrupt:
            # User pressed Ctrl+C — kill child immediately, then recover partial results
            proc.kill()
            proc.wait()
            partial = _read_sublist3r_output(tmp_path)
            if partial:
                count = len(partial)
                details: dict = {
                    "Domain":           domain,
                    "Subdomains Found": f"{count} (partial — scan cancelled by user)",
                    "Brute Force":      "Enabled" if use_brute else "Disabled",
                    "Threads":          str(threads),
                    "Execution Mode":   mode,
                }
                for i, sub in enumerate(partial[:30], 1):
                    details[f"  Sub {i:02d}"] = sub
                if count > 30:
                    details["..."] = f"(+{count - 30} more — use export)"
                return {
                    "source":     source,
                    "skipped":    False,
                    "error":      False,
                    "flagged":    False,
                    "subdomains": partial,
                    "details":    details,
                }
            return _not_found_result(source, f"Scan cancelled — no subdomains captured for {domain}.")

        # Normal completion — parse output file
        subdomains = _read_sublist3r_output(tmp_path)

        if not subdomains:
            if proc.returncode != 0:
                stderr_snippet = (_stderr or "")[:200].strip()
                return _error_result(
                    source,
                    f"Sublist3r exited with code {proc.returncode}. {stderr_snippet}",
                )
            return _not_found_result(source, f"No subdomains found for {domain}.")

        count   = len(subdomains)
        details: dict = {
            "Domain":           domain,
            "Subdomains Found": count,
            "Brute Force":      "Enabled" if use_brute else "Disabled",
            "Threads":          str(threads),
            "Execution Mode":   mode,
        }
        for i, sub in enumerate(subdomains[:30], 1):
            details[f"  Sub {i:02d}"] = sub
        if count > 30:
            details["..."] = f"(+{count - 30} more — use export)"

        return {
            "source":     source,
            "skipped":    False,
            "error":      False,
            "flagged":    False,
            "subdomains": subdomains,
            "details":    details,
        }

    except OSError as exc:
        return _error_result(source, str(exc))
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Menu
# ---------------------------------------------------------------------------

def handle_subdomain_menu() -> None:
    """Interactive subdomain/ASN intelligence menu."""
    from rich.prompt import Prompt

    while True:
        console.print("\n[bold cyan]Subdomain & ASN Intelligence[/bold cyan]")
        console.print("  [white]1[/white]  Enumerate subdomains — crt.sh")
        console.print("  [white]2[/white]  Enumerate subdomains — HackerTarget")
        console.print("  [white]3[/white]  ASN / IP lookup — BGPView")
        console.print("  [white]4[/white]  IP / Prefix lookup — RIPEstat")
        console.print("  [white]5[/white]  Subdomain lookup — SecurityTrails")
        console.print("  [white]6[/white]  Full subdomain report (crt.sh + HackerTarget + SecurityTrails)")
        console.print("  [white]0[/white]  Back\n")

        choice = Prompt.ask("[bold cyan]Select option[/bold cyan]", default="0").strip()

        if choice == "0":
            break

        elif choice == "1":
            domain = Prompt.ask("[bold cyan]Enter domain[/bold cyan]").strip()
            if not domain:
                console.print("[yellow]Invalid input.[/yellow]")
                continue
            with _spinner(f"Querying crt.sh for {domain}..."):
                result = enumerate_subdomains_crtsh(domain)
            _display_result(result, f"crt.sh: {domain}")

        elif choice == "2":
            domain = Prompt.ask("[bold cyan]Enter domain[/bold cyan]").strip()
            if not domain:
                console.print("[yellow]Invalid input.[/yellow]")
                continue
            with _spinner(f"Querying HackerTarget for {domain}..."):
                result = enumerate_subdomains_hackertarget(domain)
            _display_result(result, f"HackerTarget: {domain}")

        elif choice == "3":
            target = Prompt.ask("[bold cyan]Enter IP or ASN (e.g. 8.8.8.8 or AS15169)[/bold cyan]").strip()
            if not target:
                console.print("[yellow]Invalid input.[/yellow]")
                continue
            with _spinner(f"BGPView lookup: {target}..."):
                result = asn_lookup_bgpview(target)
            _display_result(result, f"BGPView: {target}")

        elif choice == "4":
            target = Prompt.ask("[bold cyan]Enter IP or prefix (e.g. 8.8.8.0/24)[/bold cyan]").strip()
            if not target:
                console.print("[yellow]Invalid input.[/yellow]")
                continue
            with _spinner(f"RIPEstat lookup: {target}..."):
                result = ripestat_lookup(target)
            _display_result(result, f"RIPEstat: {target}")

        elif choice == "5":
            domain = Prompt.ask("[bold cyan]Enter domain[/bold cyan]").strip()
            if not domain:
                console.print("[yellow]Invalid input.[/yellow]")
                continue
            with _spinner(f"Querying SecurityTrails for {domain}..."):
                result = securitytrails_lookup(domain)
            _display_result(result, f"SecurityTrails: {domain}")

        elif choice == "6":
            domain = Prompt.ask("[bold cyan]Enter domain[/bold cyan]").strip()
            if not domain:
                console.print("[yellow]Invalid input.[/yellow]")
                continue

            console.print(f"\n[cyan]Running full subdomain report for:[/cyan] {domain}\n")
            all_subdomains: set[str] = set()
            results: dict = {}

            with ThreadPoolExecutor(max_workers=3) as executor:
                futures = {
                    executor.submit(enumerate_subdomains_crtsh,        domain): "crt.sh",
                    executor.submit(enumerate_subdomains_hackertarget,  domain): "HackerTarget",
                    executor.submit(securitytrails_lookup,              domain): "SecurityTrails",
                }
                for future in as_completed(futures):
                    name = futures[future]
                    try:
                        res = future.result()
                        results[name] = res
                        if not res.get("skipped") and not res.get("error"):
                            all_subdomains.update(res.get("subdomains", []))
                    except Exception as exc:
                        results[name] = _error_result(name, str(exc))

            print_section_header(f"Subdomain Report: {domain}")
            for name, result in results.items():
                _display_result(result, name)

            merged = sorted(all_subdomains)
            console.print(f"\n[bold green]Total unique subdomains across all sources:[/bold green] {len(merged)}\n")

            if merged:
                export = Prompt.ask(
                    "[bold cyan]Export to TXT file? (Enter filename or leave blank to skip)[/bold cyan]",
                    default=""
                ).strip()
                if export:
                    try:
                        with open(export, "w") as f:
                            f.write(f"# Subdomain report for {domain}\n")
                            f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                            f.write(f"# Total: {len(merged)}\n\n")
                            for sub in merged:
                                f.write(sub + "\n")
                        console.print(f"[bold green]Exported {len(merged)} subdomains to:[/bold green] {export}")
                    except OSError as exc:
                        console.print(f"[bold red]Export failed:[/bold red] {exc}")
        else:
            console.print("[yellow]Invalid option.[/yellow]")


def _display_result(result: dict, title: str) -> None:
    if result.get("skipped"):
        reason = result.get("details", {}).get("reason", "No API key")
        console.print(f"  [dim]○ {title}: SKIPPED — {reason}[/dim]\n")
        return
    if result.get("error"):
        err = result.get("details", {}).get("Error", "Unknown error")
        console.print(f"  [bold red]✗ {title}: ERROR — {err}[/bold red]\n")
        return
    print_result_table(result, title)


def _spinner(message: str):
    from rich.progress import Progress, SpinnerColumn, TextColumn
    return Progress(SpinnerColumn(), TextColumn(f"[cyan]{message}"), transient=True, console=console)
