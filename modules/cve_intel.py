"""
cve_intel.py — CVE lookup, CISA KEV tracking, ExploitDB search, and vulnerability intelligence.

Each function:
  - Returns a structured dict: source, skipped, error, flagged, details.
  - Never raises exceptions to the caller.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from typing import Optional

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import CONFIG  # noqa: E402

from modules.utils import console, print_result_table, print_section_header

REQUEST_TIMEOUT = 15

# Module-level CISA KEV cache
_CISA_KEV_CACHE: Optional[dict] = None

# CVE ID validation pattern
_CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _skipped_result(source: str, reason: str = "No API key configured") -> dict:
    return {"source": source, "skipped": True, "error": False, "flagged": False, "details": {"reason": reason}}


def _error_result(source: str, message: str) -> dict:
    return {"source": source, "skipped": False, "error": True, "flagged": False, "details": {"Error": message}}


def _not_found_result(source: str, message: str) -> dict:
    return {"source": source, "skipped": False, "error": False, "flagged": False, "details": {"Status": message}}


def _validate_cve(cve_id: str) -> bool:
    return bool(_CVE_PATTERN.match(cve_id.strip()))


# ---------------------------------------------------------------------------
# 1. NVD NIST CVE v2.0
# ---------------------------------------------------------------------------

def lookup_nvd(cve_id: str) -> dict:
    """
    Query NVD NIST API v2.0 for CVE details and CVSS scores.

    Args:
        cve_id: CVE identifier (e.g. CVE-2021-44228).

    Returns:
        Structured result dict with severity and vulnerability details.
    """
    source = "NVD (NIST)"
    cve_id = cve_id.strip().upper()

    if not _validate_cve(cve_id):
        return _error_result(source, f"Invalid CVE format: {cve_id}. Expected CVE-YYYY-NNNNN.")

    headers: dict = {"Accept": "application/json"}
    key = CONFIG.get("nvd")
    if key:
        headers["apiKey"] = key

    try:
        resp = requests.get(
            f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}",
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        )

        if resp.status_code == 404:
            return _not_found_result(source, f"{cve_id} not found in NVD.")

        if resp.status_code == 403:
            return _error_result(source, "NVD API key invalid or rate-limited.")

        resp.raise_for_status()
        data = resp.json()

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return _not_found_result(source, f"{cve_id} returned no vulnerability data.")

        vuln  = vulns[0].get("cve", {})
        descs = vuln.get("descriptions", [])
        desc  = next((d["value"] for d in descs if d.get("lang") == "en"), "No description")

        # Published / modified dates
        published = vuln.get("published", "")[:10]
        modified  = vuln.get("lastModified", "")[:10]

        # CVSS scoring: prefer v3.1 > v3.0 > v2
        metrics   = vuln.get("metrics", {})
        cvss_score: Optional[float] = None
        cvss_ver   = "N/A"
        severity   = "N/A"
        vector     = "N/A"

        for ver_key, ver_label in [("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")]:
            metric_list = metrics.get(ver_key, [])
            if metric_list:
                m          = metric_list[0]
                cvss_data  = m.get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                severity   = cvss_data.get("baseSeverity", m.get("baseSeverity", "N/A"))
                vector     = cvss_data.get("vectorString", "N/A")
                cvss_ver   = ver_label
                break

        # CWE
        weaknesses = vuln.get("weaknesses", [])
        cwes = []
        for w in weaknesses:
            for wd in w.get("description", []):
                if wd.get("lang") == "en":
                    cwes.append(wd.get("value", ""))

        # References
        refs     = vuln.get("references", [])
        ref_urls = [r.get("url", "") for r in refs[:3]]

        flagged = bool(cvss_score and cvss_score >= 7.0)

        details: dict = {
            "CVE ID":           cve_id,
            "Published":        published,
            "Last Modified":    modified,
            "CVSS Version":     cvss_ver,
            "CVSS Score":       str(cvss_score) if cvss_score is not None else "N/A",
            "Severity":         severity,
            "Vector":           vector,
            "CWE":              ", ".join(cwes) if cwes else "N/A",
            "Description":      desc[:300] + ("..." if len(desc) > 300 else ""),
        }
        for i, url in enumerate(ref_urls, 1):
            details[f"Reference {i}"] = url

        return {
            "source":  source,
            "skipped": False,
            "error":   False,
            "flagged": flagged,
            "details": details,
        }

    except requests.exceptions.RequestException as exc:
        return _error_result(source, str(exc))


# ---------------------------------------------------------------------------
# 2. CISA KEV
# ---------------------------------------------------------------------------

def check_cisa_kev(cve_id: str) -> dict:
    """
    Check if a CVE is in the CISA Known Exploited Vulnerabilities catalog.

    Uses a module-level cache to avoid repeated downloads.

    Args:
        cve_id: CVE identifier.

    Returns:
        Structured result dict indicating if CVE is in CISA KEV.
    """
    global _CISA_KEV_CACHE
    source = "CISA KEV"
    cve_id = cve_id.strip().upper()

    if not _validate_cve(cve_id):
        return _error_result(source, f"Invalid CVE format: {cve_id}.")

    try:
        if _CISA_KEV_CACHE is None:
            resp = requests.get(
                "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                timeout=REQUEST_TIMEOUT,
            )
            resp.raise_for_status()
            _CISA_KEV_CACHE = resp.json()

        vulnerabilities = _CISA_KEV_CACHE.get("vulnerabilities", [])
        match = next((v for v in vulnerabilities if v.get("cveID", "").upper() == cve_id), None)

        if match is None:
            return _not_found_result(source, f"{cve_id} is NOT in CISA KEV catalog.")

        details: dict = {
            "CVE ID":             cve_id,
            "In CISA KEV":        "YES — actively exploited",
            "Vendor/Project":     match.get("vendorProject", ""),
            "Product":            match.get("product", ""),
            "Vulnerability Name": match.get("vulnerabilityName", ""),
            "Date Added":         match.get("dateAdded", ""),
            "Due Date":           match.get("dueDate", ""),
            "Required Action":    match.get("requiredAction", "")[:200],
            "Short Description":  match.get("shortDescription", "")[:200],
        }

        return {
            "source":  source,
            "skipped": False,
            "error":   False,
            "flagged": True,
            "details": details,
        }

    except requests.exceptions.RequestException as exc:
        return _error_result(source, str(exc))


# ---------------------------------------------------------------------------
# 3. ExploitDB / searchsploit
# ---------------------------------------------------------------------------

def search_exploitdb(cve_id: str) -> dict:
    """
    Search local ExploitDB via searchsploit binary for a CVE.

    Args:
        cve_id: CVE identifier.

    Returns:
        Structured result dict with exploit entries found.
    """
    source = "ExploitDB (searchsploit)"

    if not shutil.which("searchsploit"):
        return _skipped_result(source, "searchsploit not installed. See: apt install exploitdb")

    cve_id = cve_id.strip().upper()

    try:
        result = subprocess.run(
            ["searchsploit", "--cve", cve_id, "--json"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        output = result.stdout.strip()
        if not output:
            # Fallback: text search
            result2 = subprocess.run(
                ["searchsploit", cve_id],
                capture_output=True,
                text=True,
                timeout=30,
            )
            lines = [ln for ln in result2.stdout.splitlines() if cve_id.lower() in ln.lower() or "Exploit" in ln]
            if not lines:
                return _not_found_result(source, f"No exploits found for {cve_id}.")

            details: dict = {"CVE ID": cve_id, "Exploits Found": len(lines)}
            for i, line in enumerate(lines[:10], 1):
                details[f"  Exploit {i:02d}"] = line.strip()[:120]
            return {
                "source":  source,
                "skipped": False,
                "error":   False,
                "flagged": True,
                "details": details,
            }

        try:
            data    = __import__("json").loads(output)
            exploits = data.get("RESULTS_EXPLOIT", []) + data.get("RESULTS_SHELLCODE", [])
        except Exception:
            exploits = []

        if not exploits:
            return _not_found_result(source, f"No exploits found for {cve_id}.")

        details = {"CVE ID": cve_id, "Exploits Found": len(exploits)}
        for i, exp in enumerate(exploits[:10], 1):
            title = exp.get("Title", "Unknown")
            path  = exp.get("Path", "")
            etype = exp.get("Type", "")
            details[f"  Exploit {i:02d}"] = f"{title} [{etype}] {path}"

        return {
            "source":  source,
            "skipped": False,
            "error":   False,
            "flagged": True,
            "details": details,
        }

    except subprocess.TimeoutExpired:
        return _error_result(source, "searchsploit timed out.")
    except FileNotFoundError:
        return _skipped_result(source, "searchsploit binary not found.")
    except Exception as exc:
        return _error_result(source, str(exc))


# ---------------------------------------------------------------------------
# 4. Vulners
# ---------------------------------------------------------------------------

def search_vulners(cve_id: str) -> dict:
    """
    Query Vulners for CVE details, EPSS score, and exploit availability.

    Args:
        cve_id: CVE identifier.

    Returns:
        Structured result dict with Vulners intelligence.
    """
    source = "Vulners"
    key    = CONFIG.get("vulners")
    if not key:
        return _skipped_result(source)

    cve_id = cve_id.strip().upper()

    try:
        resp = requests.post(
            "https://vulners.com/api/v3/search/id/",
            json={"id": cve_id, "apiKey": key},
            timeout=REQUEST_TIMEOUT,
        )

        if resp.status_code in (401, 403):
            return _error_result(source, "Invalid Vulners API key.")

        resp.raise_for_status()
        data = resp.json()

        if data.get("result") != "OK":
            return _not_found_result(source, data.get("data", {}).get("error", f"{cve_id} not found."))

        doc = data.get("data", {}).get("documents", {}).get(cve_id, {})
        if not doc:
            return _not_found_result(source, f"{cve_id} not found in Vulners.")

        cvss    = doc.get("cvss", {})
        score   = cvss.get("score", "N/A")
        epss    = doc.get("epss", [{}])
        epss_v  = epss[0].get("epss", "N/A") if epss else "N/A"
        exploit_count = len(doc.get("references", []))

        details: dict = {
            "CVE ID":       cve_id,
            "CVSS Score":   str(score),
            "EPSS Score":   str(epss_v),
            "Exploit Refs": str(exploit_count),
            "Description":  (doc.get("description", "")[:300]),
            "Published":    doc.get("published", "")[:10],
            "Modified":     doc.get("modified", "")[:10],
        }

        flagged = (isinstance(score, (int, float)) and score >= 7.0) or exploit_count > 0

        return {
            "source":  source,
            "skipped": False,
            "error":   False,
            "flagged": bool(flagged),
            "details": details,
        }

    except requests.exceptions.RequestException as exc:
        return _error_result(source, str(exc))


# ---------------------------------------------------------------------------
# Menu
# ---------------------------------------------------------------------------

def handle_cve_menu() -> None:
    """Interactive CVE intelligence menu."""
    from rich import box
    from rich.prompt import Prompt
    from rich.table import Table

    while True:
        console.print("\n[bold cyan]CVE Intelligence[/bold cyan]")
        console.print("  [white]1[/white]  NVD lookup (NIST)")
        console.print("  [white]2[/white]  CISA KEV check")
        console.print("  [white]3[/white]  ExploitDB search (searchsploit)")
        console.print("  [white]4[/white]  Vulners intelligence")
        console.print("  [white]5[/white]  Full CVE report (all sources)")
        console.print("  [white]6[/white]  Latest CISA KEV additions")
        console.print("  [white]0[/white]  Back\n")

        choice = Prompt.ask("[bold cyan]Select option[/bold cyan]", default="0").strip()

        if choice == "0":
            break

        elif choice in ("1", "2", "3", "4", "5"):
            cve_id = Prompt.ask("[bold cyan]Enter CVE ID (e.g. CVE-2021-44228)[/bold cyan]").strip().upper()
            if not _validate_cve(cve_id):
                console.print("[yellow]Invalid CVE format. Expected CVE-YYYY-NNNNN.[/yellow]")
                continue

            if choice == "1":
                with _spinner(f"Querying NVD for {cve_id}..."):
                    result = lookup_nvd(cve_id)
                _display_result(result, f"NVD: {cve_id}")

            elif choice == "2":
                with _spinner(f"Checking CISA KEV for {cve_id}..."):
                    result = check_cisa_kev(cve_id)
                _display_result(result, f"CISA KEV: {cve_id}")

            elif choice == "3":
                with _spinner(f"Searching ExploitDB for {cve_id}..."):
                    result = search_exploitdb(cve_id)
                _display_result(result, f"ExploitDB: {cve_id}")

            elif choice == "4":
                with _spinner(f"Querying Vulners for {cve_id}..."):
                    result = search_vulners(cve_id)
                _display_result(result, f"Vulners: {cve_id}")

            elif choice == "5":
                console.print(f"\n[cyan]Running full CVE intelligence for:[/cyan] {cve_id}\n")
                from concurrent.futures import ThreadPoolExecutor, as_completed
                results: dict = {}

                with ThreadPoolExecutor(max_workers=4) as executor:
                    futures = {
                        executor.submit(lookup_nvd,       cve_id): "NVD",
                        executor.submit(check_cisa_kev,   cve_id): "CISA KEV",
                        executor.submit(search_exploitdb, cve_id): "ExploitDB",
                        executor.submit(search_vulners,   cve_id): "Vulners",
                    }
                    for future in as_completed(futures):
                        name = futures[future]
                        try:
                            results[name] = future.result()
                        except Exception as exc:
                            results[name] = _error_result(name, str(exc))

                print_section_header(f"CVE Report: {cve_id}")
                for name, result in results.items():
                    _display_result(result, name)

        elif choice == "6":
            _show_latest_kev()

        else:
            console.print("[yellow]Invalid option.[/yellow]")


def _show_latest_kev() -> None:
    """Display the latest 20 CISA KEV additions."""
    from rich import box
    from rich.table import Table

    console.print("[cyan]Fetching CISA KEV catalog...[/cyan]")
    try:
        with _spinner("Loading CISA KEV feed..."):
            resp = requests.get(
                "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                timeout=REQUEST_TIMEOUT,
            )
            resp.raise_for_status()
            data = resp.json()

        vulns = data.get("vulnerabilities", [])
        # Sort by dateAdded descending
        vulns_sorted = sorted(vulns, key=lambda v: v.get("dateAdded", ""), reverse=True)
        latest = vulns_sorted[:20]

        table = Table(
            title="Latest CISA KEV Additions",
            box=box.ROUNDED,
            header_style="bold cyan",
            show_lines=True,
        )
        table.add_column("CVE ID",       style="bold red",  min_width=18)
        table.add_column("Date Added",   min_width=12)
        table.add_column("Vendor",       min_width=18)
        table.add_column("Product",      min_width=18)
        table.add_column("Due Date",     min_width=12)

        for v in latest:
            table.add_row(
                v.get("cveID", ""),
                v.get("dateAdded", ""),
                v.get("vendorProject", "")[:18],
                v.get("product", "")[:18],
                v.get("dueDate", ""),
            )

        console.print(table)
        console.print(f"\n[dim]Total KEV entries: {len(vulns)}[/dim]\n")

    except requests.exceptions.RequestException as exc:
        console.print(f"[bold red]Failed to fetch CISA KEV:[/bold red] {exc}")


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
