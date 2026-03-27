"""
threat_feeds.py — Abuse.ch threat feed lookups: URLhaus, ThreatFox, Feodo, SSLBL.

Each function:
  - Returns a structured dict: source, skipped, error, flagged, details.
  - Never raises exceptions to the caller.
"""

from __future__ import annotations

import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import CONFIG  # noqa: E402

from modules.utils import console, print_result_table, print_section_header

REQUEST_TIMEOUT = 15

# Module-level Feodo tracker cache
_FEODO_CACHE: Optional[dict] = None

# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _skipped_result(source: str, reason: str = "Not applicable") -> dict:
    return {"source": source, "skipped": True, "error": False, "flagged": False, "details": {"reason": reason}}


def _error_result(source: str, message: str) -> dict:
    return {"source": source, "skipped": False, "error": True, "flagged": False, "details": {"Error": message}}


def _not_found_result(source: str, message: str) -> dict:
    return {"source": source, "skipped": False, "error": False, "flagged": False, "details": {"Status": message}}


# ---------------------------------------------------------------------------
# 1. URLhaus
# ---------------------------------------------------------------------------

def check_urlhaus(ioc: str) -> dict:
    """
    Query URLhaus for a URL, domain, or IP address.

    Args:
        ioc: URL, domain, or IP address to look up.

    Returns:
        Structured result dict with URLhaus threat data.
    """
    source = "URLhaus"
    ioc    = ioc.strip()

    # Determine query type
    if ioc.startswith("http://") or ioc.startswith("https://"):
        data_key  = "url"
        query_key = "url"
    else:
        data_key  = "host"
        query_key = "host"

    try:
        resp = requests.post(
            "https://urlhaus-api.abuse.ch/v1/",
            data={f"query": f"lookup_{query_key}", data_key: ioc},
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()

        query_status = data.get("query_status", "")

        if query_status in ("no_results", "invalid_url", "invalid_host"):
            return _not_found_result(source, f"Not found in URLhaus: {ioc}")

        urls_listed = data.get("urls", []) or []
        count       = len(urls_listed)

        if count == 0 and query_status != "is_host":
            return _not_found_result(source, f"No URLhaus entries for {ioc}.")

        # Host-level query
        if query_key == "host":
            blacklisted = data.get("blacklists", {})
            details: dict = {
                "IOC":             ioc,
                "Query Status":    query_status,
                "URLs Listed":     count,
                "SURBL":           blacklisted.get("surbl", "not listed"),
                "SPAMHAUS DBL":    blacklisted.get("spamhaus_dbl", "not listed"),
            }
            for i, u in enumerate(urls_listed[:5], 1):
                threat = u.get("threat", "")
                url_s  = u.get("url", "")[:80]
                status = u.get("url_status", "")
                details[f"  URL {i}"] = f"[{status}] {threat}: {url_s}"

            flagged = count > 0
        else:
            # URL-level query
            threat     = data.get("threat", "")
            url_status = data.get("url_status", "")
            tags       = ", ".join(data.get("tags") or [])

            details = {
                "IOC":         ioc,
                "Status":      url_status,
                "Threat":      threat,
                "Tags":        tags,
                "Date Added":  data.get("date_added", ""),
                "Reporter":    data.get("reporter", ""),
                "URL Count":   count,
            }

            payloads = data.get("payloads") or []
            for i, p in enumerate(payloads[:3], 1):
                md5  = p.get("response_md5", "")
                ftype = p.get("file_type", "")
                details[f"  Payload {i}"] = f"{ftype}: {md5}"

            flagged = url_status == "online" or bool(threat)

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
# 2. ThreatFox
# ---------------------------------------------------------------------------

def check_threatfox_ioc(ioc: str) -> dict:
    """
    Query ThreatFox for an IP address, domain, or URL IOC.

    Args:
        ioc: IP, domain, or URL to look up.

    Returns:
        Structured result dict with ThreatFox threat intelligence.
    """
    source = "ThreatFox"
    ioc    = ioc.strip()

    try:
        resp = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "search_ioc", "search_term": ioc},
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()

        query_status = data.get("query_status", "")

        if query_status == "no_result":
            return _not_found_result(source, f"Not found in ThreatFox: {ioc}")

        if query_status != "ok":
            return _error_result(source, f"ThreatFox error: {query_status}")

        ioc_list = data.get("data", []) or []
        count    = len(ioc_list)

        if count == 0:
            return _not_found_result(source, f"No ThreatFox entries for {ioc}.")

        first = ioc_list[0]
        malware      = first.get("malware", "")
        malware_alias = first.get("malware_alias", "")
        ioc_type     = first.get("ioc_type", "")
        confidence   = first.get("confidence_level", "")
        threat_type  = first.get("threat_type", "")
        first_seen   = first.get("first_seen", "")
        last_seen    = first.get("last_seen", "")
        reporter     = first.get("reporter", "")
        tags         = ", ".join(first.get("tags") or [])

        details: dict = {
            "IOC":            ioc,
            "IOC Type":       ioc_type,
            "Entries Found":  count,
            "Malware":        malware,
            "Malware Alias":  malware_alias,
            "Threat Type":    threat_type,
            "Confidence":     str(confidence),
            "First Seen":     first_seen,
            "Last Seen":      last_seen,
            "Reporter":       reporter,
            "Tags":           tags,
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
# 3. Feodo Tracker C2 blocklist
# ---------------------------------------------------------------------------

def check_feodo_tracker(ip: str) -> dict:
    """
    Check if an IP is in the Feodo Tracker C2 blocklist.

    Downloads and caches the JSON blocklist at module level.

    Args:
        ip: IP address to check.

    Returns:
        Structured result dict indicating C2 status.
    """
    global _FEODO_CACHE
    source = "Feodo Tracker"
    ip     = ip.strip()

    try:
        if _FEODO_CACHE is None:
            resp = requests.get(
                "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
                timeout=REQUEST_TIMEOUT,
            )
            resp.raise_for_status()
            _FEODO_CACHE = resp.json()

        blocklist = _FEODO_CACHE if isinstance(_FEODO_CACHE, list) else _FEODO_CACHE.get("blocklist", [])
        match     = next((entry for entry in blocklist if entry.get("ip_address") == ip), None)

        if match is None:
            return _not_found_result(source, f"{ip} is NOT in Feodo C2 blocklist.")

        details: dict = {
            "IP Address":    ip,
            "In Feodo C2":   "YES — active C2 server",
            "Malware":       match.get("malware", ""),
            "Status":        match.get("status", ""),
            "Country":       match.get("country", ""),
            "Hostname":      match.get("hostname", ""),
            "AS Number":     str(match.get("as_number", "")),
            "AS Name":       match.get("as_name", ""),
            "First Seen":    match.get("first_seen", ""),
            "Last Online":   match.get("last_online", ""),
            "Port":          str(match.get("port", "")),
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
# 4. SSL Blacklist (SSLBL)
# ---------------------------------------------------------------------------

def check_ssl_blacklist(fingerprint_or_ja3: str) -> dict:
    """
    Look up an SSL certificate fingerprint or JA3 hash in the Abuse.ch SSLBL.

    Args:
        fingerprint_or_ja3: SHA1 certificate fingerprint or JA3 hash string.

    Returns:
        Structured result dict with blacklist status.
    """
    source = "SSLBL (Abuse.ch)"
    value  = fingerprint_or_ja3.strip().lower().replace(":", "")

    # Determine if fingerprint (40 hex chars) or JA3 (32 hex chars)
    if len(value) == 40:
        query_type = "sslsha1"
        api_key    = "ssl_sha1"
    elif len(value) == 32:
        query_type = "ja3"
        api_key    = "ja3_hash"
    else:
        return _error_result(source, "Input must be a 40-char SHA1 fingerprint or 32-char JA3 hash.")

    try:
        resp = requests.post(
            "https://sslbl.abuse.ch/api/v1/",
            data={"query": f"lookup_{query_type}", api_key: value},
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()

        query_status = data.get("query_status", "")

        if query_status == "no_results":
            return _not_found_result(source, f"Not found in SSLBL: {fingerprint_or_ja3[:20]}...")

        if query_status != "ok":
            return _error_result(source, f"SSLBL error: {query_status}")

        records = data.get("ssl_certificates", data.get("ja3_hashes", [])) or []
        if not records:
            return _not_found_result(source, "No SSLBL records found.")

        first = records[0]
        details: dict = {
            "Fingerprint / JA3": fingerprint_or_ja3[:40],
            "Listed in SSLBL":   "YES — malicious",
            "Malware":           first.get("subject", first.get("malware", "")),
            "Reason":            first.get("reason", ""),
            "Date Added":        first.get("listingDate", first.get("date_added", "")),
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
# 5. Feed summary
# ---------------------------------------------------------------------------

def get_feed_summary() -> dict:
    """
    Retrieve statistics from the main abuse.ch threat feeds.

    Returns:
        Structured result dict with counts from each feed.
    """
    source = "Abuse.ch Feed Summary"

    try:
        stats: dict = {}

        # URLhaus stats
        try:
            r = requests.post(
                "https://urlhaus-api.abuse.ch/v1/",
                data={"query": "get_stats"},
                timeout=REQUEST_TIMEOUT,
            )
            r.raise_for_status()
            d = r.json()
            stats["URLhaus URLs Online"]   = d.get("urls_online", "N/A")
            stats["URLhaus URLs Total"]    = d.get("urls_total", "N/A")
            stats["URLhaus Payloads Total"]= d.get("payloads_total", "N/A")
        except Exception:
            stats["URLhaus"] = "unavailable"

        # ThreatFox stats
        try:
            r2 = requests.post(
                "https://threatfox-api.abuse.ch/api/v1/",
                json={"query": "get_iocs", "days": 1},
                timeout=REQUEST_TIMEOUT,
            )
            r2.raise_for_status()
            d2 = r2.json()
            iocs = d2.get("data") or []
            stats["ThreatFox IOCs (24h)"] = len(iocs)
        except Exception:
            stats["ThreatFox"] = "unavailable"

        # Feodo stats
        try:
            r3 = requests.get(
                "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
                timeout=REQUEST_TIMEOUT,
            )
            r3.raise_for_status()
            bl = r3.json()
            bl_list = bl if isinstance(bl, list) else bl.get("blocklist", [])
            online  = sum(1 for e in bl_list if e.get("status") == "Online")
            stats["Feodo C2 Total"]  = len(bl_list)
            stats["Feodo C2 Online"] = online
        except Exception:
            stats["Feodo Tracker"] = "unavailable"

        return {
            "source":  source,
            "skipped": False,
            "error":   False,
            "flagged": False,
            "details": stats,
        }

    except Exception as exc:
        return _error_result(source, str(exc))


# ---------------------------------------------------------------------------
# Menu
# ---------------------------------------------------------------------------

def handle_feeds_menu() -> None:
    """Interactive threat feeds menu."""
    from rich import box
    from rich.panel import Panel
    from rich.prompt import Prompt
    from rich.text import Text

    while True:
        console.print("\n[bold cyan]Threat Feeds (Abuse.ch)[/bold cyan]")
        console.print("  [white]1[/white]  URLhaus lookup (URL/domain/IP)")
        console.print("  [white]2[/white]  ThreatFox IOC lookup")
        console.print("  [white]3[/white]  Feodo Tracker C2 check (IP)")
        console.print("  [white]4[/white]  SSLBL lookup (fingerprint/JA3)")
        console.print("  [white]5[/white]  Live feed summary / threat landscape")
        console.print("  [white]0[/white]  Back\n")

        choice = Prompt.ask("[bold cyan]Select option[/bold cyan]", default="0").strip()

        if choice == "0":
            break

        elif choice == "1":
            ioc = Prompt.ask("[bold cyan]Enter URL, domain, or IP[/bold cyan]").strip()
            if not ioc:
                console.print("[yellow]Invalid input.[/yellow]")
                continue
            with _spinner(f"Querying URLhaus for {ioc}..."):
                result = check_urlhaus(ioc)
            _display_result(result, f"URLhaus: {ioc[:50]}")

        elif choice == "2":
            ioc = Prompt.ask("[bold cyan]Enter IP, domain, or URL[/bold cyan]").strip()
            if not ioc:
                console.print("[yellow]Invalid input.[/yellow]")
                continue
            with _spinner(f"Querying ThreatFox for {ioc}..."):
                result = check_threatfox_ioc(ioc)
            _display_result(result, f"ThreatFox: {ioc[:50]}")

        elif choice == "3":
            ip = Prompt.ask("[bold cyan]Enter IP address[/bold cyan]").strip()
            if not ip:
                console.print("[yellow]Invalid input.[/yellow]")
                continue
            with _spinner(f"Checking Feodo Tracker for {ip}..."):
                result = check_feodo_tracker(ip)
            _display_result(result, f"Feodo Tracker: {ip}")

        elif choice == "4":
            fp = Prompt.ask("[bold cyan]Enter SHA1 fingerprint or JA3 hash[/bold cyan]").strip()
            if not fp:
                console.print("[yellow]Invalid input.[/yellow]")
                continue
            with _spinner(f"Checking SSLBL for {fp[:20]}..."):
                result = check_ssl_blacklist(fp)
            _display_result(result, f"SSLBL: {fp[:20]}...")

        elif choice == "5":
            console.print("\n[cyan]Fetching live threat feed statistics...[/cyan]\n")

            with ThreadPoolExecutor(max_workers=3) as executor:
                future = executor.submit(get_feed_summary)
                try:
                    result = future.result(timeout=REQUEST_TIMEOUT + 5)
                except Exception as exc:
                    result = _error_result("Feed Summary", str(exc))

            if not result.get("error") and not result.get("skipped"):
                details = result.get("details", {})
                lines   = [f"[white]{k}:[/white] [bold cyan]{v}[/bold cyan]" for k, v in details.items()]
                panel_content = "\n".join(lines)
                console.print(
                    Panel(
                        panel_content,
                        title="[bold cyan]Live Threat Landscape (Abuse.ch)[/bold cyan]",
                        box=box.ROUNDED,
                        border_style="cyan",
                        padding=(1, 2),
                    )
                )
            else:
                _display_result(result, "Feed Summary")

        else:
            console.print("[yellow]Invalid option.[/yellow]")


def _display_result(result: dict, title: str) -> None:
    if result.get("skipped"):
        reason = result.get("details", {}).get("reason", "Not applicable")
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
