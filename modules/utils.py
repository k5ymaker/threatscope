"""
utils.py — Input validation, output formatting, and risk aggregation helpers.


All public helpers are importable independently so individual modules or a
future CLI / web wrapper can reuse them without pulling in the full app.
"""

from __future__ import annotations

import re
import ipaddress
from urllib.parse import urlparse
from typing import Any

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

# Single shared console instance used across the application
console = Console()

# Re-export urlparse so main.py can import it from utils without an extra import
__all__ = [
    "console",
    "urlparse",
    "validate_url",
    "validate_ip",
    "validate_domain",
    "detect_input_type",
    "print_result_table",
    "print_section_header",
    "print_skipped",
    "aggregate_risk_score",
    "verdict_style",
]


# ---------------------------------------------------------------------------
# Input Validation
# ---------------------------------------------------------------------------

def validate_url(input_str: str) -> bool:
    """Return True if input_str is a valid http/https URL with a netloc."""
    try:
        parsed = urlparse(input_str.strip())
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except Exception:
        return False


def validate_ip(input_str: str) -> bool:
    """Return True if input_str is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(input_str.strip())
        return True
    except ValueError:
        return False


def validate_domain(input_str: str) -> bool:
    """
    Return True if input_str looks like a valid domain name.

    Accepts labels of letters, digits, and hyphens separated by dots,
    with a TLD of at least two characters.
    """
    pattern = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
        r"+[a-zA-Z]{2,}$"
    )
    return bool(pattern.match(input_str.strip()))


def detect_input_type(input_str: str) -> str:
    """
    Detect whether the input is a URL, IP, domain, or unknown.

    Returns:
        One of ``"url"``, ``"ip"``, ``"domain"``, or ``"unknown"``.
    """
    s = input_str.strip()
    if validate_url(s):
        return "url"
    if validate_ip(s):
        return "ip"
    if validate_domain(s):
        return "domain"
    return "unknown"


# ---------------------------------------------------------------------------
# Output Formatting
# ---------------------------------------------------------------------------

def _risk_colour(value: Any) -> str:
    """Derive a rich markup colour string from the value's risk-level semantics."""
    v = str(value).lower()
    if any(x in v for x in (
        "malicious", "critical", "high", "phishing", "listed",
        "true", "yes", "infected", "compromised",
    )):
        return "bold red"
    if any(x in v for x in (
        "suspicious", "medium", "unknown", "unrated", "moderate",
    )):
        return "yellow"
    if any(x in v for x in (
        "clean", "low", "benign", "harmless", "no", "not listed",
        "false", "safe",
    )):
        return "green"
    return "white"


def print_result_table(data: dict | None, title: str = "Result") -> None:
    """
    Display a dict as a colour-coded rich Table.

    Args:
        data:  Key-value pairs to display. Nested dicts are flattened one level.
        title: Table title string.
    """
    if not data:
        console.print(f"  [dim]No data returned for: {title}[/dim]\n")
        return

    # If a result dict contains a nested 'details' dict, surface it
    if isinstance(data, dict) and "details" in data and isinstance(data["details"], dict):
        display_data = data["details"]
        # Also show top-level flags that callers might want to see
        for k in ("flagged", "risk_score", "skipped", "error"):
            if k in data and k not in display_data:
                display_data[k] = data[k]
    else:
        display_data = data

    table = Table(
        title=title,
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
        title_style="bold white",
        expand=False,
        show_lines=True,
    )
    table.add_column("Field", style="bold white", no_wrap=True, min_width=26)
    table.add_column("Value", min_width=44)

    for key, value in display_data.items():
        if value is None or value == "" or value == []:
            table.add_row(str(key), "[dim]N/A[/dim]")
            continue

        # Lists → one line per item so every entry is visible
        if isinstance(value, list):
            display = "\n".join(str(item) for item in value) if value else "None"
        else:
            display = str(value)

        colour = _risk_colour(display)
        table.add_row(str(key), f"[{colour}]{display}[/{colour}]")

    console.print(table)
    console.print()


def print_section_header(title: str) -> None:
    """Print a bold cyan section-divider panel."""
    console.print(
        Panel(
            Text(title, style="bold cyan", justify="center"),
            box=box.HEAVY,
            border_style="cyan",
            padding=(0, 2),
        )
    )


def print_skipped(source: str) -> None:
    """Print a dim 'SKIPPED' notice for APIs with no key configured."""
    console.print(f"  [dim]○ {source}: SKIPPED — no API key configured[/dim]")


# ---------------------------------------------------------------------------
# Risk Aggregation
# ---------------------------------------------------------------------------

def aggregate_risk_score(results: list[dict]) -> dict:
    """
    Calculate an overall risk verdict from a list of API result dicts.

    Each result dict should contain:
        - ``source``     (str)            : name of the API
        - ``flagged``    (bool)           : True if this source considers the IOC malicious
        - ``skipped``    (bool)           : True if the API was skipped (no key)
        - ``error``      (bool, optional) : True if the call errored out
        - ``risk_score`` (int|float|None) : 0–100 normalised score if available

    Returns:
        dict with keys: ``verdict``, ``flagged_by``, ``clean_sources``,
        ``skipped_sources``, ``confidence`` (%), ``summary``.
    """
    flagged_by: list[str] = []
    clean_sources: list[str] = []
    skipped_sources: list[str] = []
    scores: list[float] = []

    for r in results:
        source = r.get("source", "Unknown")
        if r.get("skipped"):
            skipped_sources.append(source)
            continue
        if r.get("error"):
            skipped_sources.append(f"{source} (error)")
            continue

        if r.get("flagged", False):
            flagged_by.append(source)
        else:
            clean_sources.append(source)

        rs = r.get("risk_score")
        if rs is not None:
            try:
                scores.append(float(rs))
            except (TypeError, ValueError):
                pass

    total_active = len(flagged_by) + len(clean_sources)

    if total_active == 0:
        verdict = "UNKNOWN"
        confidence = 0
    else:
        ratio = len(flagged_by) / total_active
        avg_score = (sum(scores) / len(scores)) if scores else (ratio * 100)

        if ratio == 0 and avg_score < 15:
            verdict = "CLEAN"
        elif ratio < 0.25 or avg_score < 25:
            verdict = "LOW"
        elif ratio < 0.5 or avg_score < 50:
            verdict = "MEDIUM"
        elif ratio < 0.75 or avg_score < 75:
            verdict = "HIGH"
        else:
            verdict = "CRITICAL"

        confidence = round(ratio * 100)

    parts: list[str] = []
    if flagged_by:
        parts.append(f"Flagged by {len(flagged_by)} source(s): {', '.join(flagged_by)}.")
    if clean_sources:
        parts.append(f"Clean on {len(clean_sources)} source(s): {', '.join(clean_sources)}.")
    if skipped_sources:
        parts.append(f"Skipped/error: {', '.join(skipped_sources)}.")

    return {
        "verdict":         verdict,
        "flagged_by":      flagged_by,
        "clean_sources":   clean_sources,
        "skipped_sources": skipped_sources,
        "confidence":      confidence,
        "summary":         " ".join(parts) if parts else "No data collected.",
    }


def verdict_style(verdict: str) -> str:
    """Return the rich style string for a given verdict label."""
    mapping = {
        "CLEAN":    "bold green",
        "LOW":      "bold yellow",
        "MEDIUM":   "bold yellow",
        "HIGH":     "bold red",
        "CRITICAL": "bold red on white",
        "UNKNOWN":  "dim",
    }
    return mapping.get(verdict.upper(), "white")
