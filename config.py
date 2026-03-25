"""
config.py — Centralised API key management for ThreatScope.


Loads keys from config.yaml (same directory), falls back to environment
variables, and exposes a single CONFIG dict used by all modules.

On startup, call display_api_status() to show which APIs are ACTIVE vs SKIPPED.
"""

from __future__ import annotations

import os
from pathlib import Path

import yaml
from rich.console import Console
from rich.table import Table

console = Console()

# Path to config.yaml (same directory as this file)
_CONFIG_PATH = Path(__file__).parent / "config.yaml"

# Mapping: config_key -> environment variable name (fallback)
_ENV_VAR_MAP: dict[str, str] = {
    "virustotal":         "VT_API_KEY",
    "phishtank":          "PHISHTANK_API_KEY",
    "google_safe_browsing": "GSB_API_KEY",
    "urlscan":            "URLSCAN_API_KEY",
    "apivoid":            "APIVOID_API_KEY",
    "shodan":             "SHODAN_API_KEY",
    "greynoise":          "GREYNOISE_API_KEY",
    "alienvault_otx":     "OTX_API_KEY",
    "ipinfo":             "IPINFO_API_KEY",
    "abstractapi_ip":     "ABSTRACTAPI_KEY",
    "abuseipdb":          "ABUSEIPDB_API_KEY",
}

_API_LABELS: dict[str, str] = {
    "virustotal":           "VirusTotal",
    "phishtank":            "PhishTank",
    "google_safe_browsing": "Google Safe Browsing",
    "urlscan":              "URLScan.io",
    "apivoid":              "APIVoid",
    "shodan":               "Shodan",
    "greynoise":            "GreyNoise",
    "alienvault_otx":       "AlienVault OTX",
    "ipinfo":               "IPInfo",
    "abstractapi_ip":       "AbstractAPI (IP)",
    "abuseipdb":            "AbuseIPDB",
}


def _load_config() -> dict[str, str | None]:
    """Load API keys from config.yaml and fall back to environment variables."""
    yaml_keys: dict = {}
    if _CONFIG_PATH.exists():
        try:
            with open(_CONFIG_PATH, "r") as fh:
                data = yaml.safe_load(fh) or {}
            yaml_keys = data.get("api_keys", {}) or {}
        except Exception:
            yaml_keys = {}

    resolved: dict[str, str | None] = {}
    for key, env_var in _ENV_VAR_MAP.items():
        yaml_val = (yaml_keys.get(key) or "").strip()
        env_val = os.environ.get(env_var, "").strip()
        if yaml_val:
            resolved[key] = yaml_val
        elif env_val:
            resolved[key] = env_val
        else:
            resolved[key] = None  # explicitly absent — APIs will skip gracefully
    return resolved


def display_api_status() -> None:
    """Print a table showing ACTIVE / SKIPPED status for every configured API."""
    yaml_keys: dict = {}
    if _CONFIG_PATH.exists():
        try:
            with open(_CONFIG_PATH, "r") as fh:
                data = yaml.safe_load(fh) or {}
            yaml_keys = data.get("api_keys", {}) or {}
        except Exception:
            pass

    table = Table(
        title="API Key Status",
        show_header=True,
        header_style="bold cyan",
        show_lines=False,
    )
    table.add_column("API Service", style="bold white", no_wrap=True, min_width=24)
    table.add_column("Status", justify="center", min_width=14)
    table.add_column("Source", style="dim", min_width=20)

    for key, label in _API_LABELS.items():
        yaml_val = (yaml_keys.get(key) or "").strip()
        env_val = os.environ.get(_ENV_VAR_MAP[key], "").strip()

        if yaml_val:
            status = "[bold green]● ACTIVE[/bold green]"
            source = "config.yaml"
        elif env_val:
            status = "[bold green]● ACTIVE[/bold green]"
            source = f"env: {_ENV_VAR_MAP[key]}"
        else:
            status = "[dim]○ SKIPPED[/dim]"
            source = "—"

        table.add_row(label, status, source)

    console.print(table)
    console.print()


# ---------------------------------------------------------------------------
# Single CONFIG dict — imported by all modules
# ---------------------------------------------------------------------------
CONFIG: dict[str, str | None] = _load_config()
