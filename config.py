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
    "virustotal":            "VT_API_KEY",
    "phishtank":             "PHISHTANK_API_KEY",
    "google_safe_browsing":  "GSB_API_KEY",
    "urlscan":               "URLSCAN_API_KEY",
    "apivoid":               "APIVOID_API_KEY",
    "shodan":                "SHODAN_API_KEY",
    "greynoise":             "GREYNOISE_API_KEY",
    "alienvault_otx":        "OTX_API_KEY",
    "ipinfo":                "IPINFO_API_KEY",
    "abstractapi_ip":        "ABSTRACTAPI_KEY",
    "abuseipdb":             "ABUSEIPDB_API_KEY",
    "hybrid_analysis":       "HYBRID_ANALYSIS_API_KEY",
    "malshare":              "MALSHARE_API_KEY",
    "builtwith":             "BUILTWITH_API_KEY",
    "hibp":                  "HIBP_API_KEY",
    "emailrep":              "EMAILREP_API_KEY",
    "securitytrails":        "SECURITYTRAILS_API_KEY",
    "nvd":                   "NVD_API_KEY",
    "vulners":               "VULNERS_API_KEY",
    "iphub":                 "IPHUB_API_KEY",
}

_API_LABELS: dict[str, str] = {
    "virustotal":            "VirusTotal",
    "phishtank":             "PhishTank",
    "google_safe_browsing":  "Google Safe Browsing",
    "urlscan":               "URLScan.io",
    "apivoid":               "APIVoid",
    "shodan":                "Shodan",
    "greynoise":             "GreyNoise",
    "alienvault_otx":        "AlienVault OTX",
    "ipinfo":                "IPInfo",
    "abstractapi_ip":        "AbstractAPI (IP)",
    "abuseipdb":             "AbuseIPDB",
    "hybrid_analysis":       "Hybrid Analysis",
    "malshare":              "Malshare",
    "builtwith":             "BuiltWith",
    "hibp":                  "Have I Been Pwned",
    "emailrep":              "EmailRep.io",
    "securitytrails":        "SecurityTrails",
    "nvd":                   "NVD NIST (CVE)",
    "vulners":               "Vulners",
    "iphub":                 "IPHub (proxy detect)",
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
    """Print a grouped table showing ACTIVE / SKIPPED status for every configured API."""
    yaml_keys: dict = {}
    if _CONFIG_PATH.exists():
        try:
            with open(_CONFIG_PATH, "r") as fh:
                data = yaml.safe_load(fh) or {}
            yaml_keys = data.get("api_keys", {}) or {}
        except Exception:
            pass

    table = Table(
        title="API Key & Tool Status",
        show_header=True,
        header_style="bold cyan",
        show_lines=False,
    )
    table.add_column("API Service", style="bold white", no_wrap=True, min_width=26)
    table.add_column("Status", justify="center", min_width=14)
    table.add_column("Source", style="dim", min_width=22)

    def _row(key: str, label: str) -> None:
        yaml_val = (yaml_keys.get(key) or "").strip()
        env_val  = os.environ.get(_ENV_VAR_MAP[key], "").strip()
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

    def _sep(title: str) -> None:
        table.add_row(f"[bold dim]─── {title} ───[/bold dim]", "", "")

    # URL Intelligence
    _sep("URL INTELLIGENCE")
    for k in ("virustotal", "phishtank", "google_safe_browsing", "urlscan", "apivoid"):
        _row(k, _API_LABELS[k])

    # IP Intelligence
    _sep("IP INTELLIGENCE")
    for k in ("shodan", "greynoise", "alienvault_otx", "ipinfo", "abstractapi_ip", "abuseipdb"):
        _row(k, _API_LABELS[k])

    # Hash & File
    _sep("HASH & FILE INTELLIGENCE")
    for k in ("hybrid_analysis", "malshare"):
        _row(k, _API_LABELS[k])
    table.add_row("MalwareBazaar",  "[bold green]● ACTIVE[/bold green]", "No key required")
    table.add_row("ThreatFox",      "[bold green]● ACTIVE[/bold green]", "No key required")

    # OSINT
    _sep("OSINT / WEB FINGERPRINT")
    _row("builtwith", _API_LABELS["builtwith"])
    table.add_row("Wayback Machine", "[bold green]● ACTIVE[/bold green]", "No key required")

    import shutil as _shutil
    import importlib.util as _iutil

    _th_bin = _shutil.which("theHarvester") or _shutil.which("theharvester")
    table.add_row(
        "theHarvester",
        "[bold green]● ACTIVE[/bold green]" if _th_bin else "[yellow]○ NOT INSTALLED[/yellow]",
        _th_bin or "install: sudo apt install theharvester",
    )
    _et_bin = _shutil.which("exiftool")
    table.add_row(
        "exiftool",
        "[bold green]● ACTIVE[/bold green]" if _et_bin else "[yellow]○ NOT INSTALLED[/yellow]",
        _et_bin or "install: sudo apt install libimage-exiftool-perl",
    )
    _wap_spec = _iutil.find_spec("Wappalyzer")
    table.add_row(
        "Wappalyzer (lib)",
        "[bold green]● ACTIVE[/bold green]" if _wap_spec else "[yellow]○ NOT INSTALLED[/yellow]",
        "pip install python-wappalyzer" if not _wap_spec else "python-wappalyzer",
    )
    _fitz_spec = _iutil.find_spec("fitz")
    table.add_row(
        "PyMuPDF (PDF meta)",
        "[bold green]● ACTIVE[/bold green]" if _fitz_spec else "[yellow]○ NOT INSTALLED[/yellow]",
        "pip install PyMuPDF" if not _fitz_spec else "PyMuPDF / fitz",
    )

    # Email Intelligence
    _sep("EMAIL INTELLIGENCE")
    for k in ("hibp", "emailrep"):
        _row(k, _API_LABELS[k])
    _holehe_bin = _shutil.which("holehe")
    table.add_row(
        "Holehe (binary)",
        "[bold green]● ACTIVE[/bold green]" if _holehe_bin else "[yellow]○ NOT INSTALLED[/yellow]",
        _holehe_bin or "pip install holehe",
    )

    # Subdomain & ASN
    _sep("SUBDOMAIN & ASN RECON")
    _row("securitytrails", _API_LABELS["securitytrails"])
    table.add_row("crt.sh",        "[bold green]● ACTIVE[/bold green]", "No key required")
    table.add_row("HackerTarget",  "[bold green]● ACTIVE[/bold green]", "No key required")
    table.add_row("BGPView",       "[bold green]● ACTIVE[/bold green]", "No key required")
    table.add_row("RIPEstat",      "[bold green]● ACTIVE[/bold green]", "No key required")

    # CVE Intelligence
    _sep("CVE INTELLIGENCE")
    for k in ("nvd", "vulners"):
        _row(k, _API_LABELS[k])
    _ss_bin = _shutil.which("searchsploit")
    table.add_row(
        "searchsploit (binary)",
        "[bold green]● ACTIVE[/bold green]" if _ss_bin else "[yellow]○ NOT INSTALLED[/yellow]",
        _ss_bin or "install: sudo apt install exploitdb",
    )
    table.add_row("CISA KEV",  "[bold green]● ACTIVE[/bold green]", "No key required")

    # SSL Analyzer
    _sep("SSL/TLS ANALYZER")
    table.add_row("Qualys SSL Labs", "[bold green]● ACTIVE[/bold green]", "No key required")
    _crypto_spec = _iutil.find_spec("cryptography")
    table.add_row(
        "cryptography (lib)",
        "[bold green]● ACTIVE[/bold green]" if _crypto_spec else "[yellow]○ NOT INSTALLED[/yellow]",
        "pip install cryptography" if not _crypto_spec else "cryptography",
    )

    # Threat Feeds
    _sep("LIVE THREAT FEEDS")
    table.add_row("URLhaus",         "[bold green]● ACTIVE[/bold green]", "No key required")
    table.add_row("Feodo Tracker",   "[bold green]● ACTIVE[/bold green]", "No key required")
    table.add_row("SSL Blacklist",   "[bold green]● ACTIVE[/bold green]", "No key required")

    # MITRE ATT&CK
    _sep("MITRE ATT&CK")
    import pathlib as _pathlib
    _attack_cache = _pathlib.Path.home() / ".threatscope" / "enterprise-attack.json"
    table.add_row(
        "ATT&CK STIX bundle",
        "[bold green]● CACHED[/bold green]" if _attack_cache.exists() else "[yellow]○ NOT CACHED[/yellow]",
        str(_attack_cache) if _attack_cache.exists() else "Downloaded on first use from GitHub",
    )

    # Geo / Proxy
    _sep("GEO / PROXY INTELLIGENCE")
    _row("iphub", _API_LABELS["iphub"])

    console.print(table)
    console.print()


# ---------------------------------------------------------------------------
# Single CONFIG dict — imported by all modules
# ---------------------------------------------------------------------------
CONFIG: dict[str, str | None] = _load_config()
