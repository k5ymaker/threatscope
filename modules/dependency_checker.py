"""
dependency_checker.py — System dependency detection and installation management.

Checks all required/optional binary and Python package dependencies, API key
configuration, and provides OS-appropriate install commands.
"""

from __future__ import annotations

import importlib.util
import os
import platform
import re
import shutil
import subprocess
import sys
from datetime import datetime
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import CONFIG  # noqa: E402

# ---------------------------------------------------------------------------
# OS Detection
# ---------------------------------------------------------------------------

def detect_os() -> str:
    """Detect current OS. Returns: kali/debian/ubuntu/arch/fedora/rhel/macos/windows/unknown"""
    if sys.platform == "win32":
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    # Linux - read /etc/os-release
    try:
        with open("/etc/os-release") as f:
            content = f.read().lower()
        if "kali" in content:
            return "kali"
        if "ubuntu" in content:
            return "ubuntu"
        if "debian" in content:
            return "debian"
        if "arch" in content or "manjaro" in content:
            return "arch"
        if "fedora" in content:
            return "fedora"
        if "rhel" in content or "centos" in content:
            return "rhel"
    except Exception:
        pass
    return "unknown"

CURRENT_OS = detect_os()

# ---------------------------------------------------------------------------
# API Key Registration URLs
# ---------------------------------------------------------------------------

API_KEY_URLS: dict[str, str] = {
    "virustotal":          "https://www.virustotal.com/gui/sign-in",
    "phishtank":           "https://www.phishtank.com/register.php",
    "google_safe_browsing":"https://developers.google.com/safe-browsing/v4/get-started",
    "urlscan":             "https://urlscan.io/user/signup",
    "apivoid":             "https://www.apivoid.com/register/",
    "abuseipdb":           "https://www.abuseipdb.com/register",
    "greynoise":           "https://www.greynoise.io/signup",
    "alienvault_otx":      "https://otx.alienvault.com/",
    "shodan":              "https://account.shodan.io/register",
    "ipinfo":              "https://ipinfo.io/signup",
    "hybrid_analysis":     "https://www.hybrid-analysis.com/apikeys/info",
    "malshare":            "https://malshare.com/register.php",
    "builtwith":           "https://api.builtwith.com/signup",
    "hibp":                "https://haveibeenpwned.com/API/Key",
    "emailrep":            "https://emailrep.io/key",
    "securitytrails":      "https://securitytrails.com/app/account/apikey",
    "nvd":                 "https://nvd.nist.gov/developers/request-an-api-key",
    "vulners":             "https://vulners.com/api",
    "iphub":               "https://iphub.info/apiKey",
}

# ---------------------------------------------------------------------------
# Install Command Map
# ---------------------------------------------------------------------------

INSTALL_COMMANDS: dict[str, dict[str, str]] = {
    "nmap": {
        "kali":    "sudo apt install -y nmap",
        "debian":  "sudo apt install -y nmap",
        "ubuntu":  "sudo apt install -y nmap",
        "arch":    "sudo pacman -S --noconfirm nmap",
        "fedora":  "sudo dnf install -y nmap",
        "rhel":    "sudo yum install -y nmap",
        "macos":   "brew install nmap",
        "windows": "winget install nmap  OR  choco install nmap  OR download: https://nmap.org/download.html",
        "unknown": "Install nmap: https://nmap.org/download.html",
    },
    "theharvester": {
        "kali":    "sudo apt install -y theharvester",
        "debian":  "sudo apt install -y theharvester",
        "ubuntu":  "sudo apt install -y theharvester",
        "arch":    "pip install theHarvester",
        "fedora":  "pip install theHarvester",
        "rhel":    "pip install theHarvester",
        "macos":   "pip install theHarvester",
        "windows": "pip install theHarvester",
        "unknown": "pip install theHarvester",
    },
    "exiftool": {
        "kali":    "sudo apt install -y libimage-exiftool-perl",
        "debian":  "sudo apt install -y libimage-exiftool-perl",
        "ubuntu":  "sudo apt install -y libimage-exiftool-perl",
        "arch":    "sudo pacman -S --noconfirm perl-image-exiftool",
        "fedora":  "sudo dnf install -y perl-Image-ExifTool",
        "rhel":    "sudo yum install -y perl-Image-ExifTool",
        "macos":   "brew install exiftool",
        "windows": "choco install exiftool  OR  download: https://exiftool.org",
        "unknown": "Install exiftool: https://exiftool.org",
    },
    "searchsploit": {
        "kali":    "sudo apt install -y exploitdb",
        "debian":  "sudo apt install -y exploitdb",
        "ubuntu":  "sudo apt install -y exploitdb",
        "arch":    "git clone https://github.com/offensive-security/exploitdb /opt/exploitdb && sudo ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit",
        "fedora":  "git clone https://github.com/offensive-security/exploitdb /opt/exploitdb && sudo ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit",
        "rhel":    "git clone https://github.com/offensive-security/exploitdb /opt/exploitdb && sudo ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit",
        "macos":   "brew install exploitdb",
        "windows": "Manual install: https://github.com/offensive-security/exploitdb",
        "unknown": "git clone https://github.com/offensive-security/exploitdb",
    },
    "python-nmap": {
        **{os_name: "pip install python-nmap" for os_name in ["kali","debian","ubuntu","arch","fedora","rhel","macos","windows","unknown"]},
    },
    "python-wappalyzer": {
        **{os_name: "pip install python-wappalyzer" for os_name in ["kali","debian","ubuntu","arch","fedora","rhel","macos","windows","unknown"]},
    },
    "PyMuPDF": {
        **{os_name: "pip install PyMuPDF" for os_name in ["kali","debian","ubuntu","arch","fedora","rhel","macos","windows","unknown"]},
    },
    "holehe": {
        **{os_name: "pip install holehe" for os_name in ["kali","debian","ubuntu","arch","fedora","rhel","macos","windows","unknown"]},
    },
    "geoip2": {
        **{os_name: "pip install geoip2" for os_name in ["kali","debian","ubuntu","arch","fedora","rhel","macos","windows","unknown"]},
    },
    "attackcti": {
        **{os_name: "pip install attackcti" for os_name in ["kali","debian","ubuntu","arch","fedora","rhel","macos","windows","unknown"]},
    },
    "reportlab": {
        **{os_name: "pip install reportlab" for os_name in ["kali","debian","ubuntu","arch","fedora","rhel","macos","windows","unknown"]},
    },
    "python-docx": {
        **{os_name: "pip install python-docx" for os_name in ["kali","debian","ubuntu","arch","fedora","rhel","macos","windows","unknown"]},
    },
    "jinja2": {
        **{os_name: "pip install Jinja2" for os_name in ["kali","debian","ubuntu","arch","fedora","rhel","macos","windows","unknown"]},
    },
    "scapy": {
        **{os_name: "pip install scapy" for os_name in ["kali","debian","ubuntu","arch","fedora","rhel","macos","windows","unknown"]},
    },
    "pyshark": {
        **{os_name: "pip install pyshark" for os_name in ["kali","debian","ubuntu","arch","fedora","rhel","macos","windows","unknown"]},
    },
    "cryptography": {
        **{os_name: "pip install cryptography" for os_name in ["kali","debian","ubuntu","arch","fedora","rhel","macos","windows","unknown"]},
    },
    "sublist3r": {
        "kali":    "sudo apt install -y sublist3r",
        "debian":  "sudo apt install -y sublist3r",
        "ubuntu":  "sudo apt install -y sublist3r",
        "arch":    "pip install sublist3r",
        "fedora":  "pip install sublist3r",
        "rhel":    "pip install sublist3r",
        "macos":   "pip install sublist3r",
        "windows": "pip install sublist3r",
        "unknown": "pip install sublist3r",
    },
}

# ---------------------------------------------------------------------------
# Dependency Registry
# ---------------------------------------------------------------------------

DEPENDENCY_REGISTRY: list[dict] = [
    # Python packages
    {"name": "python-nmap",       "key": "python-nmap",       "type": "python_pkg", "required_by": ["Nmap Scanner"],     "optional": False, "check_fn": "check_python_pkg", "description": "Python bindings for nmap port scanner"},
    {"name": "python-wappalyzer", "key": "python-wappalyzer", "type": "python_pkg", "required_by": ["OSINT Recon"],      "optional": True,  "check_fn": "check_python_pkg", "description": "Tech stack detection library"},
    {"name": "PyMuPDF",           "key": "PyMuPDF",           "type": "python_pkg", "required_by": ["OSINT Recon"],      "optional": True,  "check_fn": "check_python_pkg", "description": "PDF metadata extraction"},
    {"name": "holehe",            "key": "holehe",            "type": "python_pkg", "required_by": ["Email Intel"],      "optional": True,  "check_fn": "check_python_pkg", "description": "Email account discovery tool"},
    {"name": "geoip2",            "key": "geoip2",            "type": "python_pkg", "required_by": ["Geo Intelligence"], "optional": True,  "check_fn": "check_python_pkg", "description": "MaxMind GeoIP2 database reader"},
    {"name": "attackcti",         "key": "attackcti",         "type": "python_pkg", "required_by": ["MITRE ATT&CK"],     "optional": False, "check_fn": "check_python_pkg", "description": "MITRE ATT&CK TAXII client"},
    {"name": "cryptography",      "key": "cryptography",      "type": "python_pkg", "required_by": ["SSL Analyzer"],     "optional": False, "check_fn": "check_python_pkg", "description": "SSL certificate parsing"},
    {"name": "reportlab",         "key": "reportlab",         "type": "python_pkg", "required_by": ["Report Generator"],"optional": True,  "check_fn": "check_python_pkg", "description": "PDF report generation"},
    {"name": "python-docx",       "key": "python-docx",       "type": "python_pkg", "required_by": ["Report Generator"],"optional": True,  "check_fn": "check_python_pkg", "description": "Word document generation"},
    {"name": "jinja2",            "key": "jinja2",            "type": "python_pkg", "required_by": ["Report Generator"],"optional": True,  "check_fn": "check_python_pkg", "description": "HTML report templating"},
    {"name": "scapy",             "key": "scapy",             "type": "python_pkg", "required_by": ["PCAP Analyzer"],   "optional": True,  "check_fn": "check_python_pkg", "description": "Packet manipulation library"},
    {"name": "pyshark",           "key": "pyshark",           "type": "python_pkg", "required_by": ["PCAP Analyzer"],   "optional": True,  "check_fn": "check_python_pkg", "description": "Wireshark PCAP parser"},
    # System binaries
    {"name": "nmap",              "key": "nmap",              "type": "binary",     "required_by": ["Nmap Scanner"],     "optional": False, "check_fn": "check_binary",     "description": "Network port scanner"},
    {"name": "theHarvester",      "key": "theharvester",      "type": "binary",     "required_by": ["OSINT Recon"],      "optional": False, "check_fn": "check_binary",     "description": "Email and subdomain harvesting"},
    {"name": "exiftool",          "key": "exiftool",          "type": "binary",     "required_by": ["OSINT Recon"],      "optional": True,  "check_fn": "check_binary",     "description": "File metadata extraction"},
    {"name": "searchsploit",      "key": "searchsploit",      "type": "binary",     "required_by": ["CVE Intelligence"],"optional": True,  "check_fn": "check_binary",     "description": "Exploit-DB local search tool"},
    {"name": "sublist3r",         "key": "sublist3r",         "type": "python_pkg", "required_by": ["Subdomain Recon"],  "optional": True,  "check_fn": "check_python_pkg", "description": "Multi-source subdomain enumeration tool"},
    # API keys
    {"name": "VirusTotal",           "key": "virustotal",          "type": "api_key", "api_key_cfg": "virustotal",          "required_by": ["URL Intel", "Hash Intel"], "optional": False, "check_fn": "check_api_key", "description": "Multi-engine malware scanner"},
    {"name": "PhishTank",            "key": "phishtank",           "type": "api_key", "api_key_cfg": "phishtank",           "required_by": ["URL Intel"],               "optional": True,  "check_fn": "check_api_key", "description": "Phishing URL database"},
    {"name": "Google Safe Browsing", "key": "google_safe_browsing","type": "api_key", "api_key_cfg": "google_safe_browsing","required_by": ["URL Intel"],               "optional": True,  "check_fn": "check_api_key", "description": "Google's malware/phishing detection"},
    {"name": "URLScan.io",           "key": "urlscan",             "type": "api_key", "api_key_cfg": "urlscan",             "required_by": ["URL Intel"],               "optional": False, "check_fn": "check_api_key", "description": "URL scanning sandbox"},
    {"name": "APIVoid",              "key": "apivoid",             "type": "api_key", "api_key_cfg": "apivoid",             "required_by": ["URL Intel"],               "optional": True,  "check_fn": "check_api_key", "description": "URL/domain reputation"},
    {"name": "AbuseIPDB",            "key": "abuseipdb",           "type": "api_key", "api_key_cfg": "abuseipdb",           "required_by": ["IP Intel"],                "optional": False, "check_fn": "check_api_key", "description": "IP abuse reporting database"},
    {"name": "GreyNoise",            "key": "greynoise",           "type": "api_key", "api_key_cfg": "greynoise",           "required_by": ["IP Intel"],                "optional": True,  "check_fn": "check_api_key", "description": "Internet noise/scanner detection"},
    {"name": "AlienVault OTX",       "key": "alienvault_otx",      "type": "api_key", "api_key_cfg": "alienvault_otx",      "required_by": ["IP Intel", "Hash Intel"], "optional": True,  "check_fn": "check_api_key", "description": "Open threat exchange"},
    {"name": "Shodan",               "key": "shodan",              "type": "api_key", "api_key_cfg": "shodan",              "required_by": ["IP Intel"],                "optional": True,  "check_fn": "check_api_key", "description": "Internet device search engine"},
    {"name": "IPInfo",               "key": "ipinfo",              "type": "api_key", "api_key_cfg": "ipinfo",              "required_by": ["IP Intel"],                "optional": True,  "check_fn": "check_api_key", "description": "IP geolocation and info"},
    {"name": "Hybrid Analysis",      "key": "hybrid_analysis",     "type": "api_key", "api_key_cfg": "hybrid_analysis",     "required_by": ["Hash Intel"],              "optional": True,  "check_fn": "check_api_key", "description": "Malware sandbox analysis"},
    {"name": "Malshare",             "key": "malshare",            "type": "api_key", "api_key_cfg": "malshare",            "required_by": ["Hash Intel"],              "optional": True,  "check_fn": "check_api_key", "description": "Malware sample repository"},
    {"name": "BuiltWith",            "key": "builtwith",           "type": "api_key", "api_key_cfg": "builtwith",           "required_by": ["OSINT Recon"],             "optional": True,  "check_fn": "check_api_key", "description": "Website technology profiler"},
    {"name": "HaveIBeenPwned",       "key": "hibp",                "type": "api_key", "api_key_cfg": "hibp",                "required_by": ["Email Intel"],             "optional": False, "check_fn": "check_api_key", "description": "Email breach database"},
    {"name": "EmailRep.io",          "key": "emailrep",            "type": "api_key", "api_key_cfg": "emailrep",            "required_by": ["Email Intel"],             "optional": True,  "check_fn": "check_api_key", "description": "Email reputation scoring"},
    {"name": "SecurityTrails",       "key": "securitytrails",      "type": "api_key", "api_key_cfg": "securitytrails",      "required_by": ["Subdomain Recon"],         "optional": True,  "check_fn": "check_api_key", "description": "Historical DNS and subdomain data"},
    {"name": "NVD (NIST)",           "key": "nvd",                 "type": "api_key", "api_key_cfg": "nvd",                 "required_by": ["CVE Intel"],               "optional": True,  "check_fn": "check_api_key", "description": "National Vulnerability Database (optional key)"},
    {"name": "Vulners",              "key": "vulners",             "type": "api_key", "api_key_cfg": "vulners",             "required_by": ["CVE Intel"],               "optional": True,  "check_fn": "check_api_key", "description": "Vulnerability intelligence + EPSS"},
    {"name": "IPHub",                "key": "iphub",               "type": "api_key", "api_key_cfg": "iphub",               "required_by": ["Geo Intel"],               "optional": True,  "check_fn": "check_api_key", "description": "VPN/proxy/Tor IP detection"},
]

# ---------------------------------------------------------------------------
# Check functions
# ---------------------------------------------------------------------------

def check_binary(name: str) -> bool:
    """Check if a binary is available in PATH or common locations."""
    if shutil.which(name):
        return True
    if shutil.which(name.lower()):
        return True
    if shutil.which(name.upper()):
        return True
    for prefix in ("/usr/bin", "/usr/local/bin", "/opt/homebrew/bin"):
        if os.path.isfile(os.path.join(prefix, name)):
            return True
        if os.path.isfile(os.path.join(prefix, name.lower())):
            return True
    return False


def check_python_pkg(pkg_name: str) -> bool:
    """Check if a Python package is importable."""
    aliases = {
        "PyMuPDF":           "fitz",
        "python-nmap":       "nmap",
        "python-wappalyzer": "Wappalyzer",
        "python-docx":       "docx",
    }
    module_name = aliases.get(pkg_name, pkg_name.replace("-", "_"))
    return importlib.util.find_spec(module_name) is not None


def check_api_key(config_key: str) -> bool:
    """Return True if the API key is configured."""
    return bool((CONFIG.get(config_key) or "").strip())


def get_install_command(key: str) -> str:
    """Return OS-appropriate install command for a dependency."""
    commands = INSTALL_COMMANDS.get(key, {})
    return commands.get(CURRENT_OS, commands.get("unknown", f"See documentation for {key}"))


# ---------------------------------------------------------------------------
# Main check function
# ---------------------------------------------------------------------------

def run_all_checks() -> dict:
    """
    Run checks for every entry in DEPENDENCY_REGISTRY.
    Returns structured result dict with summary and per-item results.
    """
    results = []
    for entry in DEPENDENCY_REGISTRY:
        item = dict(entry)
        fn_name = entry["check_fn"]
        try:
            if fn_name == "check_binary":
                names_to_try = [entry["key"], entry["name"]]
                item["installed"] = any(check_binary(n) for n in names_to_try)
                item["path"] = shutil.which(entry["key"]) or shutil.which(entry["name"].lower()) or "not found"
            elif fn_name == "check_python_pkg":
                item["installed"] = check_python_pkg(entry["name"])
                item["path"] = "pip package"
            elif fn_name == "check_api_key":
                item["installed"] = check_api_key(entry.get("api_key_cfg", entry["key"]))
                item["path"] = "config.yaml"
        except Exception:
            item["installed"] = False
            item["path"] = "check failed"
        results.append(item)

    total           = len(results)
    installed       = sum(1 for r in results if r["installed"] and r["type"] != "api_key")
    api_configured  = sum(1 for r in results if r["installed"] and r["type"] == "api_key")
    api_total       = sum(1 for r in results if r["type"] == "api_key")

    missing_req  = [r for r in results if not r["installed"] and not r["optional"] and r["type"] != "api_key"]
    missing_opt  = [r for r in results if not r["installed"] and r["optional"] and r["type"] != "api_key"]
    missing_keys = [r for r in results if not r["installed"] and r["type"] == "api_key"]

    return {
        "os":             CURRENT_OS,
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "timestamp":      datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "summary": {
            "total":               total,
            "installed":           installed,
            "missing_required":    len(missing_req),
            "missing_optional":    len(missing_opt),
            "api_keys_configured": api_configured,
            "api_keys_missing":    len(missing_keys),
        },
        "results":          results,
        "missing_required": missing_req,
        "missing_optional": missing_opt,
        "missing_api_keys": missing_keys,
    }


def run_single_install(key: str) -> tuple[bool, str]:
    """
    Execute the install command for a dependency.
    Returns (success, output_message).
    """
    cmd_str = get_install_command(key)

    if "git clone" in cmd_str or "ln -sf" in cmd_str or "Manual" in cmd_str:
        return False, f"Manual installation required:\n  {cmd_str}"

    if cmd_str.startswith("pip install"):
        parts = cmd_str.split()
    elif cmd_str.startswith("sudo apt"):
        parts = cmd_str.split()
    elif cmd_str.startswith("sudo pacman"):
        parts = cmd_str.split()
    elif cmd_str.startswith("sudo dnf") or cmd_str.startswith("sudo yum"):
        parts = cmd_str.split()
    elif cmd_str.startswith("brew"):
        parts = cmd_str.split()
    elif cmd_str.startswith("winget") or cmd_str.startswith("choco"):
        parts = cmd_str.split()
    else:
        return False, f"Cannot auto-install. Run manually:\n  {cmd_str}"

    try:
        result = subprocess.run(
            parts,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode == 0:
            return True, result.stdout[:500] or "Installed successfully"
        else:
            return False, result.stderr[:500] or f"Install failed (exit {result.returncode})"
    except subprocess.TimeoutExpired:
        return False, "Installation timed out after 120 seconds"
    except OSError as exc:
        return False, str(exc)
