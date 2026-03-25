"""
web_fingerprint.py — Web Application Fingerprinting for ThreatScope.

Wraps three optional external CLI tools:
  WhatWeb    — CMS, framework, server, and plugin detection
  Wappalyzer — Full tech stack fingerprinting (CLI or python-wappalyzer library)
  WafW00f    — Web Application Firewall identification

If a binary is not found the function returns a graceful skipped dict that
matches the ThreatScope module return convention.  No function raises an
unhandled exception.

Binary detection runs at import time and is stored in module-level constants
that can be imported by the menus module for the tool-status display.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from typing import Optional

# ---------------------------------------------------------------------------
# Binary / Library detection (module-level, at import time)
# ---------------------------------------------------------------------------

WHATWEB_BIN:    Optional[str] = shutil.which("whatweb")
WAFW00F_BIN:    Optional[str] = shutil.which("wafw00f")
WAPPALYZER_BIN: Optional[str] = shutil.which("wappalyzer") or shutil.which("webtech")

try:
    import Wappalyzer as _wap_lib  # type: ignore[import]
    WAPPALYZER_LIB: bool = True
except ImportError:
    WAPPALYZER_LIB = False

TOOL_STATUS: dict[str, dict] = {
    "whatweb": {
        "available": bool(WHATWEB_BIN),
        "path":      WHATWEB_BIN or "not found",
    },
    "wappalyzer": {
        "available": bool(WAPPALYZER_BIN) or WAPPALYZER_LIB,
        "path":      WAPPALYZER_BIN or ("python-wappalyzer (library)" if WAPPALYZER_LIB else "not found"),
    },
    "wafw00f": {
        "available": bool(WAFW00F_BIN),
        "path":      WAFW00F_BIN or "not found",
    },
}

INSTALL_HINTS: dict[str, str] = {
    "whatweb":    "sudo apt install whatweb   OR   gem install whatweb",
    "wappalyzer": "pip install python-wappalyzer   OR   npm install -g wappalyzer",
    "wafw00f":    "pip install wafw00f   OR   sudo apt install wafw00f",
}

# ---------------------------------------------------------------------------
# Category mapping for WhatWeb plugin names
# ---------------------------------------------------------------------------

_CATEGORY_MAP: dict[str, str] = {
    # CMS
    "WordPress": "CMS", "Joomla": "CMS", "Drupal": "CMS", "Magento": "CMS",
    "WooCommerce": "CMS", "Shopify": "CMS", "TYPO3": "CMS", "DotNetNuke": "CMS",
    "Umbraco": "CMS", "Ghost": "CMS", "Wix": "CMS", "Squarespace": "CMS",
    "ModX": "CMS", "Craft": "CMS", "Kentico": "CMS", "SilverStripe": "CMS",
    # Web Server
    "Apache": "Web Server", "Nginx": "Web Server", "Microsoft-IIS": "Web Server",
    "IIS": "Web Server", "LiteSpeed": "Web Server", "Caddy": "Web Server",
    "Tomcat": "Web Server", "Gunicorn": "Web Server", "OpenResty": "Web Server",
    "Cherokee": "Web Server",
    # Framework
    "Laravel": "Framework", "Django": "Framework", "Ruby-on-Rails": "Framework",
    "Rails": "Framework", "ASP.NET": "Framework", "Express": "Framework",
    "Spring": "Framework", "Flask": "Framework", "Symfony": "Framework",
    "CodeIgniter": "Framework", "CakePHP": "Framework", "Yii": "Framework",
    "ZendFramework": "Framework",
    # Language
    "PHP": "Language", "Python": "Language", "Ruby": "Language",
    "Java": "Language", "Node.js": "Language", "Go": "Language", "Perl": "Language",
    # CDN
    "Cloudflare": "CDN", "Akamai": "CDN", "Fastly": "CDN",
    "Amazon-Cloudfront": "CDN", "CloudFront": "CDN", "Incapsula": "CDN",
    # Analytics
    "Google-Analytics": "Analytics", "Hotjar": "Analytics", "Mixpanel": "Analytics",
    "Piwik": "Analytics", "Matomo": "Analytics", "Heap": "Analytics",
    # JS Library
    "jQuery": "JS Library", "React": "JS Library", "Angular": "JS Library",
    "Vue.js": "JS Library", "Bootstrap": "JS Library", "Backbone.js": "JS Library",
    "Prototype": "JS Library", "MooTools": "JS Library", "Ember.js": "JS Library",
    # Security
    "reCAPTCHA": "Security", "hCaptcha": "Security", "Sucuri": "Security",
    # Email
    "Outlook-Web-Access": "Email", "Roundcube": "Email",
}

# WAF-specific evasion notes (static lookup)
_WAF_EVASION: dict[str, list[str]] = {
    "Cloudflare": [
        "Consider IP bypass via direct IP if origin server is exposed",
        "Case variation in payloads may bypass certain rule sets",
        "HTTP/2 request smuggling vectors worth testing",
        "Check for origin IP via Shodan/Censys SSL certificate search",
    ],
    "AWS WAF": [
        "URL encoding variations may bypass pattern matching rules",
        "Header injection via non-standard HTTP headers",
        "Check for regional bypass endpoints or staging environments",
    ],
    "ModSecurity": [
        "Paranoia level (1-4) determines rule strictness — check headers",
        "Comment-based SQL injection bypass techniques applicable",
        "Multipart/form-data encoding evasion worth testing",
        "NULL byte injection in parameters may bypass string matching",
    ],
    "Akamai": [
        "IP reputation bypass via residential proxy rotation",
        "Slow-rate request evasion may avoid rate-limit triggers",
        "Check for staging/dev subdomains that may lack WAF protection",
    ],
    "F5 BIG-IP ASM": [
        "ASM signatures can have false-negative edge cases on complex payloads",
        "Binary/null byte injection in parameter values",
        "CSRF token bypass techniques may be applicable",
    ],
    "Imperva": [
        "Rate limiting evasion via session token rotation",
        "IP whitelist exploitation if internal IP ranges leak",
        "JavaScript challenge bypass tools exist for automated testing",
    ],
    "Barracuda": [
        "Filter evasion via double URL encoding",
        "Check management interface exposure on alternate ports",
    ],
    "Sucuri": [
        "Whitelist-based bypass via X-Forwarded-For header manipulation",
        "Check for origin IP exposure via MX records or subdomains",
    ],
    "Generic": [
        "No specific WAF identified — standard testing methodology applies",
        "Manual fingerprinting recommended before applying evasion",
    ],
}


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _normalise_url(url: str) -> str:
    """Ensure the target has an http/https scheme. Strips trailing slashes."""
    url = url.strip().rstrip("/")
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def _elapsed(start: float) -> str:
    """Return elapsed time from a time.time() start as a human string e.g. '4.2s'."""
    return f"{time.time() - start:.1f}s"


def _map_plugin_to_category(plugin_name: str) -> str:
    """
    Map a WhatWeb plugin name to a human-readable category string.

    Args:
        plugin_name: Raw plugin name from WhatWeb JSON output.

    Returns:
        Category string from _CATEGORY_MAP or ``"Other"`` for unmapped entries.
    """
    for key, cat in _CATEGORY_MAP.items():
        if key.lower() in plugin_name.lower():
            return cat
    return "Other"


def _parse_wafw00f_fallback(stdout: str) -> dict:
    """
    Regex-based fallback parser for WafW00f when JSON mode fails.

    Searches for patterns like:
      "is behind a Cloudflare WAF"
      "No WAF detected"
      "The site X is behind Y"

    Args:
        stdout: Raw stdout from wafw00f process.

    Returns:
        Dict with keys: waf_detected (bool), waf_name (str|None), manufacturer (str|None).
    """
    waf_name: Optional[str] = None
    detected = False

    m = re.search(r"is behind (?:a |an )?(.+?) WAF", stdout, re.IGNORECASE)
    if m:
        waf_name = m.group(1).strip()
        detected = True

    m2 = re.search(r"The site .+? is behind (.+)", stdout, re.IGNORECASE)
    if m2 and not waf_name:
        waf_name = m2.group(1).strip()
        detected = True

    if re.search(r"No WAF (?:was )?detected", stdout, re.IGNORECASE):
        detected = False
        waf_name = None

    return {
        "waf_detected": detected,
        "waf_name":     waf_name,
        "manufacturer": waf_name,
    }


def _parse_whatweb_json(raw: str) -> list[dict]:
    """
    Parse WhatWeb --log-json=- output. Handles both JSON arrays and
    newline-delimited JSON objects.

    Args:
        raw: Raw stdout from the WhatWeb process.

    Returns:
        List of parsed JSON objects.
    """
    raw = raw.strip()
    if not raw:
        return []

    # Try full JSON parse first (array or single object)
    try:
        data = json.loads(raw)
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return [data]
    except json.JSONDecodeError:
        pass

    # Try newline-delimited JSON
    results = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            results.append(json.loads(line))
        except json.JSONDecodeError:
            pass

    return results


def _extract_whatweb_details(parsed_entries: list[dict], target: str) -> dict:
    """
    Extract structured details from a list of parsed WhatWeb JSON entries.

    Args:
        parsed_entries: Output of _parse_whatweb_json().
        target:         Original scan target string.

    Returns:
        Populated details dict ready for the result dict.
    """
    if not parsed_entries:
        return {
            "url": target, "http_status": None, "technologies": [],
            "cms": None, "web_server": None, "frameworks": [],
            "languages": [], "javascript_libs": [], "email_addresses": [],
            "ip_addresses": [], "country": None, "cookies": [],
            "security_headers": [], "interesting_headers": [],
            "raw_plugins": {}, "total_plugins": 0, "redirect_chain": [],
        }

    entry = parsed_entries[0]
    plugins: dict = entry.get("plugins", {})

    technologies: list[dict] = []
    cms: Optional[str] = None
    web_server: Optional[str] = None
    frameworks: list[str] = []
    languages: list[str] = []
    js_libs: list[str] = []
    email_addresses: list[str] = []
    ip_addresses: list[str] = []
    cookies: list[str] = []
    security_headers: list[str] = []
    interesting_headers: list[str] = []
    redirect_chain: list[str] = []

    for plugin_name, plugin_data in plugins.items():
        versions: list[str] = plugin_data.get("version", [])
        version_str = versions[0] if versions else ""
        category = _map_plugin_to_category(plugin_name)

        tech_entry: dict = {
            "name":     plugin_name,
            "version":  version_str,
            "category": category,
        }
        technologies.append(tech_entry)

        label = f"{plugin_name} {version_str}".strip()

        # Categorise
        if category == "CMS" and not cms:
            cms = label
        elif category == "Web Server" and not web_server:
            web_server = label
        elif category == "Framework":
            frameworks.append(label)
        elif category == "Language":
            languages.append(label)
        elif category == "JS Library":
            js_libs.append(label)

        # Special plugins WhatWeb detects
        if plugin_name.lower() in ("email", "email-address"):
            strings = plugin_data.get("string", [])
            email_addresses.extend(strings)
        if plugin_name.lower() in ("ip-address", "ipv6"):
            strings = plugin_data.get("string", [])
            ip_addresses.extend(strings)
        if plugin_name.lower() in ("cookies", "cookie"):
            strings = plugin_data.get("string", [])
            cookies.extend(strings)
        if plugin_name.lower().startswith("header"):
            strings = plugin_data.get("string", [])
            interesting_headers.extend(strings)
        if plugin_name.lower() == "redirect-location":
            strings = plugin_data.get("string", [])
            redirect_chain.extend(strings)
        if plugin_name.lower() in ("strict-transport-security", "content-security-policy",
                                    "x-frame-options", "x-xss-protection",
                                    "x-content-type-options"):
            security_headers.append(plugin_name)

    return {
        "url":                 entry.get("target", target),
        "http_status":         entry.get("http_status"),
        "technologies":        technologies,
        "cms":                 cms,
        "web_server":          web_server,
        "frameworks":          frameworks,
        "languages":           languages,
        "javascript_libs":     js_libs,
        "email_addresses":     list(set(email_addresses)),
        "ip_addresses":        list(set(ip_addresses)),
        "country":             None,
        "cookies":             cookies[:10],
        "security_headers":    security_headers,
        "interesting_headers": interesting_headers[:10],
        "raw_plugins":         plugins,
        "total_plugins":       len(plugins),
        "redirect_chain":      redirect_chain,
    }


def _merge_technologies(whatweb_result: dict, wappalyzer_result: dict) -> list[str]:
    """
    Merge technology lists from WhatWeb and Wappalyzer, deduplicating by name
    (case-insensitive). Prefers entries that include version information.

    Args:
        whatweb_result:    Result dict from run_whatweb().
        wappalyzer_result: Result dict from run_wappalyzer().

    Returns:
        Sorted deduplicated list of technology strings.
    """
    seen: dict[str, str] = {}  # normalised_name → display_string

    for tech in whatweb_result.get("details", {}).get("technologies", []):
        name = tech.get("name", "")
        ver  = tech.get("version", "")
        label = f"{name} {ver}".strip()
        key = name.lower()
        if key not in seen or (ver and not seen[key].split()[-1].replace(".", "").isdigit()):
            seen[key] = label

    for tech in wappalyzer_result.get("details", {}).get("technologies", []):
        name = tech.get("name", "")
        ver  = tech.get("version", "")
        label = f"{name} {ver}".strip()
        key = name.lower()
        if key not in seen or (ver and not seen[key].split()[-1].replace(".", "").isdigit()):
            seen[key] = label

    return sorted(seen.values())


def _skipped_result(tool_key: str, source: str, target: str) -> dict:
    """Return a standardised skipped result when the tool binary is unavailable."""
    return {
        "source":       source,
        "target":       target,
        "skipped":      True,
        "error":        False,
        "flagged":      False,
        "details":      {},
        "raw_output":   "",
        "command":      "",
        "scan_time":    "0s",
        "install_hint": INSTALL_HINTS.get(tool_key, ""),
    }


def _error_result(source: str, target: str, msg: str,
                  command: str = "", scan_time: str = "0s") -> dict:
    """Return a standardised error result dict."""
    return {
        "source":     source,
        "target":     target,
        "skipped":    False,
        "error":      True,
        "flagged":    False,
        "details":    {"Error": msg},
        "raw_output": "",
        "command":    command,
        "scan_time":  scan_time,
    }


# ---------------------------------------------------------------------------
# FUNCTION 1 — WhatWeb
# ---------------------------------------------------------------------------

def run_whatweb(
    target: str,
    aggression: int = 1,
    user_agent: Optional[str] = None,
    follow_redirects: bool = True,
    extra_args: Optional[list[str]] = None,
) -> dict:
    """
    Run WhatWeb against a target URL or domain.

    Args:
        target:           URL or domain to fingerprint.
        aggression:       Aggression level 1–4 (1 = passive/stealthy, 4 = heavy).
        user_agent:       Optional custom User-Agent string.
        follow_redirects: If True, passes ``--follow-redirect`` to WhatWeb.
        extra_args:       Additional raw CLI arguments passed through verbatim.

    Returns:
        Result dict with keys: source, target, skipped, error, flagged,
        details (technologies, cms, web_server, …), raw_output, command, scan_time.
    """
    if not WHATWEB_BIN:
        return _skipped_result("whatweb", "WhatWeb", target)

    target = _normalise_url(target)
    aggression = max(1, min(4, aggression))

    cmd: list[str] = [
        WHATWEB_BIN,
        f"--aggression={aggression}",
        "--log-json=-",
        "--colour=never",
        "--no-errors",
    ]
    if user_agent:
        cmd += ["--user-agent", user_agent]
    if follow_redirects:
        cmd.append("--follow-redirect=always")
    if extra_args:
        cmd.extend(extra_args)
    cmd.append(target)

    command_str = " ".join(cmd)
    start = time.time()

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )
        elapsed = _elapsed(start)
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""

        if proc.returncode not in (0, 1) and not stdout.strip():
            return _error_result("WhatWeb", target, stderr or "WhatWeb exited unexpectedly.",
                                 command_str, elapsed)

        parsed_entries = _parse_whatweb_json(stdout)
        details = _extract_whatweb_details(parsed_entries, target)

        # Determine flagged status
        has_versions = any(t.get("version") for t in details["technologies"])
        has_emails   = bool(details["email_addresses"])
        flagged = has_versions or has_emails

        return {
            "source":     "WhatWeb",
            "target":     target,
            "skipped":    False,
            "error":      False,
            "flagged":    flagged,
            "details":    details,
            "raw_output": stdout[:4000],
            "command":    command_str,
            "scan_time":  elapsed,
        }

    except subprocess.TimeoutExpired:
        return _error_result("WhatWeb", target, "Scan timed out after 30 seconds.",
                             command_str, _elapsed(start))
    except FileNotFoundError:
        return _error_result("WhatWeb", target,
                             f"WhatWeb binary not found at: {WHATWEB_BIN}",
                             command_str, _elapsed(start))
    except Exception as exc:  # noqa: BLE001
        return _error_result("WhatWeb", target, str(exc), command_str, _elapsed(start))


# ---------------------------------------------------------------------------
# FUNCTION 2 — Wappalyzer
# ---------------------------------------------------------------------------

def run_wappalyzer(target: str, use_headless: bool = False) -> dict:
    """
    Run Wappalyzer tech stack fingerprinting against a target URL.

    Attempts CLI binary first (wappalyzer or webtech), then falls back to
    the python-wappalyzer library, then returns a skipped dict if neither
    is available.

    Args:
        target:       URL or domain to fingerprint.
        use_headless: Reserved for future headless-browser mode (unused now).

    Returns:
        Result dict with technologies grouped by category.
    """
    if not WAPPALYZER_BIN and not WAPPALYZER_LIB:
        return _skipped_result("wappalyzer", "Wappalyzer", target)

    target = _normalise_url(target)
    start  = time.time()

    # ── Strategy 1: CLI binary ──────────────────────────────────────────────
    if WAPPALYZER_BIN:
        bin_name = os.path.basename(WAPPALYZER_BIN)
        if bin_name == "webtech":
            cmd = [WAPPALYZER_BIN, "-u", target, "--json"]
        else:
            cmd = [WAPPALYZER_BIN, target, "--pretty"]

        command_str = " ".join(cmd)

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=45)
            elapsed = _elapsed(start)
            stdout  = proc.stdout or ""

            technologies, summary = _parse_wappalyzer_output(stdout, bin_name)

            return {
                "source":     "Wappalyzer",
                "target":     target,
                "skipped":    False,
                "error":      False,
                "flagged":    bool(technologies),
                "details": {
                    "technologies":      technologies,
                    "summary_by_category": summary,
                    "total_technologies":  len(technologies),
                    "detection_method":    f"cli_{bin_name}",
                },
                "raw_output": stdout[:4000],
                "command":    command_str,
                "scan_time":  elapsed,
            }

        except subprocess.TimeoutExpired:
            return _error_result("Wappalyzer", target, "CLI scan timed out after 45s.",
                                 command_str, _elapsed(start))
        except Exception as exc:  # noqa: BLE001
            # Fall through to library if CLI fails
            pass

    # ── Strategy 2: python-wappalyzer library ──────────────────────────────
    if WAPPALYZER_LIB:
        command_str = f"python-wappalyzer library → {target}"
        try:
            from Wappalyzer import Wappalyzer, WebPage  # type: ignore[import]
            wappalyzer_instance = Wappalyzer.latest()
            webpage = WebPage.new_from_url(target, verify=False)
            raw_results = wappalyzer_instance.analyze_with_categories(webpage)
            elapsed = _elapsed(start)

            technologies: list[dict] = []
            summary: dict[str, list[str]] = {}

            for tech_name, tech_data in raw_results.items():
                categories: list[str] = []
                if isinstance(tech_data, dict):
                    cats = tech_data.get("categories", {})
                    if isinstance(cats, dict):
                        categories = list(cats.keys())
                    elif isinstance(cats, list):
                        categories = [c if isinstance(c, str) else str(c) for c in cats]

                ver = ""
                if isinstance(tech_data, dict):
                    ver = tech_data.get("version", "")

                technologies.append({
                    "name":       tech_name,
                    "version":    ver,
                    "categories": categories,
                })

                for cat in categories:
                    label = f"{tech_name} {ver}".strip()
                    summary.setdefault(cat, []).append(label)

            return {
                "source":  "Wappalyzer",
                "target":  target,
                "skipped": False,
                "error":   False,
                "flagged": bool(technologies),
                "details": {
                    "technologies":        technologies,
                    "summary_by_category": summary,
                    "total_technologies":  len(technologies),
                    "detection_method":    "python_library",
                },
                "raw_output": str(raw_results)[:2000],
                "command":    command_str,
                "scan_time":  elapsed,
            }

        except Exception as exc:  # noqa: BLE001
            return _error_result("Wappalyzer", target, str(exc), command_str, _elapsed(start))

    return _skipped_result("wappalyzer", "Wappalyzer", target)


def _parse_wappalyzer_output(stdout: str, bin_name: str) -> tuple[list[dict], dict[str, list[str]]]:
    """
    Parse wappalyzer or webtech CLI JSON output.

    Returns:
        Tuple of (technologies list, summary_by_category dict).
    """
    technologies: list[dict] = []
    summary: dict[str, list[str]] = {}

    if not stdout.strip():
        return technologies, summary

    try:
        data = json.loads(stdout)

        if bin_name == "webtech":
            # webtech JSON: {"target": ..., "tech": {"Name": {"version": "x", "categories": [...]}}}
            tech_data = data.get("tech", {})
            for tech_name, tech_info in tech_data.items():
                ver  = tech_info.get("version", "") if isinstance(tech_info, dict) else ""
                cats = tech_info.get("categories", []) if isinstance(tech_info, dict) else []
                technologies.append({"name": tech_name, "version": ver, "categories": cats})
                label = f"{tech_name} {ver}".strip()
                for cat in cats:
                    summary.setdefault(str(cat), []).append(label)
        else:
            # wappalyzer CLI JSON: {"technologies": [{"name": ..., "categories": [...], "version": ...}]}
            techs = data.get("technologies", [])
            if not techs and isinstance(data, list):
                techs = data
            for t in techs:
                name  = t.get("name", "")
                ver   = t.get("version", "")
                cats_raw = t.get("categories", [])
                cats  = [c.get("name", str(c)) if isinstance(c, dict) else str(c) for c in cats_raw]
                technologies.append({"name": name, "version": ver, "categories": cats})
                label = f"{name} {ver}".strip()
                for cat in cats:
                    summary.setdefault(cat, []).append(label)

    except (json.JSONDecodeError, AttributeError):
        # Fallback: line-by-line text parsing
        for line in stdout.splitlines():
            line = line.strip()
            if line and not line.startswith(("{", "[", "}")):
                # Simple name extraction
                technologies.append({"name": line, "version": "", "categories": ["Unknown"]})
                summary.setdefault("Unknown", []).append(line)

    return technologies, summary


# ---------------------------------------------------------------------------
# FUNCTION 3 — WafW00f
# ---------------------------------------------------------------------------

def run_wafw00f(
    target: str,
    find_all: bool = False,
    test_all_waf: bool = False,
) -> dict:
    """
    Run WafW00f WAF detection against a target URL or domain.

    Args:
        target:       URL or domain to test.
        find_all:     Pass ``-a`` flag — find all WAFs instead of stopping at first.
        test_all_waf: Pass ``-t`` flag — test against all fingerprints in the WafW00f DB.

    Returns:
        Result dict with waf_detected, waf_name, manufacturer, and evasion_notes.
    """
    if not WAFW00F_BIN:
        return _skipped_result("wafw00f", "WafW00f", target)

    target = _normalise_url(target)

    cmd: list[str] = [WAFW00F_BIN, target, "--format", "json"]
    if find_all:
        cmd.append("-a")
    if test_all_waf:
        cmd.append("-t")

    command_str = " ".join(cmd)
    start = time.time()

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        elapsed = _elapsed(start)
        stdout  = proc.stdout or ""
        stderr  = proc.stderr or ""

        # Attempt JSON parse
        waf_info: Optional[dict] = None
        all_wafs: list[dict] = []

        try:
            parsed = json.loads(stdout)
            if isinstance(parsed, list) and parsed:
                all_wafs = parsed
                waf_info = parsed[0]
            elif isinstance(parsed, dict):
                waf_info = parsed
                all_wafs = [parsed]
        except (json.JSONDecodeError, IndexError):
            # JSON failed — use regex fallback
            fallback = _parse_wafw00f_fallback(stdout + stderr)
            waf_info = fallback

        if waf_info is None:
            return _error_result("WafW00f", target,
                                 "Could not parse WafW00f output.",
                                 command_str, elapsed)

        waf_detected  = bool(waf_info.get("detected", False))
        waf_name: Optional[str] = waf_info.get("firewall") or waf_info.get("waf_name")
        manufacturer: Optional[str] = waf_info.get("manufacturer") or waf_name

        # Clean up "Generic" / "N/A" from no-WAF results
        if waf_name and waf_name.strip().lower() in ("generic", "n/a", "none", ""):
            waf_name = None
        if manufacturer and manufacturer.strip().lower() in ("generic", "n/a", "none", ""):
            manufacturer = None

        evasion_key = waf_name if waf_name and waf_name in _WAF_EVASION else "Generic"
        evasion_notes = _WAF_EVASION.get(evasion_key, _WAF_EVASION["Generic"])

        details: dict = {
            "waf_detected":  waf_detected,
            "waf_name":      waf_name,
            "manufacturer":  manufacturer,
            "all_wafs":      all_wafs,
            "waf_count":     len([w for w in all_wafs if w.get("detected")]),
            "evasion_notes": evasion_notes if waf_detected else [],
            "bypass_hints":  evasion_notes if waf_detected else [],
        }

        if not waf_detected:
            details["no_waf_warning"] = (
                "No WAF detected — target may be unprotected. "
                "Direct exploitation attempts are more likely to succeed. "
                "Run with -t flag for an exhaustive check."
            )

        return {
            "source":     "WafW00f",
            "target":     target,
            "skipped":    False,
            "error":      False,
            "flagged":    waf_detected,
            "details":    details,
            "raw_output": stdout[:2000],
            "command":    command_str,
            "scan_time":  elapsed,
        }

    except subprocess.TimeoutExpired:
        return _error_result("WafW00f", target, "Scan timed out after 30 seconds.",
                             command_str, _elapsed(start))
    except FileNotFoundError:
        return _error_result("WafW00f", target,
                             f"WafW00f binary not found at: {WAFW00F_BIN}",
                             command_str, _elapsed(start))
    except Exception as exc:  # noqa: BLE001
        return _error_result("WafW00f", target, str(exc), command_str, _elapsed(start))


# ---------------------------------------------------------------------------
# FUNCTION 4 — Combined Full Fingerprint Scan
# ---------------------------------------------------------------------------

def run_full_fingerprint(target: str, whatweb_aggression: int = 1) -> dict:
    """
    Run all three tools concurrently against the same target.

    Uses ``concurrent.futures.ThreadPoolExecutor`` with max_workers=3 so
    WhatWeb, Wappalyzer, and WafW00f all run in parallel.

    Args:
        target:             URL or domain to scan.
        whatweb_aggression: WhatWeb aggression level passed to run_whatweb().

    Returns:
        Combined result dict with per-tool results nested under ``"results"``
        and a merged ``"summary"`` section.
    """
    target = _normalise_url(target)
    start  = time.time()

    results: dict[str, dict] = {}
    tools_run: list[str]     = []
    tools_skipped: list[str] = []

    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = {
            "whatweb":    executor.submit(run_whatweb,    target, whatweb_aggression),
            "wappalyzer": executor.submit(run_wappalyzer, target),
            "wafw00f":    executor.submit(run_wafw00f,    target),
        }
        for key, future in futures.items():
            try:
                results[key] = future.result(timeout=90)
            except FuturesTimeoutError:
                results[key] = _error_result(
                    key.capitalize(), target,
                    f"{key} timed out during concurrent scan."
                )
            except Exception as exc:  # noqa: BLE001
                results[key] = _error_result(key.capitalize(), target, str(exc))

    for key, r in results.items():
        if r.get("skipped"):
            tools_skipped.append(key.capitalize())
        else:
            tools_run.append(key.capitalize())

    # Build merged summary
    ww   = results.get("whatweb",    {})
    wa   = results.get("wappalyzer", {})
    waf  = results.get("wafw00f",    {})

    ww_details  = ww.get("details",  {})
    wa_details  = wa.get("details",  {})
    waf_details = waf.get("details", {})

    merged_techs  = _merge_technologies(ww, wa)
    waf_name      = waf_details.get("waf_name") if not waf.get("skipped") else None
    waf_detected  = bool(waf_details.get("waf_detected")) if not waf.get("skipped") else False

    security_concerns: list[str] = []
    if ww.get("flagged") and ww_details.get("email_addresses"):
        security_concerns.append(f"Email addresses exposed: {ww_details['email_addresses']}")
    if ww.get("flagged") and any(t.get("version") for t in ww_details.get("technologies", [])):
        security_concerns.append("Technology version numbers exposed (aids targeted exploitation)")
    if not waf_detected and not waf.get("skipped"):
        security_concerns.append("No WAF detected — target appears unprotected")

    overall_flagged = (
        ww.get("flagged", False)
        or wa.get("flagged", False)
        or waf.get("flagged", False)
    )

    return {
        "source":    "Web Fingerprint - Full Scan",
        "target":    target,
        "skipped":   False,
        "error":     False,
        "flagged":   overall_flagged,
        "scan_time": _elapsed(start),
        "results": {
            "whatweb":    ww,
            "wappalyzer": wa,
            "wafw00f":    waf,
        },
        "summary": {
            "cms":                ww_details.get("cms") or _find_cms_in_wappalyzer(wa_details),
            "web_server":         ww_details.get("web_server"),
            "waf":                waf_name,
            "waf_detected":       waf_detected,
            "technologies":       merged_techs,
            "total_technologies": len(merged_techs),
            "frameworks":         ww_details.get("frameworks", []),
            "languages":          ww_details.get("languages", []),
            "security_concerns":  security_concerns,
            "tools_run":          tools_run,
            "tools_skipped":      tools_skipped,
        },
    }


def _find_cms_in_wappalyzer(wa_details: dict) -> Optional[str]:
    """Extract first CMS entry from Wappalyzer summary_by_category."""
    summary = wa_details.get("summary_by_category", {})
    for key in summary:
        if "cms" in key.lower():
            items = summary[key]
            if items:
                return items[0]
    return None


# ---------------------------------------------------------------------------
# FUNCTION 5 — Custom WhatWeb Scan
# ---------------------------------------------------------------------------

def run_whatweb_custom(
    target: str,
    aggression: int,
    user_agent: str,
    extra_plugins: Optional[list[str]] = None,
    cookies: Optional[str] = None,
    proxy: Optional[str] = None,
    no_ssl_verify: bool = False,
) -> dict:
    """
    Advanced WhatWeb scan with full option control.

    Args:
        target:         URL or domain to scan.
        aggression:     WhatWeb aggression level 1–4.
        user_agent:     Custom User-Agent string to send.
        extra_plugins:  List of specific WhatWeb plugin names to enable.
        cookies:        Cookie string for authenticated scanning
                        (e.g. ``"PHPSESSID=abc; token=xyz"``).
        proxy:          Proxy address (e.g. ``"127.0.0.1:8080"`` for Burp Suite).
        no_ssl_verify:  If True, adds ``--no-check-certificate``.

    Returns:
        Result dict matching run_whatweb() schema, with extra ``scan_options`` key.
    """
    if not WHATWEB_BIN:
        return _skipped_result("whatweb", "WhatWeb", target)

    target = _normalise_url(target)
    aggression = max(1, min(4, aggression))

    cmd: list[str] = [
        WHATWEB_BIN,
        f"--aggression={aggression}",
        "--log-json=-",
        "--colour=never",
        "--no-errors",
        "--follow-redirect=always",
    ]
    if user_agent:
        cmd += ["--user-agent", user_agent]
    if cookies:
        cmd += ["--cookie", cookies]
    if proxy:
        cmd += ["--proxy", proxy]
    if no_ssl_verify:
        cmd.append("--no-check-certificate")
    if extra_plugins:
        cmd += ["--plugins", ",".join(extra_plugins)]

    cmd.append(target)
    command_str = " ".join(cmd)
    start = time.time()

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        elapsed = _elapsed(start)
        stdout  = proc.stdout or ""
        stderr  = proc.stderr or ""

        if proc.returncode not in (0, 1) and not stdout.strip():
            return _error_result("WhatWeb", target, stderr or "WhatWeb exited unexpectedly.",
                                 command_str, elapsed)

        parsed_entries = _parse_whatweb_json(stdout)
        details = _extract_whatweb_details(parsed_entries, target)
        details["scan_options"] = {
            "aggression":    aggression,
            "user_agent":    user_agent or "default",
            "cookies":       bool(cookies),
            "proxy":         proxy or "none",
            "no_ssl_verify": no_ssl_verify,
            "extra_plugins": extra_plugins or [],
        }

        has_versions = any(t.get("version") for t in details["technologies"])
        has_emails   = bool(details["email_addresses"])
        flagged = has_versions or has_emails

        return {
            "source":     "WhatWeb",
            "target":     target,
            "skipped":    False,
            "error":      False,
            "flagged":    flagged,
            "details":    details,
            "raw_output": stdout[:4000],
            "command":    command_str,
            "scan_time":  elapsed,
        }

    except subprocess.TimeoutExpired:
        return _error_result("WhatWeb", target, "Scan timed out after 60 seconds.",
                             command_str, _elapsed(start))
    except Exception as exc:  # noqa: BLE001
        return _error_result("WhatWeb", target, str(exc), command_str, _elapsed(start))
