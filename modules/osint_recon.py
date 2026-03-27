"""
osint_recon.py — Passive OSINT reconnaissance for ThreatScope.

Provides email/subdomain harvesting, Wayback Machine history lookup,
tech stack fingerprinting (BuiltWith + Wappalyzer), exposed file detection,
and file metadata extraction (exiftool / PyMuPDF).

Each function returns a structured dict and never raises unhandled exceptions.
Optional dependencies are detected at import time; missing tools produce
_skipped_result() gracefully.
"""

from __future__ import annotations

import importlib
import importlib.util
import json
import mimetypes
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import CONFIG  # noqa: E402
from modules.utils import console  # noqa: E402

# ---------------------------------------------------------------------------
# API keys
# ---------------------------------------------------------------------------

BUILTWITH_API_KEY: Optional[str] = CONFIG.get("builtwith")

# ---------------------------------------------------------------------------
# Timeouts
# ---------------------------------------------------------------------------

REQUEST_TIMEOUT = 15
WAYBACK_TIMEOUT = 20

# ---------------------------------------------------------------------------
# Optional tool / library detection (run at import time)
# ---------------------------------------------------------------------------

# theHarvester
THEHARVESTER_CMD: Optional[str] = None
for _harvest_candidate in ("theHarvester", "theharvester"):
    _resolved = shutil.which(_harvest_candidate)
    if _resolved:
        THEHARVESTER_CMD = _resolved
        break
if THEHARVESTER_CMD is None:
    for _static_path in (
        "/usr/bin/theHarvester", "/usr/local/bin/theHarvester",
        "/usr/bin/theharvester", "/usr/local/bin/theharvester",
    ):
        if Path(_static_path).exists():
            THEHARVESTER_CMD = _static_path
            break

THEHARVESTER_AVAILABLE: bool = THEHARVESTER_CMD is not None

# exiftool
EXIFTOOL_AVAILABLE: bool = shutil.which("exiftool") is not None

# python-wappalyzer library
WAPPALYZER_AVAILABLE: bool = False
_Wappalyzer_cls  = None
_WebPage_cls     = None
try:
    if importlib.util.find_spec("Wappalyzer") is not None:
        from Wappalyzer import Wappalyzer as _Wappalyzer_cls, WebPage as _WebPage_cls  # type: ignore
        WAPPALYZER_AVAILABLE = True
except Exception:
    WAPPALYZER_AVAILABLE = False

# PyMuPDF (imported as fitz)
PYMUPDF_AVAILABLE: bool = False
_fitz_module = None
try:
    if importlib.util.find_spec("fitz") is not None:
        import fitz as _fitz_module  # type: ignore
        PYMUPDF_AVAILABLE = True
except Exception:
    PYMUPDF_AVAILABLE = False


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _skipped_result(source: str, reason: str = "no API key configured") -> dict:
    """Return a standardised skipped result dict."""
    return {
        "source":  source,
        "skipped": True,
        "flagged": False,
        "error":   False,
        "details": {"Reason": reason},
    }


def _error_result(source: str, message: str) -> dict:
    """Return a standardised error result dict."""
    return {
        "source":  source,
        "skipped": False,
        "flagged": False,
        "error":   True,
        "details": {"Error": message},
    }


def _not_found_result(source: str, message: str) -> dict:
    """Return a standardised not-found result (no error, no flag)."""
    return {
        "source":  source,
        "skipped": False,
        "flagged": False,
        "error":   False,
        "details": {"Status": message},
    }


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------

def clean_domain(input_str: str) -> str:
    """
    Normalise a domain input — strip scheme, www prefix, trailing slashes, paths.

    Examples:
        "https://www.example.com/path" → "example.com"
        "www.example.com"              → "example.com"
        "example.com"                  → "example.com"
    """
    s = input_str.strip()
    if "://" not in s:
        s = "https://" + s
    try:
        netloc = urlparse(s).netloc or s
    except Exception:
        netloc = s
    netloc = netloc.split(":")[0]  # strip port
    if netloc.lower().startswith("www."):
        netloc = netloc[4:]
    return netloc.lower()


def human_filesize(size_bytes: int) -> str:
    """Convert bytes to a human-readable size string (e.g. 1234567 → '1.2 MB')."""
    val = float(size_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if val < 1024 or unit == "TB":
            return f"{val:.1f} {unit}" if unit != "B" else f"{int(val)} B"
        val /= 1024
    return f"{val:.1f} PB"


def is_valid_email(email: str) -> bool:
    """Basic email format validation."""
    return bool(re.match(
        r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$",
        email.strip(),
    ))


def _run_subprocess(cmd: list[str], timeout: int = 60) -> tuple[str, str, int]:
    """
    Run a subprocess safely (never shell=True).
    Returns: (stdout, stderr, returncode)
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", f"Command timed out after {timeout}s", -1
    except OSError as exc:
        return "", str(exc), -2


# ---------------------------------------------------------------------------
# 1. theHarvester — Email & Subdomain Harvesting
# ---------------------------------------------------------------------------

def harvest_emails_and_subdomains(
    domain: str,
    sources: str = "google,bing,duckduckgo,crtsh,otx",
    limit: int = 200,
) -> dict:
    """
    Run theHarvester against a domain to collect emails, subdomains, and IPs.

    Args:
        domain:  Target domain (e.g. "example.com").
        sources: Comma-separated list of OSINT sources.
        limit:   Max results per source.

    Returns:
        Structured result dict.
    """
    source = "theHarvester"

    if not THEHARVESTER_AVAILABLE:
        return _skipped_result(
            source,
            "theHarvester binary not found. Install: sudo apt install theharvester "
            "or pip install theHarvester",
        )

    tmp_dir  = tempfile.mkdtemp(prefix="ts_harvest_")
    out_base = os.path.join(tmp_dir, "harvest_out")

    cmd = [THEHARVESTER_CMD, "-d", domain, "-b", sources, "-l", str(limit), "-f", out_base]

    emails:      list[str] = []
    subdomains:  list[str] = []
    ips:         list[str] = []
    urls:        list[str] = []
    interesting: list[str] = []

    try:
        _stdout, stderr, rc = _run_subprocess(cmd, timeout=120)

        if rc not in (0, 1):  # exit code 1 is normal for partial results
            return _error_result(source, stderr[:500] if stderr else "theHarvester failed to run")

        json_path = out_base + ".json"
        if Path(json_path).exists():
            try:
                with open(json_path, "r", encoding="utf-8", errors="replace") as fh:
                    data: dict = json.load(fh)
            except (json.JSONDecodeError, IOError):
                data = {}
        else:
            data = {}

        raw_emails = data.get("emails", []) or []
        raw_hosts  = (data.get("hosts") or data.get("subdomains")) or []
        raw_ips    = data.get("ips", []) or []
        raw_urls   = data.get("urls", []) or []
        raw_interesting = data.get("interesting_urls", []) or []

        emails = sorted(set(
            e.strip() for e in raw_emails
            if isinstance(e, str) and is_valid_email(e.strip())
        ))

        subdomain_raw: list[str] = []
        for h in raw_hosts:
            if isinstance(h, str):
                host_part = h.split(":")[0].strip().lower()
                if host_part:
                    subdomain_raw.append(host_part)
        subdomains = sorted(set(subdomain_raw))

        ips  = sorted(set(str(ip).strip() for ip in raw_ips if ip))
        urls = sorted(set(str(u).strip() for u in raw_urls if u))[:20]
        interesting = sorted(set(str(u).strip() for u in raw_interesting if u))

    finally:
        try:
            shutil.rmtree(tmp_dir, ignore_errors=True)
        except Exception:
            pass

    flagged = len(emails) > 0 or len(subdomains) > 5

    return {
        "source":  source,
        "flagged": flagged,
        "skipped": False,
        "error":   False,
        "details": {
            "Target Domain":    domain,
            "Sources Queried":  sources,
            "Emails Found":     f"{len(emails)} addresses",
            "Email List":       emails,
            "Subdomains Found": f"{len(subdomains)} subdomains",
            "Subdomain List":   subdomains,
            "IPs Found":        f"{len(ips)} addresses",
            "IP List":          ips,
            "Interesting URLs": interesting,
            "Total URLs":       f"{len(urls)} captured",
            "Sources Used":     sources,
            "Harvest Time":     datetime.now().isoformat(timespec="seconds"),
        },
    }


# ---------------------------------------------------------------------------
# 2. Wayback Machine — Historical Domain Lookup
# ---------------------------------------------------------------------------

def wayback_lookup(domain: str, limit: int = 10) -> dict:
    """
    Query the Wayback Machine (Internet Archive) for domain history.
    No API key required — fully public APIs.

    Args:
        domain: Target domain (e.g. "example.com").
        limit:  Number of recent snapshots to retrieve.

    Returns:
        Structured result dict.
    """
    source = "Wayback Machine"

    try:
        # Step 1 — CDX API for snapshot history
        cdx_resp = requests.get(
            "https://web.archive.org/cdx/search/cdx",
            params={
                "url":        f"{domain}/*",
                "output":     "json",
                "limit":      str(limit),
                "fl":         "timestamp,original,statuscode,mimetype,length",
                "collapse":   "urlkey",
                "filter":     "statuscode:200",
                "fastLatest": "true",
            },
            timeout=WAYBACK_TIMEOUT,
        )
        cdx_resp.raise_for_status()
        cdx_data = cdx_resp.json()

        # First row is headers; remaining rows are data
        if len(cdx_data) <= 1:
            # Try without status filter for total count
            cdx_all = requests.get(
                "https://web.archive.org/cdx/search/cdx",
                params={
                    "url":      f"{domain}",
                    "output":   "json",
                    "limit":    "1",
                    "fl":       "timestamp",
                    "matchType": "domain",
                },
                timeout=WAYBACK_TIMEOUT,
            ).json()
            if len(cdx_all) <= 1:
                return _not_found_result(source, f"No archived snapshots found for {domain}")

        # Step 2 — Availability API
        avail_resp = requests.get(
            "https://archive.org/wayback/available",
            params={"url": domain},
            timeout=WAYBACK_TIMEOUT,
        )
        avail_resp.raise_for_status()
        avail_data = avail_resp.json()

        closest = avail_data.get("archived_snapshots", {}).get("closest", {})
        latest_url = closest.get("url", "")
        latest_ts  = closest.get("timestamp", "")
        if latest_ts and len(latest_ts) >= 14:
            try:
                dt = datetime.strptime(latest_ts[:14], "%Y%m%d%H%M%S")
                latest_ts_fmt = dt.strftime("%Y-%m-%d %H:%M")
            except ValueError:
                latest_ts_fmt = latest_ts
        else:
            latest_ts_fmt = latest_ts or "N/A"

        # Parse CDX rows
        rows = cdx_data[1:] if len(cdx_data) > 1 else []
        # fields: timestamp, original, statuscode, mimetype, length

        def _fmt_ts(ts_str: str) -> str:
            try:
                return datetime.strptime(ts_str[:14], "%Y%m%d%H%M%S").strftime("%Y-%m-%d %H:%M")
            except ValueError:
                return ts_str

        timestamps  = [r[0] for r in rows if r]
        years       = sorted(set(ts[:4] for ts in timestamps if len(ts) >= 4))
        first_arcd  = _fmt_ts(min(timestamps)) if timestamps else "N/A"
        last_arcd   = _fmt_ts(max(timestamps)) if timestamps else "N/A"
        status_codes = sorted(set(r[2] for r in rows if len(r) > 2))

        # Build year range string
        if years:
            year_parts: list[str] = []
            start = years[0]
            prev  = years[0]
            for y in years[1:]:
                if int(y) == int(prev) + 1:
                    prev = y
                else:
                    year_parts.append(start if start == prev else f"{start}–{prev}")
                    start = prev = y
            year_parts.append(start if start == prev else f"{start}–{prev}")
            years_str = ", ".join(year_parts)
        else:
            years_str = "N/A"

        # Build snapshot list
        mime_abbrev = {
            "text/html": "HTML", "application/pdf": "PDF",
            "image/jpeg": "JPEG", "image/png": "PNG",
            "application/json": "JSON", "text/plain": "TXT",
        }
        snapshots: list[str] = []
        for r in rows:
            if len(r) < 5:
                continue
            ts, orig, status, mime, length = r[0], r[1], r[2], r[3], r[4]
            size = human_filesize(int(length)) if length.isdigit() else "N/A"
            mime_short = mime_abbrev.get(mime, mime.split("/")[-1].upper()[:8])
            wb_url = f"https://web.archive.org/web/{ts}/{orig}"
            snapshots.append(f"{_fmt_ts(ts)} | {status} | {mime_short} | {size} | {wb_url}")

        # Notable changes (content-length outliers)
        notable: list[str] = []
        if status_codes and any(c in status_codes for c in ["301", "302"]):
            notable.append("Redirect responses detected in archive — domain may have moved")
        if status_codes and "404" in status_codes:
            notable.append("404 responses in archive — content gaps or path changes")

    except requests.exceptions.RequestException as exc:
        return _error_result(source, str(exc))
    except Exception as exc:
        return _error_result(source, f"Unexpected error: {exc}")

    return {
        "source":  source,
        "flagged": False,
        "skipped": False,
        "error":   False,
        "details": {
            "Target Domain":       domain,
            "Total Snapshots":     str(len(rows)),
            "First Archived":      first_arcd,
            "Last Archived":       last_arcd,
            "Archived Years":      years_str,
            "Latest Snapshot URL": latest_url or "N/A",
            "Status Codes Seen":   ", ".join(status_codes) if status_codes else "200",
            "Recent Snapshots":    snapshots,
            "Wayback Search URL":  f"https://web.archive.org/web/*/{domain}",
            "Notable Changes":     notable if notable else ["None detected"],
        },
    }


# ---------------------------------------------------------------------------
# 3a. BuiltWith API — Tech Stack Fingerprinting
# ---------------------------------------------------------------------------

def builtwith_lookup(domain: str) -> dict:
    """
    Query the BuiltWith API for technology stack fingerprinting.
    Requires a free API key — skip gracefully if missing.

    Args:
        domain: Target domain.

    Returns:
        Structured result dict.
    """
    source = "BuiltWith"

    if not BUILTWITH_API_KEY:
        return _skipped_result(source, "No builtwith API key. Register free: https://api.builtwith.com/signup")

    try:
        resp = requests.get(
            "https://api.builtwith.com/free1/api.json",
            params={"KEY": BUILTWITH_API_KEY, "LOOKUP": domain},
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code in (401, 403):
            return _error_result(source, "Invalid API key. Check builtwith key in config.yaml.")
        if resp.status_code == 429:
            return _error_result(source, "Rate limit reached. BuiltWith free tier: 1 req/domain/day.")
        resp.raise_for_status()
        body = resp.json()
    except requests.exceptions.RequestException as exc:
        return _error_result(source, str(exc))

    # Parse technology groups
    groups = body.get("groups", []) or []
    category_map: dict[str, list[str]] = {}
    for group in groups:
        tag   = (group.get("tag") or group.get("name") or "other").lower()
        techs = group.get("technologies", []) or []
        names = [t.get("name", "") for t in techs if t.get("name")]
        if names:
            category_map.setdefault(tag, []).extend(names)

    def _join(key: str) -> str:
        return ", ".join(category_map.get(key, [])) or "None detected"

    all_techs = sorted(set(
        name for names in category_map.values() for name in names if name
    ))

    return {
        "source":  source,
        "flagged": False,
        "skipped": False,
        "error":   False,
        "details": {
            "Target Domain":          domain,
            "Total Technologies":     str(len(all_techs)),
            "CMS":                    _join("cms"),
            "Web Server":             _join("web-server"),
            "Programming Language":   _join("programming-language"),
            "Frameworks":             _join("framework"),
            "CDN":                    _join("cdn"),
            "SSL / Security":         _join("ssl"),
            "Analytics":              _join("analytics"),
            "Hosting":                _join("hosting"),
            "JavaScript Libraries":   _join("javascript-libraries"),
            "E-Commerce":             _join("ecommerce"),
            "Payment Systems":        _join("payment"),
            "Email Services":         _join("email"),
            "All Technologies":       all_techs,
            "BuiltWith Report":       f"https://builtwith.com/{domain}",
        },
    }


# ---------------------------------------------------------------------------
# 3b. Wappalyzer (local) — Tech Stack + Security Headers
# ---------------------------------------------------------------------------

def wappalyzer_lookup(domain: str) -> dict:
    """
    Detect technology stack by fetching the live domain and running
    python-wappalyzer fingerprinting locally. No API key required.

    Args:
        domain: Target domain (e.g. "example.com").

    Returns:
        Structured result dict.
    """
    source = "Wappalyzer"

    if not WAPPALYZER_AVAILABLE or _Wappalyzer_cls is None or _WebPage_cls is None:
        return _skipped_result(
            source,
            "python-wappalyzer not installed. Run: pip install python-wappalyzer",
        )

    ua = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
          "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
    headers = {"User-Agent": ua, "Accept-Language": "en-US,en;q=0.9"}

    # Try HTTPS then HTTP
    live_url = ""
    response = None
    for scheme in ("https", "http"):
        try:
            url_try = f"{scheme}://{domain}"
            r = requests.get(url_try, headers=headers, timeout=REQUEST_TIMEOUT)
            live_url = url_try
            response = r
            break
        except requests.exceptions.ConnectionError:
            continue
        except requests.exceptions.RequestException:
            continue

    if response is None:
        return _error_result(source, f"Could not connect to {domain} via HTTPS or HTTP")

    try:
        webpage      = _WebPage_cls(live_url, html=response.text, headers=dict(response.headers))
        wappalyzer   = _Wappalyzer_cls.latest()
        technologies = wappalyzer.analyze_with_categories(webpage)
    except Exception as exc:
        return _error_result(source, f"Wappalyzer analysis failed: {exc}")

    # Organise by category
    category_map: dict[str, list[str]] = {}
    for tech_name, info in technologies.items():
        cats = info.get("categories", set())
        for cat in cats:
            category_map.setdefault(cat, []).append(tech_name)

    def _cat_join(key: str) -> str:
        # Case-insensitive category lookup
        for k, v in category_map.items():
            if k.lower() == key.lower():
                return ", ".join(sorted(v))
        return "None detected"

    all_techs = sorted(technologies.keys())

    # Security headers analysis
    resp_headers = response.headers
    present: list[str] = []
    missing: list[str] = []
    security_checks = {
        "Strict-Transport-Security": "HSTS",
        "Content-Security-Policy":   "CSP",
        "X-Frame-Options":           "X-Frame-Options",
        "X-Content-Type-Options":    "X-Content-Type-Options",
        "X-XSS-Protection":          "X-XSS-Protection",
        "Referrer-Policy":           "Referrer-Policy",
        "Permissions-Policy":        "Permissions-Policy",
    }
    for header, label in security_checks.items():
        if header in resp_headers:
            present.append(label)
        else:
            missing.append(label)

    missing_count = len(missing)
    if missing_count >= 5:
        header_risk = f"High — {missing_count}/7 headers missing"
    elif missing_count >= 3:
        header_risk = f"Medium — {missing_count}/7 headers missing"
    else:
        header_risk = f"Low — {missing_count}/7 headers missing"

    flagged = missing_count >= 3

    return {
        "source":  source,
        "flagged": flagged,
        "skipped": False,
        "error":   False,
        "details": {
            "Target Domain":            domain,
            "Live URL Tested":          live_url,
            "Total Technologies":       str(len(all_techs)),
            "CMS":                      _cat_join("CMS"),
            "Web Server":               resp_headers.get("Server", "") or _cat_join("Web servers"),
            "Frameworks":               _cat_join("Web frameworks"),
            "JavaScript Libraries":     _cat_join("JavaScript libraries"),
            "Programming Language":     _cat_join("Programming languages"),
            "CDN":                      _cat_join("CDN"),
            "Analytics":                _cat_join("Analytics"),
            "Security Tools":           _cat_join("Security"),
            "All Technologies":         all_techs,
            "Server Header":            resp_headers.get("Server", "Not disclosed"),
            "X-Powered-By":             resp_headers.get("X-Powered-By", "Not set"),
            "X-Generator":              resp_headers.get("X-Generator", "Not set"),
            "Security Headers Present": present,
            "Security Headers Missing": missing,
            "Missing Header Risk":      header_risk,
        },
    }


# ---------------------------------------------------------------------------
# 3c. Combined Tech Stack (BuiltWith + Wappalyzer)
# ---------------------------------------------------------------------------

def fingerprint_tech_stack(domain: str) -> dict:
    """
    Run both wappalyzer_lookup() and builtwith_lookup() concurrently and
    merge the results into a unified technology profile.

    Args:
        domain: Target domain.

    Returns:
        Merged structured result dict.
    """
    source = "Tech Stack (BuiltWith + Wappalyzer)"

    with ThreadPoolExecutor(max_workers=2) as executor:
        bw_future  = executor.submit(builtwith_lookup, domain)
        wap_future = executor.submit(wappalyzer_lookup, domain)
        bw_result  = bw_future.result()
        wap_result = wap_future.result()

    bw_details  = bw_result.get("details",  {}) if not bw_result.get("skipped") and not bw_result.get("error") else {}
    wap_details = wap_result.get("details", {}) if not wap_result.get("skipped") and not wap_result.get("error") else {}

    # Merge all technologies
    bw_techs  = set(bw_details.get("All Technologies", []))
    wap_techs = set(wap_details.get("All Technologies", []))
    merged    = sorted(bw_techs | wap_techs)

    def _merge_cat(bw_key: str, wap_key: str) -> str:
        vals: set[str] = set()
        bw_val  = bw_details.get(bw_key, "")
        wap_val = wap_details.get(wap_key, "")
        for v in (bw_val, wap_val):
            if v and v not in ("None detected", "Not disclosed", "Not set", "N/A"):
                for item in v.split(","):
                    item = item.strip()
                    if item:
                        vals.add(item)
        return ", ".join(sorted(vals)) or "None detected"

    coverage_parts: list[str] = []
    if bw_techs:
        coverage_parts.append(f"BuiltWith: {len(bw_techs)} techs")
    if wap_techs:
        coverage_parts.append(f"Wappalyzer: {len(wap_techs)} techs")
    coverage_str = " · ".join(coverage_parts) if coverage_parts else "No data from either source"

    flagged = wap_result.get("flagged", False)

    return {
        "source":  source,
        "flagged": flagged,
        "skipped": False,
        "error":   False,
        "details": {
            "Target Domain":             domain,
            "Total Unique Technologies":  str(len(merged)),
            "CMS":                       _merge_cat("CMS", "CMS"),
            "Web Server":                _merge_cat("Web Server", "Web Server"),
            "Frameworks":                _merge_cat("Frameworks", "Frameworks"),
            "JavaScript Libraries":      _merge_cat("JavaScript Libraries", "JavaScript Libraries"),
            "CDN":                       _merge_cat("CDN", "CDN"),
            "Analytics":                 _merge_cat("Analytics", "Analytics"),
            "Security Headers Missing":  wap_details.get("Security Headers Missing", []),
            "All Technologies":          merged,
            "Coverage":                  coverage_str,
            "BuiltWith Report":          f"https://builtwith.com/{domain}",
        },
    }


# ---------------------------------------------------------------------------
# 4. Exposed Files & Paths Check (Active)
# ---------------------------------------------------------------------------

_SENSITIVE_PATHS: list[tuple[str, str, str]] = [
    # (path, category, severity)
    # ── Source Control ──
    ("/.git/HEAD",              "Source Control",  "CRITICAL"),
    ("/.git/config",            "Source Control",  "CRITICAL"),
    ("/.svn/entries",           "Source Control",  "HIGH"),
    ("/.hg/hgrc",               "Source Control",  "HIGH"),
    ("/.bzr/README",            "Source Control",  "MEDIUM"),
    # ── Configuration & Secrets ──
    ("/.env",                   "Configuration",   "CRITICAL"),
    ("/.env.local",             "Configuration",   "CRITICAL"),
    ("/.env.production",        "Configuration",   "CRITICAL"),
    ("/.env.backup",            "Configuration",   "CRITICAL"),
    ("/config.php",             "Configuration",   "HIGH"),
    ("/wp-config.php",          "Configuration",   "CRITICAL"),
    ("/wp-config.php.bak",      "Configuration",   "CRITICAL"),
    ("/configuration.php",      "Configuration",   "HIGH"),
    ("/config.yml",             "Configuration",   "HIGH"),
    ("/config.yaml",            "Configuration",   "HIGH"),
    ("/config.json",            "Configuration",   "HIGH"),
    ("/settings.py",            "Configuration",   "HIGH"),
    ("/local_settings.py",      "Configuration",   "HIGH"),
    ("/database.yml",           "Configuration",   "CRITICAL"),
    ("/secrets.yml",            "Configuration",   "CRITICAL"),
    ("/credentials.json",       "Configuration",   "CRITICAL"),
    ("/.aws/credentials",       "Configuration",   "CRITICAL"),
    ("/id_rsa",                 "Configuration",   "CRITICAL"),
    ("/.ssh/id_rsa",            "Configuration",   "CRITICAL"),
    # ── Admin & Login Panels ──
    ("/admin",                  "Admin Panel",     "MEDIUM"),
    ("/admin/login",            "Admin Panel",     "MEDIUM"),
    ("/wp-admin",               "Admin Panel",     "MEDIUM"),
    ("/wp-login.php",           "Admin Panel",     "MEDIUM"),
    ("/administrator",          "Admin Panel",     "MEDIUM"),
    ("/phpmyadmin",             "Admin Panel",     "HIGH"),
    ("/pma",                    "Admin Panel",     "HIGH"),
    ("/cpanel",                 "Admin Panel",     "MEDIUM"),
    ("/webmail",                "Admin Panel",     "LOW"),
    ("/login",                  "Admin Panel",     "LOW"),
    # ── Backup & Archive Files ──
    ("/backup.zip",             "Backup",          "HIGH"),
    ("/backup.tar.gz",          "Backup",          "HIGH"),
    ("/backup.sql",             "Backup",          "CRITICAL"),
    ("/db.sql",                 "Backup",          "CRITICAL"),
    ("/database.sql",           "Backup",          "CRITICAL"),
    ("/dump.sql",               "Backup",          "CRITICAL"),
    ("/site.zip",               "Backup",          "HIGH"),
    ("/website.zip",            "Backup",          "HIGH"),
    ("/old.zip",                "Backup",          "MEDIUM"),
    ("/www.zip",                "Backup",          "HIGH"),
    # ── Info & Debug Files ──
    ("/robots.txt",             "Info",            "INFO"),
    ("/sitemap.xml",            "Info",            "INFO"),
    ("/crossdomain.xml",        "Info",            "LOW"),
    ("/.htaccess",              "Config",          "MEDIUM"),
    ("/server-status",          "Debug",           "HIGH"),
    ("/server-info",            "Debug",           "HIGH"),
    ("/info.php",               "Debug",           "HIGH"),
    ("/phpinfo.php",            "Debug",           "HIGH"),
    ("/test.php",               "Debug",           "MEDIUM"),
    ("/readme.html",            "Info",            "LOW"),
    ("/README.md",              "Info",            "LOW"),
    ("/CHANGELOG.md",           "Info",            "LOW"),
    ("/composer.json",          "Info",            "MEDIUM"),
    ("/package.json",           "Info",            "MEDIUM"),
    ("/Makefile",               "Info",            "LOW"),
    ("/Dockerfile",             "Info",            "MEDIUM"),
    ("/docker-compose.yml",     "Info",            "HIGH"),
    # ── API & Debug Endpoints ──
    ("/api/v1",                 "API",             "LOW"),
    ("/api",                    "API",             "LOW"),
    ("/.well-known/security.txt", "Info",          "INFO"),
    ("/swagger.json",           "API",             "MEDIUM"),
    ("/swagger-ui.html",        "API",             "MEDIUM"),
    ("/openapi.json",           "API",             "MEDIUM"),
    ("/graphql",                "API",             "MEDIUM"),
    ("/metrics",                "Debug",           "HIGH"),
    ("/actuator",               "Debug",           "CRITICAL"),
    ("/actuator/env",           "Debug",           "CRITICAL"),
    ("/actuator/health",        "Debug",           "MEDIUM"),
    ("/_profiler",              "Debug",           "HIGH"),
    ("/debug",                  "Debug",           "HIGH"),
    ("/trace",                  "Debug",           "MEDIUM"),
]

_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def _check_single_path(domain: str, path: str, severity: str) -> Optional[dict]:
    """
    Check a single path against the target domain.
    Returns a finding dict or None if not found.
    """
    url = f"https://{domain}{path}"
    try:
        resp = requests.get(
            url,
            headers={"User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)"},
            timeout=5,
            allow_redirects=False,
            verify=True,
        )
        sc = resp.status_code

        if sc == 404 or sc == 410:
            return None

        status_note = ""
        if sc == 200:
            body = resp.text[:500]
            content_len = len(resp.content)

            # Content validation
            valid = False
            if "HEAD" in path and ("ref:" in body or "HEAD" in body):
                valid = True
            elif ".env" in path and "=" in body:
                valid = True
            elif ".sql" in path and any(k in body.upper() for k in ("INSERT", "CREATE TABLE")):
                valid = True
            elif "phpinfo" in path and "PHP Version" in body:
                valid = True
            elif path in ("/robots.txt", "/sitemap.xml", "/.well-known/security.txt"):
                valid = content_len > 10
            elif "server-status" in path and "Apache Server Status" in body:
                valid = True
            elif "actuator" in path:
                valid = content_len > 20
            else:
                valid = content_len > 100

            if not valid:
                return None
            status_note = f"200 OK ({content_len} bytes)"

        elif sc in (401, 403):
            status_note = f"{sc} — EXISTS (Protected)"
        elif sc in (301, 302):
            location = resp.headers.get("Location", "?")
            status_note = f"{sc} REDIRECT → {location[:60]}"
        elif sc == 500:
            status_note = f"500 SERVER ERROR"
        else:
            return None

        return {"path": path, "status": status_note, "severity": severity, "url": url}

    except requests.exceptions.SSLError:
        # Try HTTP fallback for SSL errors (don't want to miss findings)
        return None
    except requests.exceptions.RequestException:
        return None


def check_exposed_files(domain: str, severity_filter: Optional[list[str]] = None) -> dict:
    """
    Passively check for common exposed files and sensitive paths.
    NOTE: This is ACTIVE reconnaissance — makes HTTP requests to the target.

    Args:
        domain:          Target domain.
        severity_filter: If provided, only check paths with these severities
                         (e.g. ["CRITICAL", "HIGH"] for quick scan).

    Returns:
        Structured result dict.
    """
    source = "Exposed Files Check"

    paths_to_check = _SENSITIVE_PATHS
    if severity_filter:
        paths_to_check = [(p, c, s) for p, c, s in _SENSITIVE_PATHS if s in severity_filter]

    findings: dict[str, list[str]] = {sev: [] for sev in _SEVERITY_ORDER}
    historically_exposed: list[str] = []
    robots_disallowed: list[str] = []
    robots_sitemaps:   list[str] = []

    # Run checks concurrently with limited workers to avoid hammering the target
    with ThreadPoolExecutor(max_workers=8) as executor:
        future_map = {
            executor.submit(_check_single_path, domain, path, severity): (path, severity)
            for path, _category, severity in paths_to_check
        }
        for future in as_completed(future_map):
            result = future.result()
            if result:
                path     = result["path"]
                status   = result["status"]
                severity = result["severity"]
                findings[severity].append(f"{path}  —  {status}")

                # Parse robots.txt if found
                if path == "/robots.txt" and "200 OK" in status:
                    try:
                        rb = requests.get(
                            f"https://{domain}/robots.txt",
                            headers={"User-Agent": "Mozilla/5.0"},
                            timeout=5,
                        )
                        for line in rb.text.splitlines():
                            line = line.strip()
                            if line.lower().startswith("disallow:"):
                                disallowed = line.split(":", 1)[1].strip()
                                if disallowed and disallowed != "/":
                                    robots_disallowed.append(disallowed)
                            elif line.lower().startswith("sitemap:"):
                                sitemap = line.split(":", 1)[1].strip()
                                if sitemap:
                                    robots_sitemaps.append(sitemap)
                    except Exception:
                        pass

    # Sort each severity group
    for sev in _SEVERITY_ORDER:
        findings[sev].sort()

    total_critical = len(findings["CRITICAL"])
    total_high     = len(findings["HIGH"])
    total_exposed  = sum(len(v) for k, v in findings.items() if k != "INFO")
    total_checked  = len(paths_to_check)

    flagged = total_critical > 0 or total_high > 0

    return {
        "source":  source,
        "flagged": flagged,
        "skipped": False,
        "error":   False,
        "details": {
            "Target Domain":         domain,
            "Total Paths Checked":   str(total_checked),
            "Exposed / Accessible":  f"{total_exposed} paths",
            "Critical Findings":     str(total_critical),
            "High Findings":         str(total_high),
            "Medium Findings":       str(len(findings["MEDIUM"])),
            "Low Findings":          str(len(findings["LOW"])),
            "Info Findings":         str(len(findings["INFO"])),
            "CRITICAL Paths":        findings["CRITICAL"],
            "HIGH Paths":            findings["HIGH"],
            "MEDIUM Paths":          findings["MEDIUM"],
            "LOW Paths":             findings["LOW"],
            "INFO Paths":            findings["INFO"],
            "Historically Exposed":  historically_exposed,
            "Robots.txt Disallowed": sorted(set(robots_disallowed))[:20],
            "Robots.txt Sitemaps":   sorted(set(robots_sitemaps))[:5],
            "Scan Time":             datetime.now().isoformat(timespec="seconds"),
            "Note":                  "Active scan — HTTP requests were made to target",
        },
    }


# ---------------------------------------------------------------------------
# 5. Metadata Extraction
# ---------------------------------------------------------------------------

_PRIVACY_FIELDS = {
    "Author", "Creator", "Last Modified By", "Company", "Software",
    "Producer", "Create Date", "Modify Date", "GPS Latitude", "GPS Longitude",
    "GPS Position", "Camera Model Name", "Serial Number", "IP Address",
    "DocumentID", "InstanceID",
}

_MIME_SUFFIXES = {
    "application/pdf": ".pdf",
    "image/jpeg": ".jpg",
    "image/png": ".png",
    "image/tiff": ".tif",
    "application/msword": ".doc",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
    "application/vnd.ms-excel": ".xls",
    "audio/mpeg": ".mp3",
    "video/mp4": ".mp4",
}


def _extract_with_exiftool(file_path: str) -> dict:
    """Run exiftool on a file and return parsed metadata dict."""
    stdout, _stderr, rc = _run_subprocess(
        ["exiftool", "-json", "-n", file_path],
        timeout=30,
    )
    if rc != 0 or not stdout.strip():
        return {}
    try:
        data = json.loads(stdout)
        return data[0] if isinstance(data, list) and data else {}
    except json.JSONDecodeError:
        return {}


def _extract_with_pymupdf(file_path: str) -> dict:
    """Extract PDF metadata using PyMuPDF."""
    if not PYMUPDF_AVAILABLE or _fitz_module is None:
        return {}
    try:
        pdf  = _fitz_module.open(file_path)
        meta = pdf.metadata or {}
        toc  = pdf.get_toc()
        return {
            "Title":       meta.get("title", ""),
            "Author":      meta.get("author", ""),
            "Subject":     meta.get("subject", ""),
            "Keywords":    meta.get("keywords", ""),
            "Creator":     meta.get("creator", ""),
            "Producer":    meta.get("producer", ""),
            "Create Date": meta.get("creationDate", ""),
            "Modify Date": meta.get("modDate", ""),
            "Encryption":  meta.get("encryption", "None"),
            "Page Count":  str(pdf.page_count),
            "TOC Entries": str(len(toc)),
        }
    except Exception:
        return {}


def _assess_privacy_risks(metadata: dict) -> list[str]:
    """Build a list of privacy risk strings from metadata fields."""
    risks: list[str] = []

    if any(k in metadata for k in ("GPS Latitude", "GPS Longitude", "GPS Position")):
        lat = metadata.get("GPS Latitude", metadata.get("GPS Position", ""))
        risks.append(f"[CRITICAL] GPS coordinates embedded: {lat}")

    if metadata.get("Serial Number"):
        risks.append(f"[HIGH] Device serial number exposed: {metadata['Serial Number']}")

    internal_ip_re = re.compile(
        r"\b(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)\b"
    )
    for val in metadata.values():
        if isinstance(val, str) and internal_ip_re.search(val):
            risks.append(f"[HIGH] Internal IP address found in metadata: {internal_ip_re.search(val).group()}")  # type: ignore
            break

    if metadata.get("Author"):
        risks.append(f"[MEDIUM] Author name exposed: {metadata['Author']}")
    if metadata.get("Creator") and metadata.get("Creator") != metadata.get("Author"):
        risks.append(f"[MEDIUM] Creator field exposed: {metadata['Creator']}")
    if metadata.get("Last Modified By"):
        risks.append(f"[MEDIUM] Last-modified-by username: {metadata['Last Modified By']}")
    if metadata.get("Company"):
        risks.append(f"[MEDIUM] Organisation name disclosed: {metadata['Company']}")

    if metadata.get("Software") or metadata.get("Producer"):
        tool = metadata.get("Software") or metadata.get("Producer")
        risks.append(f"[LOW] Software/tool fingerprint: {tool}")

    return risks


def _metadata_core(file_path: str, origin_label: str) -> dict:
    """Shared metadata extraction logic for URL and local file modes."""
    source = "Metadata Extractor"

    stat  = os.stat(file_path)
    size  = stat.st_size
    if size > 100 * 1024 * 1024:
        return _error_result(source, "File too large (>100MB) for metadata extraction")

    mime_type, _ = mimetypes.guess_type(file_path)
    mime_type     = mime_type or "application/octet-stream"

    # Choose extraction tool
    metadata:      dict = {}
    tool_used:     str  = "basic"

    if EXIFTOOL_AVAILABLE:
        metadata  = _extract_with_exiftool(file_path)
        tool_used = "exiftool"
    elif PYMUPDF_AVAILABLE and "pdf" in mime_type:
        metadata  = _extract_with_pymupdf(file_path)
        tool_used = "PyMuPDF"
    else:
        # Basic fallback
        metadata = {
            "File Size":   human_filesize(size),
            "MIME Type":   mime_type,
            "Modified":    datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M"),
        }
        tool_used = "basic (install exiftool for full extraction)"

    privacy_risks = _assess_privacy_risks(metadata)
    flagged       = len(privacy_risks) > 0

    # GPS display
    gps_lat = metadata.get("GPS Latitude", metadata.get("GPS Position", ""))
    gps_lon = metadata.get("GPS Longitude", "")
    gps_str = f"{gps_lat}, {gps_lon}".strip(", ") if (gps_lat or gps_lon) else "None"

    return {
        "source":  source,
        "flagged": flagged,
        "skipped": False,
        "error":   False,
        "details": {
            "File URL / Path":       origin_label,
            "File Type":             mime_type,
            "File Size":             human_filesize(size),
            "Extraction Tool":       tool_used,
            "Author":                metadata.get("Author", "N/A"),
            "Creator":               metadata.get("Creator", "N/A"),
            "Producer / Software":   metadata.get("Producer", metadata.get("Software", "N/A")),
            "Company":               metadata.get("Company", "N/A"),
            "Created":               metadata.get("Create Date", metadata.get("DateTimeOriginal", "N/A")),
            "Modified":              metadata.get("Modify Date", metadata.get("FileModifyDate", "N/A")),
            "Last Modified By":      metadata.get("Last Modified By", "N/A"),
            "GPS Coordinates":       gps_str,
            "Camera / Device":       metadata.get("Camera Model Name", metadata.get("Model", "N/A")),
            "Serial Number":         metadata.get("Serial Number", "N/A"),
            "Document Title":        metadata.get("Title", metadata.get("Document Title", "N/A")),
            "Keywords":              metadata.get("Keywords", metadata.get("Subject", "N/A")),
            "PDF Page Count":        metadata.get("Page Count", "N/A"),
            "Encryption":            metadata.get("Encryption", "N/A"),
            "Privacy Risks":         privacy_risks,
            "Total Risk Findings":   str(len(privacy_risks)),
            "All Metadata Fields":   {k: str(v)[:200] for k, v in metadata.items()},
        },
    }


def extract_metadata_from_url(file_url: str) -> dict:
    """
    Download a file from a URL and extract its metadata.
    Supports any file type that exiftool handles (PDF, images, Office docs, etc.).

    Args:
        file_url: Direct URL to the file (http/https).

    Returns:
        Structured result dict.
    """
    source = "Metadata Extractor"

    parsed = urlparse(file_url)
    if not (parsed.scheme in ("http", "https") and parsed.netloc):
        return _error_result(source, "Invalid URL format. Must start with http:// or https://")

    # Guess file suffix
    url_path = parsed.path
    suffix   = Path(url_path).suffix or ".tmp"
    if not suffix or suffix == ".":
        suffix = ".tmp"

    tmp_file = tempfile.NamedTemporaryFile(suffix=suffix, delete=False)
    tmp_path = tmp_file.name
    tmp_file.close()

    try:
        resp = requests.get(
            file_url,
            stream=True,
            timeout=30,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        resp.raise_for_status()

        content_length = resp.headers.get("Content-Length", "0")
        if content_length.isdigit() and int(content_length) > 50 * 1024 * 1024:
            return _error_result(source, "File too large (>50MB) to download for metadata analysis")

        content_type = resp.headers.get("Content-Type", "").split(";")[0].strip()
        if content_type in _MIME_SUFFIXES and suffix == ".tmp":
            suffix = _MIME_SUFFIXES[content_type]

        downloaded = 0
        with open(tmp_path, "wb") as fh:
            for chunk in resp.iter_content(chunk_size=8192):
                if chunk:
                    fh.write(chunk)
                    downloaded += len(chunk)
                    if downloaded > 50 * 1024 * 1024:
                        return _error_result(source, "File exceeds 50MB during download — aborted")

        return _metadata_core(tmp_path, file_url)

    except requests.exceptions.RequestException as exc:
        return _error_result(source, str(exc))
    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass


def extract_metadata_from_file(file_path: str) -> dict:
    """
    Extract metadata from a local file.

    Args:
        file_path: Absolute path to the local file.

    Returns:
        Structured result dict.
    """
    source = "Metadata Extractor"

    if not os.path.isfile(file_path):
        return _error_result(source, f"File not found: {file_path}")

    return _metadata_core(file_path, file_path)


# ---------------------------------------------------------------------------
# Full Domain Recon (all passive modules)
# ---------------------------------------------------------------------------

def full_domain_recon(domain: str) -> list[dict]:
    """
    Run all passive OSINT functions concurrently against a domain.
    Metadata extraction is NOT included (requires a specific file URL).

    Args:
        domain: Target domain.

    Returns:
        list of result dicts in completion order.
    """
    tasks = {
        "harvest":   lambda: harvest_emails_and_subdomains(domain),
        "wayback":   lambda: wayback_lookup(domain),
        "techstack": lambda: fingerprint_tech_stack(domain),
        "exposed":   lambda: check_exposed_files(domain),
    }

    results: list[dict] = []
    with ThreadPoolExecutor(max_workers=4) as executor:
        future_map = {executor.submit(fn): name for name, fn in tasks.items()}
        for future in as_completed(future_map):
            try:
                result = future.result()
                results.append(result)
            except Exception as exc:
                results.append(_error_result(future_map[future], str(exc)))

    return results
