"""
url_intel.py — URL reputation and scanning functions.

Each function:
  - Checks CONFIG for required API key; skips gracefully if missing.
  - Makes authenticated HTTP requests with a 10-second timeout.
  - Returns a structured dict: source, skipped, error, flagged, risk_score, details.

No unhandled exceptions are raised — all errors produce an error-flagged result dict.
"""

from __future__ import annotations

import base64
import os
import sys
import time
from typing import Any

import requests

# Resolve project root so this module is importable standalone
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import CONFIG  # noqa: E402
from modules.utils import console  # noqa: E402

_TIMEOUT = 10


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _skipped(source: str) -> dict:
    """Return a skipped-result dict (no API key configured)."""
    return {"source": source, "skipped": True, "error": False, "flagged": False, "risk_score": None}


def _error(source: str, msg: str) -> dict:
    """Return an error-result dict."""
    return {
        "source":     source,
        "skipped":    False,
        "error":      True,
        "flagged":    False,
        "risk_score": None,
        "details":    {"Error": msg},
    }


# ---------------------------------------------------------------------------
# 1. VirusTotal URL Check
# ---------------------------------------------------------------------------

def check_virustotal_url(url: str) -> dict:
    """
    Submit a URL to VirusTotal for analysis and retrieve engine-detection results.

    Two-step: POST to submit → GET to retrieve analysis stats.

    Args:
        url: The URL string to analyse.

    Returns:
        Structured result dict with malicious/suspicious/harmless engine counts
        and a permalink to the VirusTotal report.
    """
    source = "VirusTotal"
    key = CONFIG.get("virustotal")
    if not key:
        return _skipped(source)

    headers = {"x-apikey": key, "Accept": "application/json"}

    # Step 1 — submit URL for analysis
    try:
        submit_resp = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=_TIMEOUT,
        )
        if submit_resp.status_code == 429:
            return _error(source, "Rate limit hit (429). Try again later.")
        if submit_resp.status_code in (401, 403):
            return _error(source, "Invalid API key — check config.yaml.")
        submit_resp.raise_for_status()
        analysis_id = submit_resp.json()["data"]["id"]
    except requests.exceptions.RequestException as exc:
        return _error(source, str(exc))
    except (KeyError, ValueError):
        return _error(source, "Unexpected response format on URL submission.")

    # Step 2 — retrieve analysis result
    try:
        result_resp = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers,
            timeout=_TIMEOUT,
        )
        result_resp.raise_for_status()
        data  = result_resp.json()
        stats = data["data"]["attributes"]["stats"]
        mal   = stats.get("malicious", 0)
        sus   = stats.get("suspicious", 0)
        total = sum(stats.values()) or 1

        # Build a stable permalink using base64url-encoded URL
        url_id    = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        permalink = f"https://www.virustotal.com/gui/url/{url_id}"

        return {
            "source":     source,
            "skipped":    False,
            "error":      False,
            "flagged":    mal > 0 or sus > 0,
            "risk_score": round((mal / total) * 100),
            "details": {
                "Malicious Engines":  mal,
                "Suspicious Engines": sus,
                "Harmless Engines":   stats.get("harmless", 0),
                "Undetected Engines": stats.get("undetected", 0),
                "Total Engines":      total,
                "Permalink":          permalink,
            },
        }
    except requests.exceptions.RequestException as exc:
        return _error(source, str(exc))
    except (KeyError, ValueError):
        return _error(source, "Could not parse analysis result.")


# ---------------------------------------------------------------------------
# 2. PhishTank
# ---------------------------------------------------------------------------

def check_phishtank(url: str) -> dict:
    """
    Check a URL against the PhishTank phishing database.

    Works without an API key but is heavily rate-limited; provide a key in
    config.yaml for better throughput.

    Args:
        url: The URL string to check.

    Returns:
        Structured result dict indicating whether the URL is a known phish.
    """
    source = "PhishTank"
    key = CONFIG.get("phishtank")  # optional

    url_b64 = base64.b64encode(url.encode()).decode()
    payload: dict[str, Any] = {"url": url_b64, "format": "json"}
    if key:
        payload["app_key"] = key

    try:
        resp = requests.post(
            "https://checkurl.phishtank.com/checkurl/",
            data=payload,
            headers={"User-Agent": "phishtank/ThreatScope"},
            timeout=_TIMEOUT,
        )
        if resp.status_code == 429:
            return _error(source, "Rate limit hit (429). Try again later.")
        resp.raise_for_status()

        data     = resp.json().get("results", {})
        in_db    = data.get("in_database", False)
        verified = data.get("verified", False)
        valid    = data.get("valid", False)

        return {
            "source":     source,
            "skipped":    False,
            "error":      False,
            "flagged":    bool(in_db and verified and valid),
            "risk_score": 100 if (in_db and verified) else 0,
            "details": {
                "In Database":      str(in_db),
                "Verified Phish":   str(verified),
                "Valid (Active)":   str(valid),
                "Phish ID":         data.get("phish_id", "N/A"),
                "Phish Detail URL": data.get("phish_detail_page", "N/A"),
            },
        }
    except requests.exceptions.RequestException as exc:
        return _error(source, str(exc))
    except (KeyError, ValueError):
        return _error(source, "Unexpected PhishTank response format.")


# ---------------------------------------------------------------------------
# 3. Google Safe Browsing
# ---------------------------------------------------------------------------

def check_google_safe_browsing(url: str) -> dict:
    """
    Check a URL against the Google Safe Browsing v4 Lookup API.

    Detects: MALWARE, SOCIAL_ENGINEERING, UNWANTED_SOFTWARE,
    POTENTIALLY_HARMFUL_APPLICATION, MALICIOUS_BINARY.

    Args:
        url: The URL string to check.

    Returns:
        Structured result dict with threat types detected (empty = clean).
    """
    source = "Google Safe Browsing"
    key = CONFIG.get("google_safe_browsing")
    if not key:
        return _skipped(source)

    payload = {
        "client": {"clientId": "ThreatScope", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
                "MALICIOUS_BINARY",
            ],
            "platformTypes":    ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries":    [{"url": url}],
        },
    }

    try:
        resp = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}",
            json=payload,
            timeout=_TIMEOUT,
        )
        if resp.status_code == 429:
            return _error(source, "Rate limit hit (429). Try again later.")
        if resp.status_code in (401, 403):
            return _error(source, "Invalid API key — check config.yaml.")
        resp.raise_for_status()

        matches      = resp.json().get("matches", [])
        threat_types = [m.get("threatType", "UNKNOWN") for m in matches]
        platforms    = list({m.get("platformType", "") for m in matches})

        return {
            "source":     source,
            "skipped":    False,
            "error":      False,
            "flagged":    len(matches) > 0,
            "risk_score": 100 if matches else 0,
            "details": {
                "Threats Found": len(matches),
                "Threat Types":  ", ".join(threat_types) if threat_types else "None",
                "Platforms":     ", ".join(p for p in platforms if p) or "N/A",
                "Status":        "MALICIOUS" if matches else "CLEAN",
            },
        }
    except requests.exceptions.RequestException as exc:
        return _error(source, str(exc))
    except (KeyError, ValueError):
        return _error(source, "Unexpected Google Safe Browsing response format.")


# ---------------------------------------------------------------------------
# 4. URLScan.io
# ---------------------------------------------------------------------------

def scan_urlscan(url: str) -> dict:
    """
    Submit a URL to URLScan.io for a live browser scan and retrieve results.

    Two-step: POST to submit → wait 15 s → GET result.

    Args:
        url: The URL string to scan.

    Returns:
        Structured result dict with verdict, score, page metadata, and contacted
        domains/IPs.
    """
    source = "URLScan.io"
    key = CONFIG.get("urlscan")
    if not key:
        return _skipped(source)

    headers = {"API-Key": key, "Content-Type": "application/json"}

    # Step 1 — submit scan
    try:
        submit_resp = requests.post(
            "https://urlscan.io/api/v1/scan/",
            json={"url": url, "visibility": "public"},
            headers=headers,
            timeout=_TIMEOUT,
        )
        if submit_resp.status_code == 429:
            return _error(source, "Rate limit hit (429). Try again later.")
        if submit_resp.status_code in (401, 403):
            return _error(source, "Invalid API key — check config.yaml.")
        submit_resp.raise_for_status()

        scan_data     = submit_resp.json()
        scan_uuid     = scan_data["uuid"]
        scan_link     = scan_data.get("result", "")
    except requests.exceptions.RequestException as exc:
        return _error(source, str(exc))
    except (KeyError, ValueError):
        return _error(source, "Unexpected URLScan submission response.")

    # Step 2 — wait, then fetch result
    console.print("  [dim]URLScan.io: Waiting 15 s for scan to complete…[/dim]")
    time.sleep(15)

    try:
        result_resp = requests.get(
            f"https://urlscan.io/api/v1/result/{scan_uuid}/",
            headers=headers,
            timeout=_TIMEOUT,
        )
        result_resp.raise_for_status()

        data      = result_resp.json()
        verdicts  = data.get("verdicts", {}).get("overall", {})
        page      = data.get("page", {})
        stats     = data.get("stats", {})
        lists     = data.get("lists", {})

        malicious = verdicts.get("malicious", False)
        score     = verdicts.get("score", 0)
        domains   = lists.get("domains", [])[:10]
        ips       = lists.get("ips", [])[:10]

        return {
            "source":     source,
            "skipped":    False,
            "error":      False,
            "flagged":    bool(malicious),
            "risk_score": score,
            "details": {
                "Malicious":          str(malicious),
                "Overall Score":      score,
                "Page Domain":        page.get("domain", "N/A"),
                "Page IP":            page.get("ip", "N/A"),
                "Country":            page.get("country", "N/A"),
                "Total Requests":     stats.get("requests", "N/A"),
                "Domains Contacted":  ", ".join(domains) if domains else "N/A",
                "IPs Contacted":      ", ".join(ips) if ips else "N/A",
                "Result URL":         scan_link,
            },
        }
    except requests.exceptions.RequestException as exc:
        return _error(source, str(exc))
    except (KeyError, ValueError):
        return _error(source, "Could not parse URLScan result.")


# ---------------------------------------------------------------------------
# 5. APIVoid URL Reputation
# ---------------------------------------------------------------------------

def check_apivoid_url(url: str) -> dict:
    """
    Check a URL against APIVoid's URL Reputation API.

    Returns risk score, malicious flag, blacklist detection count, and engine count.

    Args:
        url: The URL string to check.

    Returns:
        Structured result dict.
    """
    source = "APIVoid"
    key = CONFIG.get("apivoid")
    if not key:
        return _skipped(source)

    try:
        resp = requests.get(
            "https://endpoint.apivoid.com/urlrep/v1/pay-as-you-go/",
            params={"key": key, "url": url},
            timeout=_TIMEOUT,
        )
        if resp.status_code == 429:
            return _error(source, "Rate limit hit (429). Try again later.")
        if resp.status_code in (401, 403):
            return _error(source, "Invalid API key — check config.yaml.")
        resp.raise_for_status()

        report      = resp.json().get("data", {}).get("report", {})
        risk_info   = report.get("risk_score", {})
        risk_score  = risk_info.get("result", 0)
        is_malicious = risk_info.get("is_malicious", False)
        blacklists  = report.get("blacklists", {})
        detections  = blacklists.get("detections", 0)
        engines     = blacklists.get("engines_count", 0)

        return {
            "source":     source,
            "skipped":    False,
            "error":      False,
            "flagged":    bool(is_malicious),
            "risk_score": float(risk_score),
            "details": {
                "Risk Score":   risk_score,
                "Is Malicious": str(is_malicious),
                "Detections":   f"{detections} / {engines}",
                "Domain":       report.get("domain_name", "N/A"),
            },
        }
    except requests.exceptions.RequestException as exc:
        return _error(source, str(exc))
    except (KeyError, ValueError):
        return _error(source, "Unexpected APIVoid response format.")
