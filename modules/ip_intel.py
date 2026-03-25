"""
ip_intel.py — IP reputation, geolocation, and enrichment functions.

Each function:
  - Checks CONFIG for required API key; skips gracefully if missing.
  - Makes HTTP requests with a 10-second timeout.
  - Returns a structured dict: source, skipped, error, flagged, risk_score, details.

No unhandled exceptions are raised — all errors produce an error-flagged result dict.
"""

from __future__ import annotations

import os
import sys

import requests

# Resolve project root so this module is importable standalone
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import CONFIG  # noqa: E402

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
# 1. VirusTotal IP Check
# ---------------------------------------------------------------------------

def check_virustotal_ip(ip: str) -> dict:
    """
    Query VirusTotal for reputation data on an IP address.

    Extracts malicious / suspicious / harmless vote counts, AS owner,
    country, and a reputation score.

    Args:
        ip: IPv4 or IPv6 address string.

    Returns:
        Structured result dict.
    """
    source = "VirusTotal"
    key = CONFIG.get("virustotal")
    if not key:
        return _skipped(source)

    headers = {"x-apikey": key, "Accept": "application/json"}
    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers=headers,
            timeout=_TIMEOUT,
        )
        if resp.status_code == 429:
            return _error(source, "Rate limit hit (429). Try again later.")
        if resp.status_code in (401, 403):
            return _error(source, "Invalid API key — check config.yaml.")
        resp.raise_for_status()

        attrs = resp.json()["data"]["attributes"]
        stats = attrs.get("last_analysis_stats", {})
        mal   = stats.get("malicious", 0)
        sus   = stats.get("suspicious", 0)
        total = sum(stats.values()) or 1

        return {
            "source":     source,
            "skipped":    False,
            "error":      False,
            "flagged":    mal > 0,
            "risk_score": round((mal / total) * 100),
            "details": {
                "Malicious Engines":  mal,
                "Suspicious Engines": sus,
                "Harmless Engines":   stats.get("harmless", 0),
                "Reputation Score":   attrs.get("reputation", "N/A"),
                "Country":            attrs.get("country", "N/A"),
                "AS Owner":           attrs.get("as_owner", "N/A"),
                "Permalink":          f"https://www.virustotal.com/gui/ip-address/{ip}",
            },
        }
    except requests.exceptions.RequestException as exc:
        return _error(source, str(exc))
    except (KeyError, ValueError):
        return _error(source, "Unexpected VirusTotal response format.")


# ---------------------------------------------------------------------------
# 2. AbuseIPDB
# ---------------------------------------------------------------------------

def check_abuseipdb(ip: str) -> dict:
    """
    Check an IP against AbuseIPDB for historical abuse reports.

    Extracts confidence score, total reports, ISP, country, and usage type.

    Args:
        ip: IPv4 or IPv6 address string.

    Returns:
        Structured result dict.
    """
    source = "AbuseIPDB"
    key = CONFIG.get("abuseipdb")
    if not key:
        return _skipped(source)

    headers = {"Key": key, "Accept": "application/json"}
    params  = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": "true"}

    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers=headers,
            params=params,
            timeout=_TIMEOUT,
        )
        if resp.status_code == 429:
            return _error(source, "Rate limit hit (429). Try again later.")
        if resp.status_code in (401, 403):
            return _error(source, "Invalid API key — check config.yaml.")
        resp.raise_for_status()

        data  = resp.json().get("data", {})
        score = data.get("abuseConfidenceScore", 0)

        return {
            "source":     source,
            "skipped":    False,
            "error":      False,
            "flagged":    score >= 25,
            "risk_score": score,
            "details": {
                "Abuse Confidence Score": f"{score}%",
                "Total Reports":          data.get("totalReports", 0),
                "Country":                data.get("countryCode", "N/A"),
                "ISP":                    data.get("isp", "N/A"),
                "Domain":                 data.get("domain", "N/A"),
                "Usage Type":             data.get("usageType", "N/A"),
                "Is Whitelisted":         data.get("isWhitelisted", False),
                "Is Public IP":           data.get("isPublic", True),
                "Last Reported At":       data.get("lastReportedAt", "N/A"),
            },
        }
    except requests.exceptions.RequestException as exc:
        return _error(source, str(exc))
    except (KeyError, ValueError):
        return _error(source, "Unexpected AbuseIPDB response format.")


# ---------------------------------------------------------------------------
# 3. GreyNoise Community
# ---------------------------------------------------------------------------

def check_greynoise_ip(ip: str) -> dict:
    """
    Query GreyNoise Community API to classify internet-scanning noise for an IP.

    Classifies IPs as benign, malicious, or unknown and indicates whether
    the IP is part of common internet infrastructure (RIOT).

    Args:
        ip: IPv4 address string.

    Returns:
        Structured result dict.
    """
    source = "GreyNoise"
    key = CONFIG.get("greynoise")
    if not key:
        return _skipped(source)

    headers = {"key": key, "Accept": "application/json"}
    try:
        resp = requests.get(
            f"https://api.greynoise.io/v3/community/{ip}",
            headers=headers,
            timeout=_TIMEOUT,
        )
        if resp.status_code == 404:
            return {
                "source":     source,
                "skipped":    False,
                "error":      False,
                "flagged":    False,
                "risk_score": 0,
                "details": {
                    "Noise":          "false",
                    "RIOT":           "false",
                    "Classification": "not seen",
                    "Message":        "IP not present in the GreyNoise dataset.",
                },
            }
        if resp.status_code == 429:
            return _error(source, "Rate limit hit (429). Try again later.")
        if resp.status_code in (401, 403):
            return _error(source, "Invalid API key — check config.yaml.")
        resp.raise_for_status()

        data           = resp.json()
        classification = data.get("classification", "unknown")
        is_malicious   = classification == "malicious"

        return {
            "source":     source,
            "skipped":    False,
            "error":      False,
            "flagged":    is_malicious,
            "risk_score": 100 if is_malicious else (50 if classification == "unknown" else 0),
            "details": {
                "Noise":                  str(data.get("noise", False)),
                "RIOT (Common Services)": str(data.get("riot", False)),
                "Classification":         classification,
                "Name":                   data.get("name", "N/A"),
                "Link":                   data.get("link", "N/A"),
            },
        }
    except requests.exceptions.RequestException as exc:
        return _error(source, str(exc))
    except (KeyError, ValueError):
        return _error(source, "Unexpected GreyNoise response format.")


# ---------------------------------------------------------------------------
# 4. AlienVault OTX
# ---------------------------------------------------------------------------

def check_alienvault_ip(ip: str) -> dict:
    """
    Query AlienVault OTX for threat intelligence on an IP address.

    Retrieves general metadata plus reputation / threat score from two
    OTX endpoints and aggregates pulse data (malware families, tags).

    Args:
        ip: IPv4 address string.

    Returns:
        Structured result dict.
    """
    source = "AlienVault OTX"
    key = CONFIG.get("alienvault_otx")
    if not key:
        return _skipped(source)

    headers = {"X-OTX-API-KEY": key, "Accept": "application/json"}

    try:
        # General info
        gen_resp = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
            headers=headers,
            timeout=_TIMEOUT,
        )
        gen_resp.raise_for_status()
        gen = gen_resp.json()

        pulse_info  = gen.get("pulse_info", {})
        pulse_count = pulse_info.get("count", 0)
        pulses      = pulse_info.get("pulses", [])

        tags: list[str] = []
        for p in pulses[:5]:
            tags.extend(p.get("tags", []))
        tags = list(set(tags))[:10]

        malware_families: set[str] = set()
        for p in pulses:
            for mf in p.get("malware_families", []):
                if mf:
                    malware_families.add(mf)

        # Reputation score (separate endpoint)
        rep_score = 0
        try:
            rep_resp = requests.get(
                f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/reputation",
                headers=headers,
                timeout=_TIMEOUT,
            )
            rep_resp.raise_for_status()
            rep_score = rep_resp.json().get("reputation", {}).get("threat_score", 0) or 0
        except Exception:  # noqa: BLE001
            pass

        return {
            "source":     source,
            "skipped":    False,
            "error":      False,
            "flagged":    pulse_count > 0 or rep_score > 0,
            "risk_score": min(100, int(rep_score)),
            "details": {
                "Pulse Count":       pulse_count,
                "Threat Score":      rep_score,
                "Country":           gen.get("country_name", "N/A"),
                "ASN":               gen.get("asn", "N/A"),
                "Tags":              ", ".join(tags) if tags else "None",
                "Malware Families":  ", ".join(sorted(malware_families)) if malware_families else "None",
            },
        }
    except requests.exceptions.RequestException as exc:
        return _error(source, str(exc))
    except (KeyError, ValueError):
        return _error(source, "Unexpected OTX response format.")


# ---------------------------------------------------------------------------
# 5. Shodan IP Lookup
# ---------------------------------------------------------------------------

def lookup_shodan_ip(ip: str) -> dict:
    """
    Look up an IP on Shodan to retrieve open ports, services, and known CVEs.

    Args:
        ip: IPv4 address string.

    Returns:
        Structured result dict.
    """
    source = "Shodan"
    key = CONFIG.get("shodan")
    if not key:
        return _skipped(source)

    try:
        resp = requests.get(
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": key},
            timeout=_TIMEOUT,
        )
        if resp.status_code == 404:
            return {
                "source":     source,
                "skipped":    False,
                "error":      False,
                "flagged":    False,
                "risk_score": 0,
                "details":    {"Message": "IP not found in the Shodan index."},
            }
        if resp.status_code == 429:
            return _error(source, "Rate limit hit (429). Try again later.")
        if resp.status_code in (401, 403):
            return _error(source, "Invalid API key — check config.yaml.")
        resp.raise_for_status()

        data      = resp.json()
        ports     = data.get("ports", [])
        vulns     = list(data.get("vulns", {}).keys())
        hostnames = data.get("hostnames", [])

        return {
            "source":     source,
            "skipped":    False,
            "error":      False,
            "flagged":    len(vulns) > 0,
            "risk_score": min(100, len(vulns) * 15),
            "details": {
                "Organisation": data.get("org", "N/A"),
                "ISP":          data.get("isp", "N/A"),
                "Country":      data.get("country_name", "N/A"),
                "OS":           data.get("os", "N/A"),
                "Open Ports":   ", ".join(str(p) for p in sorted(ports)[:20]) if ports else "None",
                "Hostnames":    ", ".join(hostnames[:5]) if hostnames else "None",
                "CVEs Found":   ", ".join(vulns[:10]) if vulns else "None",
                "Total CVEs":   len(vulns),
            },
        }
    except requests.exceptions.RequestException as exc:
        return _error(source, str(exc))
    except (KeyError, ValueError):
        return _error(source, "Unexpected Shodan response format.")


# ---------------------------------------------------------------------------
# 6. IPInfo
# ---------------------------------------------------------------------------

def get_ipinfo(ip: str) -> dict:
    """
    Query IPInfo for geolocation and network metadata on an IP address.

    Works without an API key (limited to 50 k requests/month on the free tier).
    Providing a key removes rate limits.

    Args:
        ip: IPv4 or IPv6 address string.

    Returns:
        Structured result dict (informational — never flags an IP as malicious).
    """
    source = "IPInfo"
    key    = CONFIG.get("ipinfo")  # optional

    params: dict = {}
    if key:
        params["token"] = key

    try:
        resp = requests.get(
            f"https://ipinfo.io/{ip}/json",
            params=params,
            timeout=_TIMEOUT,
        )
        if resp.status_code == 429:
            return _error(source, "Rate limit hit (429). Try again later.")
        resp.raise_for_status()

        data = resp.json()
        return {
            "source":     source,
            "skipped":    False,
            "error":      False,
            "flagged":    False,    # IPInfo is informational only
            "risk_score": None,
            "details": {
                "Hostname":           data.get("hostname", "N/A"),
                "Organisation":       data.get("org", "N/A"),
                "City":               data.get("city", "N/A"),
                "Region":             data.get("region", "N/A"),
                "Country":            data.get("country", "N/A"),
                "Location (lat/lng)": data.get("loc", "N/A"),
                "Timezone":           data.get("timezone", "N/A"),
                "Postal Code":        data.get("postal", "N/A"),
                "Anycast":            str(data.get("anycast", False)),
            },
        }
    except requests.exceptions.RequestException as exc:
        return _error(source, str(exc))
    except (KeyError, ValueError):
        return _error(source, "Unexpected IPInfo response format.")
