"""
hash_intel.py — File hash and malware intelligence functions.

Each function:
  - Checks CONFIG for required API key; skips gracefully if missing.
  - Makes HTTP requests with a 15-second timeout.
  - Returns a structured dict: source, skipped, error, flagged, details.

No unhandled exceptions are raised — all errors produce an error-flagged result dict.
"""

from __future__ import annotations

import hashlib
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import CONFIG  # noqa: E402

REQUEST_TIMEOUT = 15

# ---------------------------------------------------------------------------
# Hash type detection patterns
# ---------------------------------------------------------------------------

MD5_RE    = re.compile(r'^[a-fA-F0-9]{32}$')
SHA1_RE   = re.compile(r'^[a-fA-F0-9]{40}$')
SHA256_RE = re.compile(r'^[a-fA-F0-9]{64}$')


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def detect_hash_type(hash_str: str) -> str:
    """
    Detect the hash algorithm from its length and character set.

    Args:
        hash_str: Hex string to test.

    Returns:
        "md5", "sha1", "sha256", or "unknown"
    """
    s = hash_str.strip()
    if SHA256_RE.match(s):
        return "sha256"
    if SHA1_RE.match(s):
        return "sha1"
    if MD5_RE.match(s):
        return "md5"
    return "unknown"


def _human_size(size_bytes: int) -> str:
    """Convert bytes to a human-readable size string."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    if size_bytes < 1024 ** 2:
        return f"{size_bytes / 1024:.1f} KB"
    if size_bytes < 1024 ** 3:
        return f"{size_bytes / (1024 ** 2):.1f} MB"
    return f"{size_bytes / (1024 ** 3):.1f} GB"


def _fmt_ts(unix_ts: int | None) -> str:
    """Format a Unix timestamp as 'YYYY-MM-DD HH:MM UTC'."""
    if not unix_ts:
        return "N/A"
    try:
        return datetime.fromtimestamp(int(unix_ts), tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    except (ValueError, OSError):
        return "N/A"


def compute_file_hashes(file_path: str) -> dict:
    """
    Compute MD5, SHA1, and SHA256 of a local file.

    Reads in 8192-byte chunks to handle large files efficiently.

    Args:
        file_path: Absolute or relative path to the file.

    Returns:
        dict with keys: md5, sha1, sha256, file_size_bytes, file_size_human, filename.

    Raises:
        FileNotFoundError: if path doesn't exist.
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    md5    = hashlib.md5()
    sha1   = hashlib.sha1()
    sha256 = hashlib.sha256()

    with open(path, "rb") as fh:
        while chunk := fh.read(8192):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    size = path.stat().st_size
    return {
        "md5":             md5.hexdigest(),
        "sha1":            sha1.hexdigest(),
        "sha256":          sha256.hexdigest(),
        "file_size_bytes": size,
        "file_size_human": _human_size(size),
        "filename":        path.name,
    }


def _skipped_result(source: str, reason: str = "no API key configured") -> dict:
    """
    Return a standardised skipped result dict.

    Args:
        source: API source name.
        reason: Human-readable reason for skipping.

    Returns:
        Structured skipped result dict.
    """
    return {
        "source":  source,
        "skipped": True,
        "flagged": False,
        "error":   False,
        "details": {"Reason": reason},
    }


def _error_result(source: str, message: str) -> dict:
    """
    Return a standardised error result dict.

    Args:
        source:  API source name.
        message: Error description.

    Returns:
        Structured error result dict.
    """
    return {
        "source":  source,
        "skipped": False,
        "flagged": False,
        "error":   True,
        "details": {"Error": message},
    }


# ---------------------------------------------------------------------------
# 1. VirusTotal Hash Lookup
# ---------------------------------------------------------------------------

def check_virustotal_hash(hash_str: str) -> dict:
    """
    Look up a file hash (MD5/SHA1/SHA256) via the VirusTotal v3 API.

    Args:
        hash_str: MD5, SHA1, or SHA256 hex string.

    Returns:
        Structured result dict.
    """
    source  = "VirusTotal"
    vt_key  = CONFIG.get("virustotal")
    if not vt_key:
        return _skipped_result(source)

    headers = {"x-apikey": vt_key, "Accept": "application/json"}
    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/files/{hash_str.strip()}",
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code == 404:
            return {
                "source":  source,
                "skipped": False,
                "error":   False,
                "flagged": False,
                "details": {"Status": "Not found in VirusTotal database"},
            }
        if resp.status_code == 429:
            return _error_result(source, "VirusTotal rate limit reached. Free tier: 4 requests/minute.")
        if resp.status_code in (401, 403):
            return _error_result(source, "Invalid API key. Check virustotal key in config.yaml.")
        resp.raise_for_status()

        attrs       = resp.json()["data"]["attributes"]
        stats       = attrs.get("last_analysis_stats", {})
        malicious   = stats.get("malicious",  0)
        suspicious  = stats.get("suspicious", 0)
        harmless    = stats.get("harmless",   0)
        undetected  = stats.get("undetected", 0)
        timeout_cnt = stats.get("timeout",    0)
        total_engines = max(malicious + suspicious + harmless + undetected + timeout_cnt, 1)

        sha256_val = attrs.get("sha256", "")
        size_bytes = attrs.get("size", 0)
        rep_score  = attrs.get("reputation", 0)
        tags_list  = attrs.get("tags", [])

        # Top detections (first 10 malicious engines)
        top_detections: list[str] = []
        for eng, res in attrs.get("last_analysis_results", {}).items():
            if res.get("category") == "malicious" and len(top_detections) < 10:
                detection_name = res.get("result") or "unknown"
                top_detections.append(f"{eng}: {detection_name}")

        return {
            "source":  source,
            "skipped": False,
            "error":   False,
            "flagged": malicious > 0,
            "details": {
                "Hash (queried)":  hash_str,
                "MD5":             attrs.get("md5",  "N/A"),
                "SHA1":            attrs.get("sha1", "N/A"),
                "SHA256":          sha256_val or "N/A",
                "File Type":       attrs.get("type_description", "N/A"),
                "File Size":       _human_size(size_bytes) if size_bytes else "N/A",
                "Common Name":     attrs.get("meaningful_name", "N/A"),
                "Malicious":       f"{malicious} / {total_engines} engines",
                "Suspicious":      f"{suspicious} / {total_engines} engines",
                "Harmless":        f"{harmless} / {total_engines} engines",
                "Undetected":      f"{undetected} / {total_engines} engines",
                "Community Score": f"+{rep_score}" if rep_score >= 0 else str(rep_score),
                "First Seen":      _fmt_ts(attrs.get("first_submission_date")),
                "Last Analysed":   _fmt_ts(attrs.get("last_analysis_date")),
                "Times Submitted": str(attrs.get("times_submitted", "N/A")),
                "Tags":            ", ".join(tags_list) if tags_list else "None",
                "Top Detections":  top_detections if top_detections else ["None"],
                "VT Report":       f"https://www.virustotal.com/gui/file/{sha256_val}" if sha256_val else "N/A",
            },
        }
    except requests.exceptions.RequestException as exc:
        return _error_result(source, str(exc))
    except (KeyError, ValueError, TypeError):
        return _error_result(source, "Unexpected VirusTotal response format.")


# ---------------------------------------------------------------------------
# 2. MalwareBazaar Hash Lookup
# ---------------------------------------------------------------------------

def check_malwarebazaar(hash_str: str) -> dict:
    """
    Look up a file hash via MalwareBazaar (abuse.ch). No API key required.

    Args:
        hash_str: MD5, SHA1, or SHA256 hex string.

    Returns:
        Structured result dict.
    """
    source = "MalwareBazaar"
    try:
        resp = requests.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_info", "hash": hash_str.strip()},
            headers={
                "Accept":       "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent":   "ThreatScope/1.0",
            },
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code == 429:
            return _error_result(source, "MalwareBazaar rate limit reached. Try again later.")
        if resp.status_code in (401, 403):
            return _error_result(
                source,
                "MalwareBazaar returned 401 — the API may be temporarily blocking requests "
                "or your IP is rate-limited. Try again in a few minutes.",
            )
        resp.raise_for_status()
        body = resp.json()

        if body.get("query_status") in ("hash_not_found", "no_results"):
            return {
                "source":  source,
                "skipped": False,
                "error":   False,
                "flagged": False,
                "details": {"Status": "Hash not found in MalwareBazaar database"},
            }

        data       = body.get("data", [{}])[0]
        sha256_val = data.get("sha256_hash", "")
        file_size  = data.get("file_size", 0)

        # Vendor detections (max 8)
        vendor_detections: list[str] = []
        for vendor, vdata in (data.get("vendor_intel") or {}).items():
            if isinstance(vdata, dict) and vdata.get("detection"):
                vendor_detections.append(f"{vendor}: {vdata['detection']}")
            if len(vendor_detections) >= 8:
                break

        # YARA rule names (max 5)
        yara_rules: list[str] = [
            r.get("rule_name", "unknown")
            for r in (data.get("yara_rules") or [])[:5]
        ]

        tags_list  = data.get("tags") or []
        intel      = data.get("intelligence") or {}

        return {
            "source":  source,
            "skipped": False,
            "error":   False,
            "flagged": True,
            "details": {
                "Hash (queried)":    hash_str,
                "SHA256":            sha256_val or "N/A",
                "MD5":               data.get("md5_hash",  "N/A"),
                "SHA1":              data.get("sha1_hash", "N/A"),
                "File Name":         data.get("file_name", "N/A"),
                "File Type":         data.get("file_type", "N/A"),
                "MIME Type":         data.get("file_type_mime", "N/A"),
                "File Size":         _human_size(int(file_size)) if file_size else "N/A",
                "Malware Signature": data.get("signature", "N/A"),
                "Tags":              ", ".join(tags_list) if tags_list else "None",
                "First Seen":        data.get("first_seen", "N/A"),
                "Last Seen":         data.get("last_seen", "N/A"),
                "Reporter":          data.get("reporter", "N/A"),
                "Origin Country":    data.get("origin_country", "N/A"),
                "Downloads":         str(intel.get("downloads", "N/A")),
                "Seen in Malspam":   "Yes" if intel.get("mail") else "No",
                "YARA Matches":      yara_rules if yara_rules else ["None"],
                "Vendor Detections": vendor_detections if vendor_detections else ["None"],
                "ImpHash":           data.get("imphash", "N/A"),
                "Sample URL":        f"https://bazaar.abuse.ch/sample/{sha256_val}/" if sha256_val else "N/A",
            },
        }
    except requests.exceptions.RequestException as exc:
        return _error_result(source, str(exc))
    except (KeyError, ValueError, IndexError, TypeError):
        return _error_result(source, "Unexpected MalwareBazaar response format.")


# ---------------------------------------------------------------------------
# 3. Hybrid Analysis Sandbox Lookup
# ---------------------------------------------------------------------------

def check_hybrid_analysis(hash_str: str) -> dict:
    """
    Look up a hash via Hybrid Analysis (Falcon Sandbox). Free API key required.

    MD5/SHA1 use the search endpoint; SHA256 returns the fullest results.

    Args:
        hash_str: MD5, SHA1, or SHA256 hex string.

    Returns:
        Structured result dict.
    """
    source = "Hybrid Analysis"
    ha_key = CONFIG.get("hybrid_analysis")
    if not ha_key:
        return _skipped_result(source)

    headers = {
        "api-key":    ha_key,
        "User-Agent": "Falcon Sandbox",
        "Accept":     "application/json",
    }
    try:
        resp = requests.post(
            "https://www.hybrid-analysis.com/api/v2/search/hash",
            data={"hash": hash_str.strip()},
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code == 429:
            return _error_result(source, "Hybrid Analysis rate limit reached. Try again later.")
        if resp.status_code in (401, 403):
            return _error_result(source, "Invalid API key. Check hybrid_analysis key in config.yaml.")
        resp.raise_for_status()

        results = resp.json()
        if not results or not isinstance(results, list):
            return {
                "source":  source,
                "skipped": False,
                "error":   False,
                "flagged": False,
                "details": {"Status": "Hash not found in Hybrid Analysis database"},
            }

        r          = results[0]
        verdict    = r.get("verdict", "unknown")
        t_score    = int(r.get("threat_score") or 0)
        sha256_val = r.get("sha256", "")
        size_bytes = r.get("size", 0)
        av_detect  = r.get("av_detect", 0)
        flagged    = verdict in ("malicious", "suspicious") or t_score >= 50

        # Contacted domains / IPs (max 10 each)
        domains: list[str] = [str(d) for d in (r.get("domains") or [])[:10]]
        hosts:   list[str] = [str(h) for h in (r.get("hosts")   or [])[:10]]

        # Dropped files (max 5)
        dropped: list[str] = []
        for f in (r.get("extracted_files") or [])[:5]:
            name  = f.get("name", "unknown")
            ftype = f.get("type_short", "")
            dropped.append(f"{name} ({ftype})" if ftype else name)

        # MITRE ATT&CK (max 10)
        mitre: list[str] = []
        for m in (r.get("mitre_attcks") or [])[:10]:
            tactic    = m.get("tactic", "")
            tech_id   = m.get("technique_id", "")
            technique = m.get("technique", "")
            mitre.append(f"TA: {tactic} | T: {tech_id} {technique}")

        # Classification tags (max 8)
        family_tags: list[str] = [str(t) for t in (r.get("classification_tags") or [])[:8]]

        return {
            "source":  source,
            "skipped": False,
            "error":   False,
            "flagged": flagged,
            "details": {
                "Hash (queried)":      hash_str,
                "SHA256":              sha256_val or "N/A",
                "Verdict":             verdict,
                "Threat Score":        f"{t_score} / 100",
                "AV Detection":        f"{av_detect}%",
                "File Name":           r.get("submit_name", "N/A"),
                "File Type":           r.get("type_short",  "N/A"),
                "File Size":           _human_size(int(size_bytes)) if size_bytes else "N/A",
                "Sandbox Environment": r.get("environment_description", "N/A"),
                "Analysis Date":       r.get("analysis_start_time", "N/A"),
                "Total Processes":     str(r.get("total_processes", "N/A")),
                "Network Connections": str(r.get("total_network_connections", "N/A")),
                "Contacted Domains":   domains     if domains     else ["None"],
                "Contacted IPs":       hosts       if hosts       else ["None"],
                "Dropped Files":       dropped     if dropped     else ["None"],
                "Malware Family Tags": family_tags if family_tags else ["None"],
                "MITRE ATT&CK":        mitre       if mitre       else ["None"],
                "HA Report URL":       f"https://www.hybrid-analysis.com/sample/{sha256_val}" if sha256_val else "N/A",
            },
        }
    except requests.exceptions.RequestException as exc:
        return _error_result(source, str(exc))
    except (KeyError, ValueError, TypeError, IndexError):
        return _error_result(source, "Unexpected Hybrid Analysis response format.")


# ---------------------------------------------------------------------------
# 4. Malshare Hash Lookup
# ---------------------------------------------------------------------------

def check_malshare(hash_str: str) -> dict:
    """
    Look up a hash via the Malshare API. Free API key required.

    Args:
        hash_str: MD5, SHA1, or SHA256 hex string.

    Returns:
        Structured result dict.
    """
    source      = "Malshare"
    malshare_key = CONFIG.get("malshare")
    if not malshare_key:
        return _skipped_result(source)

    try:
        resp = requests.get(
            "https://malshare.com/api.php",
            params={"api_key": malshare_key, "action": "details", "hash": hash_str.strip()},
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code == 429:
            return _error_result(source, "Malshare rate limit reached. Free tier: 2000 requests/day.")
        if resp.status_code in (401, 403):
            return _error_result(source, "Invalid API key. Check malshare key in config.yaml.")
        resp.raise_for_status()

        data = resp.json()

        if isinstance(data, dict) and "ERROR" in data:
            err_msg = data["ERROR"].get("message", str(data["ERROR"]))
            if "not found" in str(err_msg).lower():
                return {
                    "source":  source,
                    "skipped": False,
                    "error":   False,
                    "flagged": False,
                    "details": {"Status": "Hash not found in Malshare database"},
                }
            return _error_result(source, str(err_msg))

        # Known filenames (first 3)
        filenames_raw = data.get("F_NAME") or []
        if isinstance(filenames_raw, str):
            filenames_raw = [filenames_raw]
        known_filenames = ", ".join(filenames_raw[:3]) if filenames_raw else "N/A"

        # Source URLs (max 3)
        sources_raw = data.get("SOURCES") or []
        if isinstance(sources_raw, str):
            sources_raw = [sources_raw]
        source_urls: list[str] = [str(u) for u in sources_raw[:3]]

        return {
            "source":  source,
            "skipped": False,
            "error":   False,
            "flagged": True,
            "details": {
                "Hash (queried)":  hash_str,
                "SHA256":          data.get("SHA256", "N/A"),
                "MD5":             data.get("MD5",    "N/A"),
                "SHA1":            data.get("SHA1",   "N/A"),
                "File Type":       data.get("F_TYPE", "N/A"),
                "SSDeep Hash":     data.get("SSDEEP", "N/A"),
                "Known Filenames": known_filenames,
                "Source URLs":     source_urls if source_urls else ["N/A"],
                "Sample URL":      f"https://malshare.com/sample.php?action=detail&hash={hash_str}",
            },
        }
    except requests.exceptions.RequestException as exc:
        return _error_result(source, str(exc))
    except (KeyError, ValueError, TypeError):
        return _error_result(source, "Unexpected Malshare response format.")


# ---------------------------------------------------------------------------
# 5. ThreatFox IOC Lookup
# ---------------------------------------------------------------------------

def check_threatfox(hash_str: str) -> dict:
    """
    Look up a hash IOC via ThreatFox (abuse.ch). No API key required.

    Args:
        hash_str: MD5, SHA1, or SHA256 hex string.

    Returns:
        Structured result dict.
    """
    source = "ThreatFox"
    try:
        resp = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "search_ioc", "search_term": hash_str.strip()},
            headers={
                "Content-Type": "application/json",
                "User-Agent":   "ThreatScope/1.0",
                "Accept":       "application/json",
            },
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code == 429:
            return _error_result(source, "ThreatFox rate limit reached. Try again later.")
        if resp.status_code in (401, 403):
            return _error_result(
                source,
                "ThreatFox returned 401 — the API may be temporarily blocking requests "
                "or your IP is rate-limited. Try again in a few minutes.",
            )
        resp.raise_for_status()
        body = resp.json()

        if body.get("query_status") == "no_result":
            return {
                "source":  source,
                "skipped": False,
                "error":   False,
                "flagged": False,
                "details": {"Status": "Hash not found in ThreatFox database"},
            }

        data_list = body.get("data") or []
        if not data_list:
            return {
                "source":  source,
                "skipped": False,
                "error":   False,
                "flagged": False,
                "details": {"Status": "No results returned from ThreatFox"},
            }

        families:    set[str]  = set()
        threat_types: set[str] = set()
        max_confidence         = 0
        first_seen_dates:  list[str] = []
        last_seen_dates:   list[str] = []
        all_entries:       list[str] = []
        first_entry = data_list[0]

        for entry in data_list:
            family = entry.get("malware_printable") or entry.get("malware") or ""
            if family:
                families.add(family)
            t_type = entry.get("threat_type", "")
            if t_type:
                threat_types.add(t_type)
            conf = int(entry.get("confidence_level") or 0)
            if conf > max_confidence:
                max_confidence = conf
            if entry.get("first_seen"):
                first_seen_dates.append(entry["first_seen"])
            if entry.get("last_seen"):
                last_seen_dates.append(entry["last_seen"])
            all_entries.append(
                f"Family: {family or 'unknown'} | "
                f"Type: {entry.get('threat_type', 'N/A')} | "
                f"Confidence: {conf}% | "
                f"Seen: {entry.get('first_seen', 'N/A')}"
            )

        first_ioc_id = first_entry.get("ioc_id", "")
        tags_raw     = first_entry.get("tags") or []

        return {
            "source":  source,
            "skipped": False,
            "error":   False,
            "flagged": True,
            "details": {
                "Hash (queried)":    hash_str,
                "Total IOC Entries": str(len(data_list)),
                "Malware Families":  ", ".join(sorted(families))    if families     else "Unknown",
                "Threat Types":      ", ".join(sorted(threat_types)) if threat_types else "N/A",
                "Max Confidence":    f"{max_confidence} / 100",
                "First Seen":        min(first_seen_dates) if first_seen_dates else "N/A",
                "Last Seen":         max(last_seen_dates)  if last_seen_dates  else "N/A",
                "Reporter":          first_entry.get("reporter", "N/A"),
                "Tags":              ", ".join(tags_raw) if tags_raw else "None",
                "Reference":         first_entry.get("reference", "N/A"),
                "ThreatFox URL":     f"https://threatfox.abuse.ch/ioc/{first_ioc_id}/" if first_ioc_id else "N/A",
                "All Entries":       all_entries,
            },
        }
    except requests.exceptions.RequestException as exc:
        return _error_result(source, str(exc))
    except (KeyError, ValueError, TypeError, IndexError):
        return _error_result(source, "Unexpected ThreatFox response format.")


# ---------------------------------------------------------------------------
# File Upload — VirusTotal
# ---------------------------------------------------------------------------

def upload_to_virustotal(file_path: str) -> dict:
    """
    Upload a file to VirusTotal for scanning. Returns the analysis result.

    Handles files up to 32 MB via standard endpoint and 32–650 MB via
    the large-file upload URL. Polls up to 12 times (2 minutes) for completion.

    Args:
        file_path: Path to the local file to upload.

    Returns:
        Structured result dict.
    """
    source = "VirusTotal"
    vt_key = CONFIG.get("virustotal")
    if not vt_key:
        return _skipped_result(source)

    if not os.path.isfile(file_path):
        return _error_result(source, f"File not found: {file_path}")

    file_size = os.path.getsize(file_path)
    if file_size > 650 * 1024 * 1024:
        return _error_result(source, "File too large for VirusTotal (max 650 MB).")

    filename = os.path.basename(file_path)
    headers  = {"x-apikey": vt_key}

    try:
        with open(file_path, "rb") as fh:
            file_bytes = fh.read()

        # Get large-file upload URL if needed
        if file_size > 32 * 1024 * 1024:
            url_resp = requests.get(
                "https://www.virustotal.com/api/v3/files/upload_url",
                headers=headers,
                timeout=REQUEST_TIMEOUT,
            )
            url_resp.raise_for_status()
            upload_url = url_resp.json().get("data", "https://www.virustotal.com/api/v3/files")
        else:
            upload_url = "https://www.virustotal.com/api/v3/files"

        upload_resp = requests.post(
            upload_url,
            headers=headers,
            files={"file": (filename, file_bytes, "application/octet-stream")},
            timeout=120,
        )
        if upload_resp.status_code == 429:
            return _error_result(source, "VirusTotal rate limit reached. Free tier: 4 requests/minute.")
        if upload_resp.status_code in (401, 403):
            return _error_result(source, "Invalid API key. Check virustotal key in config.yaml.")
        upload_resp.raise_for_status()

        analysis_id = upload_resp.json()["data"]["id"]

        # Poll for completion (max 12 attempts, 10 s delay)
        poll_headers = {"x-apikey": vt_key, "Accept": "application/json"}
        poll_data: dict = {}
        poll_resp_obj = None
        for _ in range(12):
            time.sleep(10)
            poll_resp_obj = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=poll_headers,
                timeout=REQUEST_TIMEOUT,
            )
            poll_resp_obj.raise_for_status()
            poll_data = poll_resp_obj.json()["data"]["attributes"]
            if poll_data.get("status") == "completed":
                break
        else:
            return _error_result(source, "Analysis timed out after 2 minutes.")

        stats       = poll_data.get("stats", {})
        malicious   = stats.get("malicious",  0)
        suspicious  = stats.get("suspicious", 0)
        harmless    = stats.get("harmless",   0)
        undetected  = stats.get("undetected", 0)
        timeout_cnt = stats.get("timeout",    0)
        total_engines = max(malicious + suspicious + harmless + undetected + timeout_cnt, 1)

        top_detections: list[str] = []
        for eng, res in (poll_data.get("results") or {}).items():
            if res.get("category") == "malicious" and len(top_detections) < 10:
                top_detections.append(f"{eng}: {res.get('result', 'unknown')}")

        # SHA256 from meta (if present)
        sha256_val = ""
        if poll_resp_obj:
            meta       = poll_resp_obj.json().get("meta", {})
            sha256_val = meta.get("file_info", {}).get("sha256", "")

        return {
            "source":  source,
            "skipped": False,
            "error":   False,
            "flagged": malicious > 0,
            "details": {
                "Upload Status":   "File uploaded and analysed",
                "File Name":       filename,
                "File Size":       _human_size(file_size),
                "SHA256":          sha256_val or "N/A",
                "Malicious":       f"{malicious} / {total_engines} engines",
                "Suspicious":      f"{suspicious} / {total_engines} engines",
                "Harmless":        f"{harmless} / {total_engines} engines",
                "Undetected":      f"{undetected} / {total_engines} engines",
                "Top Detections":  top_detections if top_detections else ["None"],
                "VT Report":       f"https://www.virustotal.com/gui/file/{sha256_val}" if sha256_val else "N/A",
            },
        }
    except requests.exceptions.RequestException as exc:
        return _error_result(source, str(exc))
    except (KeyError, ValueError, TypeError):
        return _error_result(source, "Unexpected VirusTotal response format during upload.")


# ---------------------------------------------------------------------------
# File Upload — Hybrid Analysis
# ---------------------------------------------------------------------------

_HA_ENVIRONMENTS: dict[int, str] = {
    110: "Windows 7 32-bit",
    120: "Windows 7 64-bit",
    160: "Windows 10 64-bit",
    300: "Linux (Ubuntu 16.04 64-bit)",
    200: "Android",
}


def upload_to_hybrid_analysis(file_path: str, environment_id: int = 160) -> dict:
    """
    Upload a file to Hybrid Analysis sandbox for detonation.

    Polls up to 20 times (5 minutes) for completion, then calls
    check_hybrid_analysis() to return normalised results.

    Args:
        file_path:       Path to the local file to upload.
        environment_id:  Sandbox environment ID. Default: 160 (Windows 10 64-bit).
                         Options: 110 (Win7 32), 120 (Win7 64), 160 (Win10 64),
                                  300 (Linux), 200 (Android)

    Returns:
        Structured result dict.
    """
    source = "Hybrid Analysis"
    ha_key = CONFIG.get("hybrid_analysis")
    if not ha_key:
        return _skipped_result(source)

    if not os.path.isfile(file_path):
        return _error_result(source, f"File not found: {file_path}")

    file_size = os.path.getsize(file_path)
    if file_size > 100 * 1024 * 1024:
        return _error_result(source, "File too large for Hybrid Analysis (max 100 MB).")

    filename = os.path.basename(file_path)
    headers  = {
        "api-key":    ha_key,
        "User-Agent": "Falcon Sandbox",
        "Accept":     "application/json",
    }

    try:
        with open(file_path, "rb") as fh:
            file_bytes = fh.read()

        submit_resp = requests.post(
            "https://www.hybrid-analysis.com/api/v2/submit/file",
            headers=headers,
            files={"file": (filename, file_bytes, "application/octet-stream")},
            data={"environment_id": str(environment_id)},
            timeout=120,
        )
        if submit_resp.status_code == 429:
            return _error_result(source, "Hybrid Analysis rate limit reached.")
        if submit_resp.status_code in (401, 403):
            return _error_result(source, "Invalid API key. Check hybrid_analysis key in config.yaml.")
        submit_resp.raise_for_status()

        submit_data = submit_resp.json()
        job_id      = submit_data.get("job_id", "")
        sha256_val  = submit_data.get("sha256", "")

        if not job_id:
            return _error_result(source, "No job_id returned from Hybrid Analysis submission.")

        # Poll for completion (max 20 attempts × 15 s = 5 minutes)
        for _ in range(20):
            time.sleep(15)
            summary_resp = requests.get(
                f"https://www.hybrid-analysis.com/api/v2/report/{job_id}/summary",
                headers=headers,
                timeout=REQUEST_TIMEOUT,
            )
            summary_resp.raise_for_status()
            if summary_resp.json().get("state") == "SUCCESS":
                break
        else:
            return _error_result(source, "Sandbox analysis timed out after 5 minutes.")

        # Fetch normalised results
        result = check_hybrid_analysis(sha256_val if sha256_val else hash_str)  # type: ignore[name-defined]
        if isinstance(result.get("details"), dict):
            env_name = _HA_ENVIRONMENTS.get(environment_id, f"Environment {environment_id}")
            result["details"]["Submission Status"] = "File submitted to sandbox"
            result["details"]["Environment"]       = env_name

        return result

    except requests.exceptions.RequestException as exc:
        return _error_result(source, str(exc))
    except (KeyError, ValueError, TypeError):
        return _error_result(source, "Unexpected Hybrid Analysis response format during upload.")
