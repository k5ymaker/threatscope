"""
dns_tools.py — DNS lookups, reverse DNS, WHOIS, and DNSBL checks.

No API key is required for any function in this module.
All lookups use standard DNS resolution (dnspython) and the python-whois library.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, date
from typing import Any

import dns.resolver
import dns.reversename
import whois


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _stringify_date(value: Any) -> str:
    """Coerce a datetime/date/list-of-dates/string to a clean ISO-8601 string."""
    if value is None:
        return "N/A"
    if isinstance(value, list):
        # whois sometimes returns a list; take the first valid entry
        for item in value:
            result = _stringify_date(item)
            if result != "N/A":
                return result
        return "N/A"
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return str(value)


# DNSBL return-code meanings for zen.spamhaus.org
_SPAMHAUS_CODES: dict[str, str] = {
    "127.0.0.2":  "SBL — Spamhaus Block List (spam source)",
    "127.0.0.3":  "SBL CSS — Snowshoe spam source",
    "127.0.0.4":  "XBL — CBL detected (infected/proxied host)",
    "127.0.0.9":  "SBL DROP — Hijacked/stolen netblock",
    "127.0.0.10": "PBL ISP — ISP-defined policy block",
    "127.0.0.11": "PBL Spamhaus — Spamhaus-defined policy block",
}


# ---------------------------------------------------------------------------
# 1. DNS Lookup
# ---------------------------------------------------------------------------

def dns_lookup(domain: str) -> dict:
    """
    Perform DNS queries for A, AAAA, MX, NS, TXT, CNAME, and SOA records.

    Args:
        domain: The domain name to query.

    Returns:
        Structured dict with source, status, flagged, and a records dict.
    """
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5

    records: dict[str, list[str]] = {}

    for rtype in record_types:
        try:
            answers = resolver.resolve(domain, rtype)
            records[rtype] = [str(rdata) for rdata in answers]
        except dns.resolver.NXDOMAIN:
            return {
                "source":   "DNS Lookup",
                "skipped":  False,
                "error":    True,
                "flagged":  False,
                "risk_score": None,
                "details":  {"Error": f"Domain '{domain}' does not exist (NXDOMAIN)."},
            }
        except dns.resolver.NoAnswer:
            records[rtype] = []
        except dns.exception.Timeout:
            records[rtype] = ["timeout"]
        except Exception as exc:  # noqa: BLE001
            records[rtype] = [f"error: {exc}"]

    # Flatten for display
    details: dict[str, str] = {}
    for rtype, values in records.items():
        if values:
            details[rtype] = " | ".join(values[:5])  # cap to 5 entries per type
        else:
            details[rtype] = "(none)"

    return {
        "source":     "DNS Lookup",
        "skipped":    False,
        "error":      False,
        "flagged":    False,
        "risk_score": None,
        "details":    details,
    }


# ---------------------------------------------------------------------------
# 2. Reverse DNS Lookup
# ---------------------------------------------------------------------------

def reverse_dns_lookup(ip: str) -> dict:
    """
    Perform a reverse DNS (PTR record) lookup for an IP address.

    Args:
        ip: IPv4 or IPv6 address string.

    Returns:
        Structured dict containing ptr_records list or an error message.
    """
    try:
        rev_name = dns.reversename.from_address(ip)
        answers = dns.resolver.resolve(rev_name, "PTR")
        ptr_records = [str(rdata) for rdata in answers]
        return {
            "source":     "Reverse DNS",
            "skipped":    False,
            "error":      False,
            "flagged":    False,
            "risk_score": None,
            "details": {
                "IP Address":  ip,
                "PTR Records": " | ".join(ptr_records),
            },
        }
    except dns.resolver.NXDOMAIN:
        return {
            "source":     "Reverse DNS",
            "skipped":    False,
            "error":      False,
            "flagged":    False,
            "risk_score": None,
            "details": {
                "IP Address":  ip,
                "PTR Records": "No PTR record found.",
            },
        }
    except dns.exception.Timeout:
        return {
            "source":  "Reverse DNS",
            "skipped": False,
            "error":   True,
            "flagged": False,
            "risk_score": None,
            "details": {"Error": "DNS query timed out."},
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "source":  "Reverse DNS",
            "skipped": False,
            "error":   True,
            "flagged": False,
            "risk_score": None,
            "details": {"Error": str(exc)},
        }


# ---------------------------------------------------------------------------
# 3. WHOIS Lookup
# ---------------------------------------------------------------------------

def get_whois(query: str) -> dict:
    """
    Retrieve WHOIS registration data for a domain name or IP address.

    Args:
        query: A domain name or IP address string.

    Returns:
        Structured dict with parsed WHOIS fields.
    """
    try:
        w = whois.whois(query)
        raw: dict = dict(w) if w else {}

        # Helper to safely get and clean a field
        def _field(key: str) -> str:
            val = raw.get(key)
            if val is None:
                return "N/A"
            if isinstance(val, list):
                val = [str(v) for v in val if v]
                return ", ".join(val[:3]) if val else "N/A"
            return str(val)

        details: dict[str, str] = {
            "Domain Name":      _field("domain_name"),
            "Registrar":        _field("registrar"),
            "Creation Date":    _stringify_date(raw.get("creation_date")),
            "Expiration Date":  _stringify_date(raw.get("expiration_date")),
            "Updated Date":     _stringify_date(raw.get("updated_date")),
            "Name Servers":     _field("name_servers"),
            "Status":           _field("status"),
            "Emails":           _field("emails"),
            "DNSSEC":           _field("dnssec"),
            "Organisation":     _field("org"),
            "Country":          _field("country"),
            "Registrant Name":  _field("registrant_name") if "registrant_name" in raw else "N/A",
        }

        return {
            "source":     "WHOIS",
            "skipped":    False,
            "error":      False,
            "flagged":    False,
            "risk_score": None,
            "details":    details,
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "source":  "WHOIS",
            "skipped": False,
            "error":   True,
            "flagged": False,
            "risk_score": None,
            "details": {"Error": f"Could not retrieve WHOIS data: {exc}"},
        }


# ---------------------------------------------------------------------------
# 4. Spamhaus / DNSBL Check
# ---------------------------------------------------------------------------

def spamhaus_dnsbl_check(ip: str) -> dict:
    """
    Check an IP address against Spamhaus, SpamCop, and Barracuda DNSBLs.

    The lookup is performed by reversing the IP octets and querying each DNSBL
    zone via standard DNS — no API key required.

    Args:
        ip: IPv4 address string to check.

    Returns:
        Structured dict with listed flag, zones listed, and per-zone details.
    """
    try:
        # Validate and reverse — only IPv4 is supported by classic DNSBLs
        addr = ipaddress.IPv4Address(ip)
        reversed_ip = ".".join(reversed(str(addr).split(".")))
    except (ipaddress.AddressValueError, ValueError):
        return {
            "source":  "DNSBL Check",
            "skipped": False,
            "error":   True,
            "flagged": False,
            "risk_score": None,
            "details": {"Error": f"'{ip}' is not a valid IPv4 address for DNSBL lookup."},
        }

    dnsbl_zones: dict[str, str] = {
        "zen.spamhaus.org":     "Spamhaus ZEN (SBL/XBL/PBL)",
        "bl.spamcop.net":       "SpamCop BL",
        "b.barracudacentral.org": "Barracuda Central",
    }

    per_zone: dict[str, str] = {}
    listed_in: list[str] = []

    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5

    for zone, label in dnsbl_zones.items():
        query = f"{reversed_ip}.{zone}"
        try:
            answers = resolver.resolve(query, "A")
            return_codes = [str(rdata) for rdata in answers]
            listed_in.append(label)

            # Decode Spamhaus return codes when possible
            reasons = [
                _SPAMHAUS_CODES.get(code, f"Listed ({code})")
                for code in return_codes
            ]
            per_zone[label] = "LISTED — " + "; ".join(reasons)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            per_zone[label] = "Not listed"
        except dns.exception.Timeout:
            per_zone[label] = "Timeout — could not query"
        except Exception as exc:  # noqa: BLE001
            per_zone[label] = f"Error: {exc}"

    is_listed = bool(listed_in)
    details = {
        "IP Address":   ip,
        "Overall":      "LISTED" if is_listed else "Not listed",
        "Listed In":    ", ".join(listed_in) if listed_in else "None",
        **per_zone,
    }

    return {
        "source":     "DNSBL Check",
        "skipped":    False,
        "error":      False,
        "flagged":    is_listed,
        "risk_score": 100 if is_listed else 0,
        "details":    details,
    }
