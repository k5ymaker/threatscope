"""
ssl_analyzer.py — SSL/TLS certificate analysis and Qualys SSL Labs scanning.

Each function:
  - Returns a structured dict: source, skipped, error, flagged, details.
  - Never raises exceptions to the caller.
"""

from __future__ import annotations

import datetime
import os
import socket
import ssl
import sys
import time
from typing import Optional

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import CONFIG  # noqa: E402

from modules.utils import console, print_result_table, print_section_header

REQUEST_TIMEOUT = 15

# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _skipped_result(source: str, reason: str = "Dependency not available") -> dict:
    return {"source": source, "skipped": True, "error": False, "flagged": False, "details": {"reason": reason}}


def _error_result(source: str, message: str) -> dict:
    return {"source": source, "skipped": False, "error": True, "flagged": False, "details": {"Error": message}}


# ---------------------------------------------------------------------------
# 1. Grab and parse certificate
# ---------------------------------------------------------------------------

def grab_certificate(hostname: str, port: int = 443) -> dict:
    """
    Retrieve and parse the SSL/TLS certificate for a hostname.

    Uses stdlib ssl + socket to fetch the DER-encoded certificate, then
    parses it with the cryptography library for full detail extraction.

    Args:
        hostname: Domain name or IP to connect to.
        port:     TCP port (default 443).

    Returns:
        Structured result dict with certificate details and security assessment.
    """
    source = "SSL Certificate"

    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
        from cryptography.x509.oid import NameOID, ExtensionOID
    except ImportError:
        return _skipped_result(source, "cryptography library not installed. Run: pip install cryptography")

    try:
        # Fetch DER certificate via ssl stdlib
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE

        with socket.create_connection((hostname, port), timeout=REQUEST_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                der_cert   = ssock.getpeercert(binary_form=True)
                tls_version = ssock.version() or "Unknown"
                cipher_name, _, cipher_bits = ssock.cipher()

        # Parse with cryptography library
        cert = x509.load_der_x509_certificate(der_cert)

        # Subject / Issuer
        def _get_attr(name_obj, oid):
            try:
                return name_obj.get_attributes_for_oid(oid)[0].value
            except (IndexError, Exception):
                return ""

        subject_cn = _get_attr(cert.subject, NameOID.COMMON_NAME)
        subject_o  = _get_attr(cert.subject, NameOID.ORGANIZATION_NAME)
        issuer_cn  = _get_attr(cert.issuer,  NameOID.COMMON_NAME)
        issuer_o   = _get_attr(cert.issuer,  NameOID.ORGANIZATION_NAME)

        # Validity dates
        not_before = cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)
        not_after  = cert.not_valid_after_utc  if hasattr(cert, "not_valid_after_utc")  else cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
        now        = datetime.datetime.now(datetime.timezone.utc)

        expired      = now > not_after
        days_left    = (not_after - now).days if not expired else 0
        expiring_soon = (not expired) and (days_left < 30)

        # SANs
        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            sans    = san_ext.value.get_values_for_type(x509.DNSName)
        except Exception:
            sans = []

        # Key info
        pub_key    = cert.public_key()
        key_type   = type(pub_key).__name__
        key_size   = getattr(pub_key, "key_size", None)

        weak_key = False
        if isinstance(pub_key, rsa.RSAPublicKey):
            key_type = "RSA"
            weak_key = pub_key.key_size < 2048
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            key_type = f"EC ({pub_key.curve.name})"
            weak_key = pub_key.key_size < 224
        elif isinstance(pub_key, dsa.DSAPublicKey):
            key_type = "DSA"
            weak_key = True  # DSA is deprecated

        # Signature algorithm
        sig_algo = cert.signature_algorithm_oid.dotted_string
        try:
            sig_algo = cert.signature_hash_algorithm.name.upper()
        except Exception:
            pass

        weak_sig = any(w in sig_algo.upper() for w in ("MD5", "SHA1"))

        # Fingerprints
        fp_sha256 = cert.fingerprint(hashes.SHA256()).hex(":").upper()
        fp_sha1   = cert.fingerprint(hashes.SHA1()).hex(":").upper()

        # Serial number
        serial = format(cert.serial_number, "x").upper()

        # Deprecated protocol check
        deprecated_proto = tls_version in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1")

        # Build details
        flags: list[str] = []
        if expired:
            flags.append("EXPIRED")
        if expiring_soon:
            flags.append(f"EXPIRING SOON ({days_left} days)")
        if weak_key:
            flags.append("WEAK KEY")
        if weak_sig:
            flags.append(f"WEAK SIGNATURE ({sig_algo})")
        if deprecated_proto:
            flags.append(f"DEPRECATED PROTOCOL ({tls_version})")

        flagged = bool(flags)

        details: dict = {
            "Hostname":          hostname,
            "Subject CN":        subject_cn,
            "Subject Org":       subject_o,
            "Issuer CN":         issuer_cn,
            "Issuer Org":        issuer_o,
            "Not Before":        not_before.strftime("%Y-%m-%d"),
            "Not After":         not_after.strftime("%Y-%m-%d"),
            "Expired":           "YES" if expired else "no",
            "Days Until Expiry": str(days_left) if not expired else "EXPIRED",
            "TLS Version":       tls_version,
            "Cipher Suite":      cipher_name,
            "Cipher Bits":       str(cipher_bits),
            "Key Type":          key_type,
            "Key Size":          str(key_size) if key_size else "N/A",
            "Signature Algo":    sig_algo,
            "SANs":              ", ".join(sans[:10]) + ("..." if len(sans) > 10 else ""),
            "SAN Count":         str(len(sans)),
            "Serial Number":     serial[:32],
            "SHA-256 Fingerprint": fp_sha256[:47] + "...",
            "SHA-1 Fingerprint":   fp_sha1[:47] + "...",
        }

        if flags:
            details["Security Issues"] = " | ".join(flags)

        return {
            "source":  source,
            "skipped": False,
            "error":   False,
            "flagged": flagged,
            "details": details,
        }

    except socket.timeout:
        return _error_result(source, f"Connection timed out to {hostname}:{port}.")
    except ConnectionRefusedError:
        return _error_result(source, f"Connection refused by {hostname}:{port}.")
    except ssl.SSLError as exc:
        return _error_result(source, f"SSL error: {exc}")
    except OSError as exc:
        return _error_result(source, f"Network error: {exc}")
    except Exception as exc:
        return _error_result(source, str(exc))


# ---------------------------------------------------------------------------
# 2. Qualys SSL Labs
# ---------------------------------------------------------------------------

def ssllabs_scan(hostname: str) -> dict:
    """
    Trigger or retrieve a Qualys SSL Labs scan for a hostname.

    Uses cached results (maxAge=24h) and polls until ready.

    Args:
        hostname: Domain name to analyse.

    Returns:
        Structured result dict with SSL Labs grade and vulnerability data.
    """
    source  = "Qualys SSL Labs"
    base    = "https://api.ssllabs.com/api/v3/analyze"
    params  = {
        "host":     hostname,
        "startNew": "off",
        "fromCache":"on",
        "maxAge":   "24",
        "all":      "done",
    }

    try:
        max_polls = 20
        poll_wait = 10

        for attempt in range(max_polls):
            resp = requests.get(base, params=params, timeout=REQUEST_TIMEOUT)

            if resp.status_code == 429:
                return _error_result(source, "SSL Labs rate limit hit. Try again later.")

            resp.raise_for_status()
            data   = resp.json()
            status = data.get("status", "")

            if status == "ERROR":
                return _error_result(source, data.get("statusMessage", "SSL Labs returned an error."))

            if status == "READY":
                break

            if attempt == 0 and status in ("DNS", "IN_PROGRESS"):
                # Switch to startNew=off for subsequent polls
                params["startNew"] = "off"

            if attempt < max_polls - 1:
                console.print(f"  [dim]SSL Labs status: {status} — waiting {poll_wait}s...[/dim]")
                time.sleep(poll_wait)
        else:
            return _error_result(source, f"SSL Labs scan timed out after {max_polls} polls.")

        endpoints = data.get("endpoints", [])
        if not endpoints:
            return _error_result(source, "No endpoint data returned by SSL Labs.")

        ep     = endpoints[0]
        grade  = ep.get("grade", "N/A")
        grade_trust = ep.get("gradeTrustIgnored", "")
        ip_addr = ep.get("ipAddress", "")
        server_name = ep.get("serverName", "")

        ep_details = ep.get("details", {})
        protocols  = [p.get("name", "") + p.get("version", "") for p in ep_details.get("protocols", [])]
        vuln_keys  = [
            ("heartbleed",       "Heartbleed"),
            ("poodle",           "POODLE"),
            ("poodleTls",        "POODLE TLS"),
            ("freak",            "FREAK"),
            ("logjam",           "Logjam"),
            ("drownVulnerable",  "DROWN"),
            ("ticketbleed",      "Ticketbleed"),
            ("zombiePoodle",     "Zombie POODLE"),
            ("goldenDoodle",     "GoldenDoodle"),
            ("zeroLengthPaddingOracle", "0-Length Padding Oracle"),
            ("sleepingPoodle",   "Sleeping POODLE"),
        ]

        vulns_found: list[str] = []
        for key, label in vuln_keys:
            val = ep_details.get(key)
            if val is True or val == 2:
                vulns_found.append(label)

        forward_secrecy = ep_details.get("forwardSecrecy", 0)
        rc4_used        = ep_details.get("rc4Used", False)
        chain_issues    = ep_details.get("chain", {}).get("issues", 0)

        flagged = grade in ("F", "T") or bool(vulns_found)

        details: dict = {
            "Hostname":           hostname,
            "IP Address":         ip_addr,
            "Server Name":        server_name,
            "Grade":              grade,
            "Grade (Trust Off)":  grade_trust or grade,
            "TLS Protocols":      ", ".join(protocols),
            "Forward Secrecy":    "yes" if forward_secrecy >= 2 else "partial" if forward_secrecy == 1 else "no",
            "RC4 Used":           "yes" if rc4_used else "no",
            "Chain Issues":       str(chain_issues),
            "Vulnerabilities":    ", ".join(vulns_found) if vulns_found else "none detected",
        }

        return {
            "source":  source,
            "skipped": False,
            "error":   False,
            "flagged": flagged,
            "details": details,
        }

    except requests.exceptions.RequestException as exc:
        return _error_result(source, str(exc))


# ---------------------------------------------------------------------------
# Menu
# ---------------------------------------------------------------------------

def handle_ssl_menu() -> None:
    """Interactive SSL analysis menu."""
    from rich.prompt import Prompt

    while True:
        console.print("\n[bold cyan]SSL / TLS Analyzer[/bold cyan]")
        console.print("  [white]1[/white]  Grab & parse certificate")
        console.print("  [white]2[/white]  Qualys SSL Labs scan")
        console.print("  [white]3[/white]  Full SSL report (cert + SSL Labs)")
        console.print("  [white]0[/white]  Back\n")

        choice = Prompt.ask("[bold cyan]Select option[/bold cyan]", default="0").strip()

        if choice == "0":
            break

        elif choice in ("1", "2", "3"):
            hostname = Prompt.ask("[bold cyan]Enter hostname (e.g. example.com)[/bold cyan]").strip()
            # Strip protocol prefix if entered
            hostname = hostname.replace("https://", "").replace("http://", "").rstrip("/").split("/")[0]
            if not hostname:
                console.print("[yellow]Invalid hostname.[/yellow]")
                continue

            port_str = "443"
            if ":" in hostname:
                parts    = hostname.rsplit(":", 1)
                hostname = parts[0]
                port_str = parts[1]

            try:
                port = int(port_str)
            except ValueError:
                port = 443

            if choice == "1":
                with _spinner(f"Connecting to {hostname}:{port}..."):
                    result = grab_certificate(hostname, port)
                _display_result(result, f"Certificate: {hostname}")

            elif choice == "2":
                console.print("[dim]SSL Labs scan may take up to 3 minutes for a fresh scan...[/dim]")
                result = ssllabs_scan(hostname)
                _display_result(result, f"SSL Labs: {hostname}")

            elif choice == "3":
                print_section_header(f"SSL Report: {hostname}")

                with _spinner(f"Grabbing certificate from {hostname}:{port}..."):
                    cert_result = grab_certificate(hostname, port)
                _display_result(cert_result, f"Certificate: {hostname}")

                console.print("[dim]Requesting SSL Labs analysis (may take a few minutes)...[/dim]")
                labs_result = ssllabs_scan(hostname)
                _display_result(labs_result, f"SSL Labs: {hostname}")

        else:
            console.print("[yellow]Invalid option.[/yellow]")


def _display_result(result: dict, title: str) -> None:
    if result.get("skipped"):
        reason = result.get("details", {}).get("reason", "Dependency not available")
        console.print(f"  [dim]○ {title}: SKIPPED — {reason}[/dim]\n")
        return
    if result.get("error"):
        err = result.get("details", {}).get("Error", "Unknown error")
        console.print(f"  [bold red]✗ {title}: ERROR — {err}[/bold red]\n")
        return
    print_result_table(result, title)


def _spinner(message: str):
    from rich.progress import Progress, SpinnerColumn, TextColumn
    return Progress(SpinnerColumn(), TextColumn(f"[cyan]{message}"), transient=True, console=console)
