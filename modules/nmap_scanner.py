"""
nmap_scanner.py — Nmap integration for ThreatScope.

Wraps the python-nmap library (which shells out to the nmap binary).
All functions return a structured dict: source, skipped, error, flagged,
risk_score, details — matching the pattern used by all other ThreatScope modules.

Dependency checks run at import time:
  NMAP_AVAILABLE  — python-nmap library present
  NMAP_BINARY     — nmap binary found in PATH
If either is False every public function returns a graceful error dict.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import sys
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeoutError
from typing import Any

# ---------------------------------------------------------------------------
# Dependency checks
# ---------------------------------------------------------------------------
try:
    import nmap  # python-nmap
    NMAP_AVAILABLE: bool = True
except ImportError:
    NMAP_AVAILABLE = False

NMAP_BINARY: bool = shutil.which("nmap") is not None

# ---------------------------------------------------------------------------
# Vulnerability keyword detection
# ---------------------------------------------------------------------------
_VULN_KEYWORDS: tuple[str, ...] = (
    "VULNERABLE", "EXPLOITABLE", "SUCCESS", "backdoor", "bypass", "overflow",
    "injection", "RCE", "CVE", "State: VULNERABLE", "likely VULNERABLE",
)


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _nmap_unavailable(source: str) -> dict:
    """Return a graceful error when nmap is not installed or not on PATH."""
    if not NMAP_AVAILABLE:
        msg = "python-nmap not installed. Run: pip install python-nmap"
    else:
        msg = (
            "nmap binary not found. "
            "Install: sudo apt install nmap  |  brew install nmap  |  "
            "https://nmap.org/download.html (Windows)"
        )
    return {
        "source":     source,
        "skipped":    False,
        "error":      True,
        "flagged":    False,
        "risk_score": None,
        "details":    {"Error": msg},
    }


def _error_result(source: str, msg: str) -> dict:
    """Return a generic error result dict."""
    return {
        "source":     source,
        "skipped":    False,
        "error":      True,
        "flagged":    False,
        "risk_score": None,
        "details":    {"Error": msg},
    }


def _timeout_error(source: str, timeout: int) -> dict:
    """Return an error result for a timed-out scan."""
    return _error_result(source, f"Scan timed out after {timeout} seconds.")


def _is_flagged(text: str) -> bool:
    """Return True if text contains any known vulnerability indicator keyword."""
    upper = text.upper()
    return any(kw.upper() in upper for kw in _VULN_KEYWORDS)


# ---------------------------------------------------------------------------
# Core parser
# ---------------------------------------------------------------------------

def _parse_nmap_results(
    nm: "nmap.PortScanner",
    target: str,
    script_mode: bool = False,
) -> dict:
    """
    Parse a completed PortScanner object into a normalised dict.

    Args:
        nm:          Completed nmap.PortScanner instance.
        target:      Original scan target string.
        script_mode: If True, also collect per-port NSE script output.

    Returns:
        Dict with keys: open_ports, script_output, host_state,
        filtered_count, closed_count, scan_stats, nmap_command.
    """
    open_ports: list[dict] = []
    script_output: dict[str, Any] = {}
    filtered_count = 0
    closed_count = 0
    host_state = "unknown"

    try:
        nmap_command = nm.command_line()
    except Exception:
        nmap_command = "N/A"

    try:
        scan_stats = nm.scanstats()
    except Exception:
        scan_stats = {}

    all_hosts = nm.all_hosts()
    if not all_hosts:
        return {
            "open_ports":    open_ports,
            "script_output": script_output,
            "host_state":    "down",
            "filtered_count": filtered_count,
            "closed_count":  closed_count,
            "scan_stats":    scan_stats,
            "nmap_command":  nmap_command,
        }

    host = all_hosts[0]
    try:
        host_state = nm[host].state()
    except Exception:
        host_state = "unknown"

    for proto in nm[host].all_protocols():
        ports_dict = nm[host][proto]
        for port in sorted(ports_dict.keys()):
            port_data = ports_dict[port]
            state = port_data.get("state", "")

            if state == "open":
                entry: dict = {
                    "port":     port,
                    "protocol": proto,
                    "state":    state,
                    "service":  port_data.get("name", ""),
                    "product":  port_data.get("product", ""),
                    "version":  port_data.get("version", ""),
                }
                open_ports.append(entry)

                if script_mode:
                    scripts = port_data.get("script", {})
                    if scripts:
                        script_output[port] = scripts

            elif state in ("open|filtered",):
                # Include UDP open|filtered as open
                entry = {
                    "port":     port,
                    "protocol": proto,
                    "state":    state,
                    "service":  port_data.get("name", ""),
                    "product":  port_data.get("product", ""),
                    "version":  port_data.get("version", ""),
                }
                open_ports.append(entry)

            elif state == "filtered":
                filtered_count += 1

            elif state == "closed":
                closed_count += 1

    return {
        "open_ports":     open_ports,
        "script_output":  script_output,
        "host_state":     host_state,
        "filtered_count": filtered_count,
        "closed_count":   closed_count,
        "scan_stats":     scan_stats,
        "nmap_command":   nmap_command,
    }


# ---------------------------------------------------------------------------
# Scan execution helpers
# ---------------------------------------------------------------------------

def _run_common_scan(
    target: str,
    arguments: str,
    source: str,
    timeout: int = 300,
) -> dict:
    """
    Run a generic (non-NSE) nmap scan and return a normalised result dict.

    Args:
        target:    Scan target — IP, hostname, or CIDR.
        arguments: Raw nmap argument string (e.g. ``"-sV"``).
        source:    Human-readable source label for the result dict.
        timeout:   Hard wall-clock timeout in seconds.

    Returns:
        Structured result dict compatible with ThreatScope module convention.
    """
    if not NMAP_AVAILABLE or not NMAP_BINARY:
        return _nmap_unavailable(source)

    try:
        nm = nmap.PortScanner()

        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(nm.scan, target, None, arguments)
            try:
                future.result(timeout=timeout)
            except FuturesTimeoutError:
                return _timeout_error(source, timeout)

        parsed = _parse_nmap_results(nm, target, script_mode=False)
        open_ports = parsed["open_ports"]

        return {
            "source":     source,
            "skipped":    False,
            "error":      False,
            "flagged":    len(open_ports) > 0,
            "risk_score": None,
            "details": {
                "target":         target,
                "state":          parsed["host_state"],
                "open_ports":     open_ports,
                "filtered_ports": parsed["filtered_count"],
                "closed_ports":   parsed["closed_count"],
                "scan_time":      parsed["scan_stats"].get("elapsed", "N/A") + "s",
                "nmap_command":   parsed["nmap_command"],
            },
        }

    except nmap.PortScannerError as exc:  # type: ignore[attr-defined]
        return _error_result(source, f"Nmap error: {exc}")
    except Exception as exc:  # noqa: BLE001
        return _error_result(source, str(exc))


def _run_nse_scan(
    target: str,
    arguments: str,
    source: str,
    script_name: str,
    timeout: int = 300,
) -> dict:
    """
    Run an NSE script scan and return a normalised result dict.

    Args:
        target:      Scan target.
        arguments:   Full nmap argument string including ``--script`` flag.
        source:      Human-readable source label.
        script_name: NSE script name (for metadata in result dict).
        timeout:     Hard wall-clock timeout in seconds.

    Returns:
        Structured result dict with script_output and flagged status.
    """
    if not NMAP_AVAILABLE or not NMAP_BINARY:
        return _nmap_unavailable(source)

    try:
        nm = nmap.PortScanner()

        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(nm.scan, target, None, arguments)
            try:
                future.result(timeout=timeout)
            except FuturesTimeoutError:
                return _timeout_error(source, timeout)

        parsed = _parse_nmap_results(nm, target, script_mode=True)

        # Flatten per-port script output into a single dict and raw string
        all_scripts: dict[str, str] = {}
        raw_lines: list[str] = []

        for port, scripts in parsed["script_output"].items():
            for sname, sout in scripts.items():
                key = f"Port {port} · {sname}"
                all_scripts[key] = str(sout)
                raw_lines.append(f"[Port {port}] {sname}:\n{sout}")

        raw_output = "\n\n".join(raw_lines) if raw_lines else "No script output returned."
        flagged = _is_flagged(raw_output)

        return {
            "source":     source,
            "skipped":    False,
            "error":      False,
            "flagged":    flagged,
            "risk_score": 100 if flagged else 0,
            "details": {
                "script_name":   script_name,
                "target":        target,
                "open_ports":    parsed["open_ports"],
                "script_output": all_scripts if all_scripts else "No script output returned.",
                "raw_output":    raw_output,
                "nmap_command":  parsed["nmap_command"],
            },
        }

    except nmap.PortScannerError as exc:  # type: ignore[attr-defined]
        return _error_result(source, f"Nmap error: {exc}")
    except Exception as exc:  # noqa: BLE001
        return _error_result(source, str(exc))


# ===========================================================================
# GROUP A — GENERIC SCAN
# ===========================================================================

def generic_port_scan(target: str) -> dict:
    """
    Standard TCP connect scan against top 1000 ports.

    Equivalent to: ``nmap <target>``

    Args:
        target: IP address, hostname, or CIDR range.

    Returns:
        Result dict with open_ports list and host state.
    """
    return _run_common_scan(target, "", "Nmap - Generic Scan")


# ===========================================================================
# GROUP B — COMMON SCANS
# ===========================================================================

def service_version_scan(target: str) -> dict:
    """
    Service and version detection on top 1000 ports.

    Equivalent to: ``nmap -sV <target>``

    Args:
        target: IP address, hostname, or CIDR range.

    Returns:
        Result dict with service name, product, and version per open port.
    """
    return _run_common_scan(target, "-sV", "Nmap - Service Version")


def os_detection_scan(target: str) -> dict:
    """
    OS fingerprinting scan. Requires root/sudo on Linux and macOS.

    Equivalent to: ``nmap -O <target>``

    Args:
        target: IP address or hostname.

    Returns:
        Result dict including os_matches list with name and accuracy.
    """
    if not NMAP_AVAILABLE or not NMAP_BINARY:
        return _nmap_unavailable("Nmap - OS Detection")

    source = "Nmap - OS Detection"
    try:
        nm = nmap.PortScanner()

        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(nm.scan, target, None, "-O")
            try:
                future.result(timeout=300)
            except FuturesTimeoutError:
                return _timeout_error(source, 300)

        parsed = _parse_nmap_results(nm, target)
        open_ports = parsed["open_ports"]

        os_matches: list[dict] = []
        all_hosts = nm.all_hosts()
        if all_hosts:
            host = all_hosts[0]
            for match in nm[host].get("osmatch", [])[:5]:
                os_matches.append({
                    "name":     match.get("name", "Unknown"),
                    "accuracy": int(match.get("accuracy", 0)),
                })

        return {
            "source":     source,
            "skipped":    False,
            "error":      False,
            "flagged":    len(open_ports) > 0,
            "risk_score": None,
            "details": {
                "target":         target,
                "state":          parsed["host_state"],
                "open_ports":     open_ports,
                "os_matches":     os_matches if os_matches else [{"name": "Could not determine", "accuracy": 0}],
                "filtered_ports": parsed["filtered_count"],
                "scan_time":      parsed["scan_stats"].get("elapsed", "N/A") + "s",
                "nmap_command":   parsed["nmap_command"],
            },
        }

    except nmap.PortScannerError as exc:  # type: ignore[attr-defined]
        return _error_result(source, f"Nmap error: {exc}")
    except Exception as exc:  # noqa: BLE001
        return _error_result(source, str(exc))


def specific_ports_scan(target: str, ports: str) -> dict:
    """
    Scan a specific set of ports.

    Equivalent to: ``nmap -p <ports> <target>``

    Args:
        target: IP address, hostname, or CIDR range.
        ports:  Port specification — digits, commas, and hyphens only
                (e.g. ``"22,80,443"`` or ``"1-1024"``).

    Returns:
        Result dict with open_ports for the specified port range.
    """
    if not re.match(r"^[\d,\-]+$", ports.strip()):
        return _error_result(
            "Nmap - Specific Ports",
            "Invalid ports string. Use digits, commas, and hyphens only (e.g. 22,80,443).",
        )
    return _run_common_scan(target, f"-p {ports.strip()}", "Nmap - Specific Ports")


def ack_scan(target: str) -> dict:
    """
    ACK scan for firewall rule mapping. Requires root/sudo.

    Equivalent to: ``nmap -sA <target>``
    Ports reported as ``unfiltered`` can be reached; ``filtered`` cannot.

    Args:
        target: IP address or hostname.

    Returns:
        Result dict with filtered/unfiltered port counts.
    """
    return _run_common_scan(target, "-sA", "Nmap - ACK Scan")


def syn_stealth_scan(target: str) -> dict:
    """
    SYN stealth (half-open) scan. Requires root/sudo.

    Equivalent to: ``nmap -sS <target>``
    Faster and less visible than a full TCP connect scan.

    Args:
        target: IP address, hostname, or CIDR range.

    Returns:
        Result dict with open ports detected via SYN probe.
    """
    return _run_common_scan(target, "-sS", "Nmap - SYN Stealth")


def udp_scan(target: str) -> dict:
    """
    UDP scan of top 1000 ports. Requires root/sudo.

    Equivalent to: ``nmap -sU <target>``
    Note: UDP scanning is significantly slower than TCP.

    Args:
        target: IP address or hostname.

    Returns:
        Result dict including open and open|filtered UDP ports.
    """
    return _run_common_scan(target, "-sU", "Nmap - UDP Scan")


def tcp_syn_ping(target: str, ports: str = "80,443") -> dict:
    """
    TCP SYN ping for host discovery — no port scan performed.

    Equivalent to: ``nmap -PS<ports> -sn <target>``
    Useful for discovering live hosts in a CIDR range.

    Args:
        target: IP address, hostname, or CIDR range (e.g. ``192.168.1.0/24``).
        ports:  Ports to send SYN probes to (default: ``"80,443"``).

    Returns:
        Result dict with hosts_up, hosts_down, and list of live IPs.
    """
    if not NMAP_AVAILABLE or not NMAP_BINARY:
        return _nmap_unavailable("Nmap - TCP SYN Ping")

    source = "Nmap - TCP SYN Ping"
    arguments = f"-PS{ports} -sn"

    try:
        nm = nmap.PortScanner()

        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(nm.scan, target, None, arguments)
            try:
                future.result(timeout=300)
            except FuturesTimeoutError:
                return _timeout_error(source, 300)

        all_hosts = nm.all_hosts()
        hosts_up: list[str] = []
        hosts_down: list[str] = []

        for host in all_hosts:
            if nm[host].state() == "up":
                hosts_up.append(host)
            else:
                hosts_down.append(host)

        try:
            stats = nm.scanstats()
        except Exception:
            stats = {}

        return {
            "source":     source,
            "skipped":    False,
            "error":      False,
            "flagged":    len(hosts_up) > 0,
            "risk_score": None,
            "details": {
                "target":       target,
                "hosts_up":     len(hosts_up),
                "hosts_down":   len(hosts_down),
                "live_hosts":   ", ".join(hosts_up[:20]) if hosts_up else "None found",
                "scan_time":    stats.get("elapsed", "N/A") + "s",
                "nmap_command": nm.command_line() if hasattr(nm, "_nmap_last_command_line") else "N/A",
            },
        }

    except nmap.PortScannerError as exc:  # type: ignore[attr-defined]
        return _error_result(source, f"Nmap error: {exc}")
    except Exception as exc:  # noqa: BLE001
        return _error_result(source, str(exc))


def scan_from_list(targets_file: str) -> dict:
    """
    Scan a list of targets read from a file.

    Equivalent to: ``nmap -iL <file>``

    Args:
        targets_file: Absolute or relative path to a newline-separated targets file.

    Returns:
        Result dict with combined open ports across all scanned hosts.
    """
    if not os.path.isfile(targets_file):
        return _error_result(
            "Nmap - Scan from File",
            f"File not found: {targets_file}",
        )

    safe_path = shlex.quote(targets_file)
    return _run_common_scan("", f"-iL {safe_path}", "Nmap - Scan from File")


def aggressive_scan(target: str) -> dict:
    """
    Aggressive scan — OS detection, version detection, scripts, and traceroute.

    Equivalent to: ``nmap -A <target>``
    Requires root/sudo for full OS detection capability.

    Args:
        target: IP address or hostname.

    Returns:
        Result dict with all available: OS, ports, services, script output.
    """
    if not NMAP_AVAILABLE or not NMAP_BINARY:
        return _nmap_unavailable("Nmap - Aggressive Scan")

    source = "Nmap - Aggressive Scan"
    try:
        nm = nmap.PortScanner()

        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(nm.scan, target, None, "-A")
            try:
                future.result(timeout=300)
            except FuturesTimeoutError:
                return _timeout_error(source, 300)

        parsed = _parse_nmap_results(nm, target, script_mode=True)
        open_ports = parsed["open_ports"]

        os_matches: list[dict] = []
        all_hosts = nm.all_hosts()
        if all_hosts:
            host = all_hosts[0]
            for match in nm[host].get("osmatch", [])[:3]:
                os_matches.append({
                    "name":     match.get("name", "Unknown"),
                    "accuracy": int(match.get("accuracy", 0)),
                })

        # Flatten any script output
        scripts_flat: dict[str, str] = {}
        for port, scripts in parsed["script_output"].items():
            for sname, sout in scripts.items():
                scripts_flat[f"Port {port} · {sname}"] = str(sout)

        return {
            "source":     source,
            "skipped":    False,
            "error":      False,
            "flagged":    len(open_ports) > 0 or _is_flagged(str(scripts_flat)),
            "risk_score": None,
            "details": {
                "target":         target,
                "state":          parsed["host_state"],
                "open_ports":     open_ports,
                "os_matches":     os_matches if os_matches else [{"name": "N/A", "accuracy": 0}],
                "script_output":  scripts_flat if scripts_flat else "None",
                "filtered_ports": parsed["filtered_count"],
                "scan_time":      parsed["scan_stats"].get("elapsed", "N/A") + "s",
                "nmap_command":   parsed["nmap_command"],
            },
        }

    except nmap.PortScannerError as exc:  # type: ignore[attr-defined]
        return _error_result(source, f"Nmap error: {exc}")
    except Exception as exc:  # noqa: BLE001
        return _error_result(source, str(exc))


# ===========================================================================
# GROUP C — NSE VULNERABILITY SCRIPTS
# ===========================================================================

# ── SPECIAL ─────────────────────────────────────────────────────────────────

def scan_vuln_all(target: str) -> dict:
    """
    Run ALL scripts in the ``vuln`` NSE category against the target.

    Equivalent to: ``nmap --script vuln <target>``
    Warning: This is slow and noisy — timeout is 600 seconds.

    Args:
        target: IP address or hostname.

    Returns:
        Aggregated result dict from all vuln-category scripts.
    """
    return _run_nse_scan(target, "--script vuln", "Nmap - vuln (all)", "vuln", timeout=600)


# ── MAC / AVAHI / MISC ──────────────────────────────────────────────────────

def scan_afp_path_vuln(target: str) -> dict:
    """Mac OS X AFP directory traversal (CVE-2010-0533). Port 548."""
    return _run_nse_scan(target, "--script afp-path-vuln -p 548", "Nmap - afp-path-vuln", "afp-path-vuln")


def scan_broadcast_avahi_dos(target: str) -> dict:
    """Avahi NULL UDP pointer DoS (CVE-2011-1002). ⚠ CAUTION: can crash Avahi daemon."""
    return _run_nse_scan(target, "--script broadcast-avahi-dos", "Nmap - broadcast-avahi-dos", "broadcast-avahi-dos")


def scan_clamav_exec(target: str) -> dict:
    """Unauthenticated remote code execution in ClamAV (port 3310). ⚠ CAUTION."""
    return _run_nse_scan(target, "--script clamav-exec -p 3310", "Nmap - clamav-exec", "clamav-exec")


def scan_distcc_cve2004_2687(target: str) -> dict:
    """distcc daemon remote code execution (CVE-2004-2687, port 3632). ⚠ CAUTION."""
    return _run_nse_scan(target, "--script distcc-cve2004-2687 -p 3632", "Nmap - distcc-cve2004-2687", "distcc-cve2004-2687")


def scan_dns_update(target: str) -> dict:
    """Unauthenticated dynamic DNS update attempt. Port 53."""
    return _run_nse_scan(target, "--script dns-update -p 53", "Nmap - dns-update", "dns-update")


def scan_firewall_bypass(target: str) -> dict:
    """Helper-based firewall vulnerability detection."""
    return _run_nse_scan(target, "--script firewall-bypass", "Nmap - firewall-bypass", "firewall-bypass")


# ── FTP ─────────────────────────────────────────────────────────────────────

def scan_ftp_libopie(target: str) -> dict:
    """FTPd OPIE stack overflow vulnerability (CVE-2010-1938). Port 21."""
    return _run_nse_scan(target, "--script ftp-libopie -p 21", "Nmap - ftp-libopie", "ftp-libopie")


def scan_ftp_proftpd_backdoor(target: str) -> dict:
    """ProFTPD 1.3.3c backdoor detection. ⚠ CAUTION: executes remote 'id' command."""
    return _run_nse_scan(target, "--script ftp-proftpd-backdoor -p 21", "Nmap - ftp-proftpd-backdoor", "ftp-proftpd-backdoor")


def scan_ftp_vsftpd_backdoor(target: str) -> dict:
    """vsFTPd 2.3.4 backdoor detection. ⚠ CAUTION: opens backdoor shell."""
    return _run_nse_scan(target, "--script ftp-vsftpd-backdoor -p 21", "Nmap - ftp-vsftpd-backdoor", "ftp-vsftpd-backdoor")


def scan_ftp_vuln_cve2010_4221(target: str) -> dict:
    """ProFTPD TELNET_IAC stack overflow (CVE-2010-4221). Port 21."""
    return _run_nse_scan(target, "--script ftp-vuln-cve2010-4221 -p 21", "Nmap - ftp-vuln-cve2010-4221", "ftp-vuln-cve2010-4221")


# ── HTTP / WEB ───────────────────────────────────────────────────────────────

def scan_http_adobe_coldfusion_apsa1301(target: str) -> dict:
    """ColdFusion admin authentication bypass via cookie manipulation."""
    return _run_nse_scan(target, "--script http-adobe-coldfusion-apsa1301 -p 80,443,8500", "Nmap - http-adobe-coldfusion-apsa1301", "http-adobe-coldfusion-apsa1301")


def scan_http_aspnet_debug(target: str) -> dict:
    """ASP.NET debugging enabled via HTTP DEBUG request. Ports 80, 443."""
    return _run_nse_scan(target, "--script http-aspnet-debug -p 80,443", "Nmap - http-aspnet-debug", "http-aspnet-debug")


def scan_http_avaya_ipoffice_users(target: str) -> dict:
    """User enumeration on Avaya IP Office 7.x. Ports 80, 443."""
    return _run_nse_scan(target, "--script http-avaya-ipoffice-users -p 80,443", "Nmap - http-avaya-ipoffice-users", "http-avaya-ipoffice-users")


def scan_http_awstatstotals_exec(target: str) -> dict:
    """Remote code execution in Awstats Totals ≤ 1.14 (CVE-2008-3922)."""
    return _run_nse_scan(target, "--script http-awstatstotals-exec -p 80,443", "Nmap - http-awstatstotals-exec", "http-awstatstotals-exec")


def scan_http_axis2_dir_traversal(target: str) -> dict:
    """Apache Axis2 1.4.1 directory traversal vulnerability."""
    return _run_nse_scan(target, "--script http-axis2-dir-traversal -p 80,443,8080", "Nmap - http-axis2-dir-traversal", "http-axis2-dir-traversal")


def scan_http_cookie_flags(target: str) -> dict:
    """Session cookies missing httponly and/or secure flags. Ports 80, 443."""
    return _run_nse_scan(target, "--script http-cookie-flags -p 80,443", "Nmap - http-cookie-flags", "http-cookie-flags")


def scan_http_cross_domain_policy(target: str) -> dict:
    """Overly permissive crossdomain.xml or clientaccesspolicy.xml."""
    return _run_nse_scan(target, "--script http-cross-domain-policy -p 80,443", "Nmap - http-cross-domain-policy", "http-cross-domain-policy")


def scan_http_csrf(target: str) -> dict:
    """Cross-Site Request Forgery vulnerability detection. Ports 80, 443."""
    return _run_nse_scan(target, "--script http-csrf -p 80,443", "Nmap - http-csrf", "http-csrf")


def scan_http_dlink_backdoor(target: str) -> dict:
    """D-Link router firmware backdoor via User-Agent manipulation."""
    return _run_nse_scan(target, "--script http-dlink-backdoor -p 80,8080", "Nmap - http-dlink-backdoor", "http-dlink-backdoor")


def scan_http_dombased_xss(target: str) -> dict:
    """DOM-based Cross-Site Scripting sink detection. Ports 80, 443."""
    return _run_nse_scan(target, "--script http-dombased-xss -p 80,443", "Nmap - http-dombased-xss", "http-dombased-xss")


def scan_http_enum(target: str) -> dict:
    """Enumerate common web application directories and paths."""
    return _run_nse_scan(target, "--script http-enum -p 80,443,8080", "Nmap - http-enum", "http-enum")


def scan_http_fileupload_exploiter(target: str) -> dict:
    """Exploit insecure file upload forms to test code execution."""
    return _run_nse_scan(target, "--script http-fileupload-exploiter -p 80,443", "Nmap - http-fileupload-exploiter", "http-fileupload-exploiter")


def scan_http_frontpage_login(target: str) -> dict:
    """Anonymous Microsoft FrontPage login check. Ports 80, 443."""
    return _run_nse_scan(target, "--script http-frontpage-login -p 80,443", "Nmap - http-frontpage-login", "http-frontpage-login")


def scan_http_git(target: str) -> dict:
    """Exposed .git directory detection (source code disclosure)."""
    return _run_nse_scan(target, "--script http-git -p 80,443,8080", "Nmap - http-git", "http-git")


def scan_http_huawei_hg5xx_vuln(target: str) -> dict:
    """Huawei HG5xx modem credential disclosure vulnerability. Port 80."""
    return _run_nse_scan(target, "--script http-huawei-hg5xx-vuln -p 80", "Nmap - http-huawei-hg5xx-vuln", "http-huawei-hg5xx-vuln")


def scan_http_iis_webdav_vuln(target: str) -> dict:
    """IIS 5.1/6.0 WebDAV authentication bypass (MS09-020). Ports 80, 443."""
    return _run_nse_scan(target, "--script http-iis-webdav-vuln -p 80,443", "Nmap - http-iis-webdav-vuln", "http-iis-webdav-vuln")


def scan_http_internal_ip_disclosure(target: str) -> dict:
    """Internal IP address leakage via HTTP/1.0 response. Ports 80, 443."""
    return _run_nse_scan(target, "--script http-internal-ip-disclosure -p 80,443", "Nmap - http-internal-ip-disclosure", "http-internal-ip-disclosure")


def scan_http_jsonp_detection(target: str) -> dict:
    """JSONP endpoint discovery — potential Same-Origin Policy bypass risk."""
    return _run_nse_scan(target, "--script http-jsonp-detection -p 80,443", "Nmap - http-jsonp-detection", "http-jsonp-detection")


def scan_http_litespeed_sourcecode_download(target: str) -> dict:
    """LiteSpeed Web Server null-byte source code download (CVE-2010-2333)."""
    return _run_nse_scan(target, "--script http-litespeed-sourcecode-download -p 80,443", "Nmap - http-litespeed-sourcecode-download", "http-litespeed-sourcecode-download")


def scan_http_majordomo2_dir_traversal(target: str) -> dict:
    """Majordomo2 directory traversal vulnerability (CVE-2011-0049). Port 80."""
    return _run_nse_scan(target, "--script http-majordomo2-dir-traversal -p 80", "Nmap - http-majordomo2-dir-traversal", "http-majordomo2-dir-traversal")


def scan_http_method_tamper(target: str) -> dict:
    """Authentication bypass using HTTP verb tampering. Ports 80, 443."""
    return _run_nse_scan(target, "--script http-method-tamper -p 80,443", "Nmap - http-method-tamper", "http-method-tamper")


def scan_http_passwd(target: str) -> dict:
    """Directory traversal to retrieve /etc/passwd or \\boot.ini. Ports 80, 443."""
    return _run_nse_scan(target, "--script http-passwd -p 80,443", "Nmap - http-passwd", "http-passwd")


def scan_http_phpmyadmin_dir_traversal(target: str) -> dict:
    """phpMyAdmin 2.6.4-pl1 directory traversal vulnerability."""
    return _run_nse_scan(target, "--script http-phpmyadmin-dir-traversal -p 80,443", "Nmap - http-phpmyadmin-dir-traversal", "http-phpmyadmin-dir-traversal")


def scan_http_phpself_xss(target: str) -> dict:
    """PHP files vulnerable to $_SERVER['PHP_SELF'] XSS. Ports 80, 443."""
    return _run_nse_scan(target, "--script http-phpself-xss -p 80,443", "Nmap - http-phpself-xss", "http-phpself-xss")


def scan_http_shellshock(target: str) -> dict:
    """Bash Shellshock RCE via HTTP CGI (CVE-2014-6271 / CVE-2014-7169)."""
    return _run_nse_scan(target, "--script http-shellshock -p 80,443,8080", "Nmap - http-shellshock", "http-shellshock")


def scan_http_slowloris_check(target: str) -> dict:
    """Slowloris DoS vulnerability check — detection only, no actual DoS sent."""
    return _run_nse_scan(target, "--script http-slowloris-check -p 80,443", "Nmap - http-slowloris-check", "http-slowloris-check")


def scan_http_sql_injection(target: str) -> dict:
    """Spider and test all URLs and forms for SQL injection vulnerabilities."""
    return _run_nse_scan(target, "--script http-sql-injection -p 80,443", "Nmap - http-sql-injection", "http-sql-injection")


def scan_http_stored_xss(target: str) -> dict:
    """Stored XSS via unfiltered HTML injection. Ports 80, 443."""
    return _run_nse_scan(target, "--script http-stored-xss -p 80,443", "Nmap - http-stored-xss", "http-stored-xss")


def scan_http_tplink_dir_traversal(target: str) -> dict:
    """TP-Link router directory traversal to read configuration. Port 80."""
    return _run_nse_scan(target, "--script http-tplink-dir-traversal -p 80", "Nmap - http-tplink-dir-traversal", "http-tplink-dir-traversal")


def scan_http_trace(target: str) -> dict:
    """HTTP TRACE method enabled — Cross-Site Tracing (XST) risk."""
    return _run_nse_scan(target, "--script http-trace -p 80,443", "Nmap - http-trace", "http-trace")


def scan_http_vmware_path_vuln(target: str) -> dict:
    """VMware ESX/ESXi path traversal vulnerability (CVE-2009-3733)."""
    return _run_nse_scan(target, "--script http-vmware-path-vuln -p 80,443,902", "Nmap - http-vmware-path-vuln", "http-vmware-path-vuln")


def scan_http_vuln_cve2006_3392(target: str) -> dict:
    """Webmin file disclosure vulnerability (CVE-2006-3392). Port 10000."""
    return _run_nse_scan(target, "--script http-vuln-cve2006-3392 -p 10000", "Nmap - http-vuln-cve2006-3392", "http-vuln-cve2006-3392")


def scan_http_vuln_cve2009_3960(target: str) -> dict:
    """Adobe XML External Entity injection (CVE-2009-3960). Ports 80, 443."""
    return _run_nse_scan(target, "--script http-vuln-cve2009-3960 -p 80,443", "Nmap - http-vuln-cve2009-3960", "http-vuln-cve2009-3960")


def scan_http_vuln_cve2010_0738(target: str) -> dict:
    """JBoss JMX console authentication bypass (CVE-2010-0738). Ports 8080, 8443."""
    return _run_nse_scan(target, "--script http-vuln-cve2010-0738 -p 8080,8443", "Nmap - http-vuln-cve2010-0738", "http-vuln-cve2010-0738")


def scan_http_vuln_cve2010_2861(target: str) -> dict:
    """ColdFusion traversal to retrieve admin password hash (CVE-2010-2861)."""
    return _run_nse_scan(target, "--script http-vuln-cve2010-2861 -p 80,443,8500", "Nmap - http-vuln-cve2010-2861", "http-vuln-cve2010-2861")


def scan_http_vuln_cve2011_3192(target: str) -> dict:
    """Apache multiple range header Denial of Service (CVE-2011-3192)."""
    return _run_nse_scan(target, "--script http-vuln-cve2011-3192 -p 80,443", "Nmap - http-vuln-cve2011-3192", "http-vuln-cve2011-3192")


def scan_http_vuln_cve2011_3368(target: str) -> dict:
    """Apache mod_proxy reverse proxy bypass (CVE-2011-3368). Ports 80, 443."""
    return _run_nse_scan(target, "--script http-vuln-cve2011-3368 -p 80,443", "Nmap - http-vuln-cve2011-3368", "http-vuln-cve2011-3368")


def scan_http_vuln_cve2012_1823(target: str) -> dict:
    """PHP-CGI query string code disclosure / RCE (CVE-2012-1823)."""
    return _run_nse_scan(target, "--script http-vuln-cve2012-1823 -p 80,443", "Nmap - http-vuln-cve2012-1823", "http-vuln-cve2012-1823")


def scan_http_vuln_cve2013_0156(target: str) -> dict:
    """Ruby on Rails XML object injection RCE/DoS (CVE-2013-0156)."""
    return _run_nse_scan(target, "--script http-vuln-cve2013-0156 -p 80,443,3000", "Nmap - http-vuln-cve2013-0156", "http-vuln-cve2013-0156")


def scan_http_vuln_cve2013_6786(target: str) -> dict:
    """Allegro RomPager open redirect and XSS (CVE-2013-6786). Port 80."""
    return _run_nse_scan(target, "--script http-vuln-cve2013-6786 -p 80", "Nmap - http-vuln-cve2013-6786", "http-vuln-cve2013-6786")


def scan_http_vuln_cve2013_7091(target: str) -> dict:
    """Zimbra 0-day LFI (pre-7.2.6 / pre-8.0.2). Ports 80, 443."""
    return _run_nse_scan(target, "--script http-vuln-cve2013-7091 -p 80,443", "Nmap - http-vuln-cve2013-7091", "http-vuln-cve2013-7091")


def scan_http_vuln_cve2014_2126(target: str) -> dict:
    """Cisco ASA ASDM privilege escalation (CVE-2014-2126). Port 443."""
    return _run_nse_scan(target, "--script http-vuln-cve2014-2126 -p 443", "Nmap - http-vuln-cve2014-2126", "http-vuln-cve2014-2126")


def scan_http_vuln_cve2014_2127(target: str) -> dict:
    """Cisco ASA SSL VPN privilege escalation (CVE-2014-2127). Port 443."""
    return _run_nse_scan(target, "--script http-vuln-cve2014-2127 -p 443", "Nmap - http-vuln-cve2014-2127", "http-vuln-cve2014-2127")


def scan_http_vuln_cve2014_2128(target: str) -> dict:
    """Cisco ASA SSL VPN authentication bypass (CVE-2014-2128). Port 443."""
    return _run_nse_scan(target, "--script http-vuln-cve2014-2128 -p 443", "Nmap - http-vuln-cve2014-2128", "http-vuln-cve2014-2128")


def scan_http_vuln_cve2014_2129(target: str) -> dict:
    """Cisco ASA SIP Denial of Service (CVE-2014-2129). Port 5060."""
    return _run_nse_scan(target, "--script http-vuln-cve2014-2129 -p 5060", "Nmap - http-vuln-cve2014-2129", "http-vuln-cve2014-2129")


def scan_http_vuln_cve2014_3704(target: str) -> dict:
    """Drupal Drupageddon SQL injection (CVE-2014-3704). Ports 80, 443."""
    return _run_nse_scan(target, "--script http-vuln-cve2014-3704 -p 80,443", "Nmap - http-vuln-cve2014-3704", "http-vuln-cve2014-3704")


def scan_http_vuln_cve2014_8877(target: str) -> dict:
    """WordPress CM Download Manager RCE (≤ 2.0.0, CVE-2014-8877)."""
    return _run_nse_scan(target, "--script http-vuln-cve2014-8877 -p 80,443", "Nmap - http-vuln-cve2014-8877", "http-vuln-cve2014-8877")


def scan_http_vuln_cve2015_1427(target: str) -> dict:
    """Elasticsearch Groovy sandbox bypass RCE (CVE-2015-1427). Port 9200."""
    return _run_nse_scan(target, "--script http-vuln-cve2015-1427 -p 9200", "Nmap - http-vuln-cve2015-1427", "http-vuln-cve2015-1427")


def scan_http_vuln_cve2015_1635(target: str) -> dict:
    """Windows HTTP.sys remote code execution (MS15-034 / CVE-2015-1635). Port 80."""
    return _run_nse_scan(target, "--script http-vuln-cve2015-1635 -p 80", "Nmap - http-vuln-cve2015-1635", "http-vuln-cve2015-1635")


def scan_http_vuln_cve2017_1001000(target: str) -> dict:
    """WordPress 4.7.x REST API content injection (CVE-2017-1001000)."""
    return _run_nse_scan(target, "--script http-vuln-cve2017-1001000 -p 80,443", "Nmap - http-vuln-cve2017-1001000", "http-vuln-cve2017-1001000")


def scan_http_vuln_cve2017_5638(target: str) -> dict:
    """Apache Struts 2 remote code execution (CVE-2017-5638). Ports 80, 443, 8080."""
    return _run_nse_scan(target, "--script http-vuln-cve2017-5638 -p 80,443,8080", "Nmap - http-vuln-cve2017-5638", "http-vuln-cve2017-5638")


def scan_http_vuln_cve2017_5689(target: str) -> dict:
    """Intel AMT privilege escalation INTEL-SA-00075 (CVE-2017-5689). Ports 16992, 16993."""
    return _run_nse_scan(target, "--script http-vuln-cve2017-5689 -p 16992,16993", "Nmap - http-vuln-cve2017-5689", "http-vuln-cve2017-5689")


def scan_http_vuln_cve2017_8917(target: str) -> dict:
    """Joomla! 3.7.x SQL injection vulnerability (CVE-2017-8917)."""
    return _run_nse_scan(target, "--script http-vuln-cve2017-8917 -p 80,443", "Nmap - http-vuln-cve2017-8917", "http-vuln-cve2017-8917")


def scan_http_vuln_misfortune_cookie(target: str) -> dict:
    """RomPager Misfortune Cookie vulnerability (CVE-2014-9222). Port 80."""
    return _run_nse_scan(target, "--script http-vuln-misfortune-cookie -p 80", "Nmap - http-vuln-misfortune-cookie", "http-vuln-misfortune-cookie")


def scan_http_vuln_wnr1000_creds(target: str) -> dict:
    """Netgear WNR1000v4 credential disclosure via firmware vulnerability. Port 80."""
    return _run_nse_scan(target, "--script http-vuln-wnr1000-creds -p 80", "Nmap - http-vuln-wnr1000-creds", "http-vuln-wnr1000-creds")


def scan_http_wordpress_users(target: str) -> dict:
    """WordPress user enumeration via information disclosure. Ports 80, 443."""
    return _run_nse_scan(target, "--script http-wordpress-users -p 80,443", "Nmap - http-wordpress-users", "http-wordpress-users")


# ── IPMI ────────────────────────────────────────────────────────────────────

def scan_ipmi_cipher_zero(target: str) -> dict:
    """IPMI 2.0 cipher zero authentication bypass. Port 623 UDP."""
    return _run_nse_scan(target, "--script ipmi-cipher-zero -p 623", "Nmap - ipmi-cipher-zero", "ipmi-cipher-zero")


def scan_supermicro_ipmi_conf(target: str) -> dict:
    """Supermicro IPMI configuration file download with clear-text credentials. Port 49152."""
    return _run_nse_scan(target, "--script supermicro-ipmi-conf -p 49152", "Nmap - supermicro-ipmi-conf", "supermicro-ipmi-conf")


# ── IRC ─────────────────────────────────────────────────────────────────────

def scan_irc_botnet_channels(target: str) -> dict:
    """Detect IRC channels commonly used by botnets. Ports 6667, 6697."""
    return _run_nse_scan(target, "--script irc-botnet-channels -p 6667,6697", "Nmap - irc-botnet-channels", "irc-botnet-channels")


def scan_irc_unrealircd_backdoor(target: str) -> dict:
    """UnrealIRCd 3.2.8.1 backdoor detection via timing test. Port 6667."""
    return _run_nse_scan(target, "--script irc-unrealircd-backdoor -p 6667", "Nmap - irc-unrealircd-backdoor", "irc-unrealircd-backdoor")


# ── MYSQL ────────────────────────────────────────────────────────────────────

def scan_mysql_vuln_cve2012_2122(target: str) -> dict:
    """MySQL authentication bypass via timing vulnerability (CVE-2012-2122). Port 3306."""
    return _run_nse_scan(target, "--script mysql-vuln-cve2012-2122 -p 3306", "Nmap - mysql-vuln-cve2012-2122", "mysql-vuln-cve2012-2122")


def scan_ms_sql_info(target: str) -> dict:
    """MS SQL Server enumeration — version, instance name, named pipes. Port 1433."""
    return _run_nse_scan(target, "--script ms-sql-info -p 1433", "Nmap - ms-sql-info", "ms-sql-info")


# ── MISC SERVICES ────────────────────────────────────────────────────────────

def scan_netbus_auth_bypass(target: str) -> dict:
    """NetBus remote access tool authentication bypass (no password). Port 12345."""
    return _run_nse_scan(target, "--script netbus-auth-bypass -p 12345", "Nmap - netbus-auth-bypass", "netbus-auth-bypass")


def scan_puppet_naivesigning(target: str) -> dict:
    """Puppet CA naive signing — CSR auto-signing enabled. Port 8140."""
    return _run_nse_scan(target, "--script puppet-naivesigning -p 8140", "Nmap - puppet-naivesigning", "puppet-naivesigning")


def scan_qconn_exec(target: str) -> dict:
    """Unauthenticated command execution via QNX QCONN service. ⚠ CAUTION. Port 8000."""
    return _run_nse_scan(target, "--script qconn-exec -p 8000", "Nmap - qconn-exec", "qconn-exec")


def scan_rmi_vuln_classloader(target: str) -> dict:
    """Java RMI registry remote class loading — possible remote code execution. Port 1099."""
    return _run_nse_scan(target, "--script rmi-vuln-classloader -p 1099", "Nmap - rmi-vuln-classloader", "rmi-vuln-classloader")


def scan_wdb_version(target: str) -> dict:
    """VxWorks WDB debug agent information disclosure and related vulnerabilities. Port 17185."""
    return _run_nse_scan(target, "--script wdb-version -p 17185", "Nmap - wdb-version", "wdb-version")


# ── RDP ─────────────────────────────────────────────────────────────────────

def scan_rdp_vuln_ms12_020(target: str) -> dict:
    """RDP MS12-020 denial of service and information disclosure vulnerability. Port 3389."""
    return _run_nse_scan(target, "--script rdp-vuln-ms12-020 -p 3389", "Nmap - rdp-vuln-ms12-020", "rdp-vuln-ms12-020")


# ── VNC ─────────────────────────────────────────────────────────────────────

def scan_realvnc_auth_bypass(target: str) -> dict:
    """RealVNC authentication bypass (CVE-2006-2369). Ports 5900, 5901."""
    return _run_nse_scan(target, "--script realvnc-auth-bypass -p 5900,5901", "Nmap - realvnc-auth-bypass", "realvnc-auth-bypass")


# ── RSA / CRYPTO ─────────────────────────────────────────────────────────────

def scan_rsa_vuln_roca(target: str) -> dict:
    """RSA keys vulnerable to ROCA factorization attack (CVE-2017-15361). Ports 443, 22."""
    return _run_nse_scan(target, "--script rsa-vuln-roca -p 443,22", "Nmap - rsa-vuln-roca", "rsa-vuln-roca")


# ── SMB / WINDOWS ────────────────────────────────────────────────────────────

def scan_smb_double_pulsar_backdoor(target: str) -> dict:
    """DoublePulsar SMB backdoor detection (NSA implant). Port 445."""
    return _run_nse_scan(target, "--script smb-double-pulsar-backdoor -p 445", "Nmap - smb-double-pulsar-backdoor", "smb-double-pulsar-backdoor")


def scan_smb_vuln_conficker(target: str) -> dict:
    """Conficker worm infected Windows system detection. Ports 139, 445."""
    return _run_nse_scan(target, "--script smb-vuln-conficker -p 139,445", "Nmap - smb-vuln-conficker", "smb-vuln-conficker")


def scan_smb_vuln_cve_2012_1182(target: str) -> dict:
    """Samba heap overflow remote code execution (CVE-2012-1182). Ports 139, 445."""
    return _run_nse_scan(target, "--script smb-vuln-cve-2012-1182 -p 139,445", "Nmap - smb-vuln-cve-2012-1182", "smb-vuln-cve-2012-1182")


def scan_smb_vuln_cve_2017_7494(target: str) -> dict:
    """SambaCry — Samba shared library RCE (CVE-2017-7494). Ports 139, 445."""
    return _run_nse_scan(target, "--script smb-vuln-cve-2017-7494 -p 139,445", "Nmap - smb-vuln-cve-2017-7494", "smb-vuln-cve-2017-7494")


def scan_smb_vuln_cve2009_3103(target: str) -> dict:
    """Windows SMBv2 remote Denial of Service (CVE-2009-3103). ⚠ CAUTION: crashes target. Port 445."""
    return _run_nse_scan(target, "--script smb-vuln-cve2009-3103 -p 445", "Nmap - smb-vuln-cve2009-3103", "smb-vuln-cve2009-3103")


def scan_smb_vuln_ms06_025(target: str) -> dict:
    """Windows RAS RPC service vulnerability MS06-025. Ports 139, 445."""
    return _run_nse_scan(target, "--script smb-vuln-ms06-025 -p 139,445", "Nmap - smb-vuln-ms06-025", "smb-vuln-ms06-025")


def scan_smb_vuln_ms07_029(target: str) -> dict:
    """Windows DNS Server RPC vulnerability MS07-029. Ports 139, 445."""
    return _run_nse_scan(target, "--script smb-vuln-ms07-029 -p 139,445", "Nmap - smb-vuln-ms07-029", "smb-vuln-ms07-029")


def scan_smb_vuln_ms08_067(target: str) -> dict:
    """MS08-067 NetAPI remote code execution (WannaCry precursor). ⚠ CAUTION: can destabilise target."""
    return _run_nse_scan(target, "--script smb-vuln-ms08-067 -p 139,445", "Nmap - smb-vuln-ms08-067", "smb-vuln-ms08-067")


def scan_smb_vuln_ms10_054(target: str) -> dict:
    """SMB remote memory corruption vulnerability MS10-054. Ports 139, 445."""
    return _run_nse_scan(target, "--script smb-vuln-ms10-054 -p 139,445", "Nmap - smb-vuln-ms10-054", "smb-vuln-ms10-054")


def scan_smb_vuln_ms10_061(target: str) -> dict:
    """Printer Spooler impersonation vulnerability MS10-061. Ports 139, 445."""
    return _run_nse_scan(target, "--script smb-vuln-ms10-061 -p 139,445", "Nmap - smb-vuln-ms10-061", "smb-vuln-ms10-061")


def scan_smb_vuln_ms17_010(target: str) -> dict:
    """EternalBlue SMBv1 remote code execution — WannaCry / Petya (MS17-010). Ports 139, 445."""
    return _run_nse_scan(target, "--script smb-vuln-ms17-010 -p 139,445", "Nmap - smb-vuln-ms17-010", "smb-vuln-ms17-010")


def scan_smb_vuln_regsvc_dos(target: str) -> dict:
    """Windows 2000 regsvc null pointer dereference DoS. ⚠ CAUTION: crashes the service."""
    return _run_nse_scan(target, "--script smb-vuln-regsvc-dos -p 139,445", "Nmap - smb-vuln-regsvc-dos", "smb-vuln-regsvc-dos")


def scan_smb_vuln_webexec(target: str) -> dict:
    """Cisco WebExService remote code execution via SMB (WebExec). Ports 139, 445."""
    return _run_nse_scan(target, "--script smb-vuln-webexec -p 139,445", "Nmap - smb-vuln-webexec", "smb-vuln-webexec")


def scan_smb2_vuln_uptime(target: str) -> dict:
    """Infer missing Windows patches from SMB2 uptime data. Port 445."""
    return _run_nse_scan(target, "--script smb2-vuln-uptime -p 445", "Nmap - smb2-vuln-uptime", "smb2-vuln-uptime")


def scan_samba_vuln_cve_2012_1182(target: str) -> dict:
    """Samba heap overflow (CVE-2012-1182) — alternative check. Ports 139, 445."""
    return _run_nse_scan(target, "--script samba-vuln-cve-2012-1182 -p 139,445", "Nmap - samba-vuln-cve-2012-1182", "samba-vuln-cve-2012-1182")


# ── SMTP ─────────────────────────────────────────────────────────────────────

def scan_smtp_vuln_cve2010_4344(target: str) -> dict:
    """Exim heap overflow and privilege escalation (CVE-2010-4344 / CVE-2010-4345). Ports 25, 465, 587."""
    return _run_nse_scan(target, "--script smtp-vuln-cve2010-4344 -p 25,465,587", "Nmap - smtp-vuln-cve2010-4344", "smtp-vuln-cve2010-4344")


def scan_smtp_vuln_cve2011_1720(target: str) -> dict:
    """Postfix + Cyrus SASL memory corruption (CVE-2011-1720). Ports 25, 465, 587."""
    return _run_nse_scan(target, "--script smtp-vuln-cve2011-1720 -p 25,465,587", "Nmap - smtp-vuln-cve2011-1720", "smtp-vuln-cve2011-1720")


def scan_smtp_vuln_cve2011_1764(target: str) -> dict:
    """Exim DKIM format string remote code execution (CVE-2011-1764). Ports 25, 465, 587."""
    return _run_nse_scan(target, "--script smtp-vuln-cve2011-1764 -p 25,465,587", "Nmap - smtp-vuln-cve2011-1764", "smtp-vuln-cve2011-1764")


# ── SSL / TLS ─────────────────────────────────────────────────────────────────

def scan_ssl_ccs_injection(target: str) -> dict:
    """OpenSSL ChangeCipherSpec injection vulnerability (CVE-2014-0224). Ports 443, 8443."""
    return _run_nse_scan(target, "--script ssl-ccs-injection -p 443,8443", "Nmap - ssl-ccs-injection", "ssl-ccs-injection")


def scan_ssl_cert_intaddr(target: str) -> dict:
    """Private IPv4 addresses exposed in public TLS certificates. Ports 443, 8443."""
    return _run_nse_scan(target, "--script ssl-cert-intaddr -p 443,8443", "Nmap - ssl-cert-intaddr", "ssl-cert-intaddr")


def scan_ssl_dh_params(target: str) -> dict:
    """Weak ephemeral Diffie-Hellman parameters — Logjam attack risk. Ports 443, 8443."""
    return _run_nse_scan(target, "--script ssl-dh-params -p 443,8443", "Nmap - ssl-dh-params", "ssl-dh-params")


def scan_ssl_heartbleed(target: str) -> dict:
    """OpenSSL Heartbleed memory disclosure vulnerability (CVE-2014-0160). Ports 443, 8443."""
    return _run_nse_scan(target, "--script ssl-heartbleed -p 443,8443", "Nmap - ssl-heartbleed", "ssl-heartbleed")


def scan_ssl_known_key(target: str) -> dict:
    """Certificate fingerprint check against known bad / compromised keys. Ports 443, 8443."""
    return _run_nse_scan(target, "--script ssl-known-key -p 443,8443", "Nmap - ssl-known-key", "ssl-known-key")


def scan_ssl_poodle(target: str) -> dict:
    """SSLv3 CBC POODLE vulnerability (CVE-2014-3566). Ports 443, 8443."""
    return _run_nse_scan(target, "--script ssl-poodle -p 443,8443", "Nmap - ssl-poodle", "ssl-poodle")


def scan_sslv2_drown(target: str) -> dict:
    """SSLv2 support and DROWN attack related CVE checks. Ports 443, 8443."""
    return _run_nse_scan(target, "--script sslv2-drown -p 443,8443", "Nmap - sslv2-drown", "sslv2-drown")


def scan_tls_ticketbleed(target: str) -> dict:
    """F5 BIG-IP TLS session ticket memory leak — Ticketbleed (CVE-2016-9244). Port 443."""
    return _run_nse_scan(target, "--script tls-ticketbleed -p 443", "Nmap - tls-ticketbleed", "tls-ticketbleed")


# ── CVE DATABASE ─────────────────────────────────────────────────────────────

def scan_vulners(target: str) -> dict:
    """
    CVE and CVSS score lookup via the Vulners database.

    Automatically includes ``-sV`` to generate CPE data required for
    vulnerability matching. Timeout: 300 seconds.

    Equivalent to: ``nmap -sV --script vulners <target>``

    Args:
        target: IP address or hostname.

    Returns:
        Result dict with per-port CVE listings and CVSS scores.
    """
    return _run_nse_scan(target, "-sV --script vulners", "Nmap - vulners", "vulners", timeout=300)
