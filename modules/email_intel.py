"""
email_intel.py — Email breach checking, reputation, DNS security, and account discovery.

Each function:
  - Checks CONFIG for required API key; skips gracefully if missing.
  - Returns a structured dict: source, skipped, error, flagged, details.

No unhandled exceptions are raised — all errors produce an error-flagged result dict.
"""

from __future__ import annotations

import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import CONFIG  # noqa: E402

from modules.utils import console, print_result_table, print_section_header, print_skipped

REQUEST_TIMEOUT = 15

# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _skipped_result(source: str, reason: str = "No API key configured") -> dict:
    return {"source": source, "skipped": True, "error": False, "flagged": False, "details": {"reason": reason}}


def _error_result(source: str, message: str) -> dict:
    return {"source": source, "skipped": False, "error": True, "flagged": False, "details": {"Error": message}}


def _not_found_result(source: str, message: str) -> dict:
    return {"source": source, "skipped": False, "error": False, "flagged": False, "details": {"Status": message}}


# ---------------------------------------------------------------------------
# 1. HaveIBeenPwned v3
# ---------------------------------------------------------------------------

def check_hibp(email: str) -> dict:
    """
    Check HaveIBeenPwned v3 for breaches associated with an email address.

    Args:
        email: Email address to check.

    Returns:
        Structured result dict with breach details if found.
    """
    source = "HaveIBeenPwned"
    key = CONFIG.get("hibp")
    if not key:
        return _skipped_result(source)

    headers = {
        "hibp-api-key": key,
        "User-Agent":   "ThreatScope",
        "Accept":       "application/json",
    }
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false"

    try:
        resp = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)

        if resp.status_code == 404:
            return _not_found_result(source, "No breaches found — address appears clean.")

        if resp.status_code == 429:
            return _error_result(source, "Rate limit hit (429). Wait before retrying.")

        if resp.status_code in (401, 403):
            return _error_result(source, "Invalid HIBP API key — check config.yaml.")

        resp.raise_for_status()
        breaches = resp.json()

        if not breaches:
            return _not_found_result(source, "No breaches found.")

        breach_names  = [b.get("Name", "Unknown") for b in breaches]
        breach_count  = len(breaches)
        is_sensitive  = any(b.get("IsSensitive", False) for b in breaches)
        has_passwords = any("Passwords" in b.get("DataClasses", []) for b in breaches)

        details: dict = {
            "Email":             email,
            "Breach Count":      breach_count,
            "Breaches":          ", ".join(breach_names[:10]) + ("..." if breach_count > 10 else ""),
            "Contains Passwords": "yes" if has_passwords else "no",
            "Has Sensitive Breach": "yes" if is_sensitive else "no",
        }

        # Add details for each breach (up to 5)
        for b in breaches[:5]:
            name = b.get("Name", "Unknown")
            date = b.get("BreachDate", "Unknown")
            classes = ", ".join(b.get("DataClasses", [])[:4])
            details[f"  {name}"] = f"Date: {date} | Data: {classes}"

        return {
            "source":  source,
            "skipped": False,
            "error":   False,
            "flagged": True,
            "details": details,
        }

    except requests.exceptions.RequestException as exc:
        return _error_result(source, str(exc))


# ---------------------------------------------------------------------------
# 2. EmailRep.io
# ---------------------------------------------------------------------------

def check_emailrep(email: str) -> dict:
    """
    Query EmailRep.io for email reputation scoring.

    Args:
        email: Email address to check.

    Returns:
        Structured result dict with reputation data.
    """
    source = "EmailRep.io"
    key = CONFIG.get("emailrep")

    headers: dict = {"User-Agent": "ThreatScope"}
    if key:
        headers["Key"] = key

    try:
        resp = requests.get(
            f"https://emailrep.io/{email}",
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        )

        if resp.status_code == 429:
            return _error_result(source, "Rate limit hit (429).")

        if resp.status_code == 400:
            return _error_result(source, "Invalid email address format.")

        resp.raise_for_status()
        data = resp.json()

        reputation = data.get("reputation", "unknown")
        suspicious  = data.get("suspicious", False)
        refs        = data.get("references", 0)
        attrs       = data.get("details", {})

        details: dict = {
            "Email":          email,
            "Reputation":     reputation,
            "Suspicious":     "yes" if suspicious else "no",
            "References":     refs,
            "Blacklisted":    "yes" if attrs.get("blacklisted") else "no",
            "Malicious Activity": "yes" if attrs.get("malicious_activity") else "no",
            "Credentials Leaked": "yes" if attrs.get("credentials_leaked") else "no",
            "Data Breach":    "yes" if attrs.get("data_breach") else "no",
            "Free Provider":  "yes" if attrs.get("free_provider") else "no",
            "Disposable":     "yes" if attrs.get("disposable") else "no",
            "Deliverable":    "yes" if attrs.get("deliverable") else "no",
            "Valid MX":       "yes" if attrs.get("valid_mx") else "no",
            "SPF Strict":     "yes" if attrs.get("spf_strict") else "no",
            "DMARC Enforced": "yes" if attrs.get("dmarc_enforced") else "no",
        }

        flagged = suspicious or reputation in ("high", "critical") or attrs.get("malicious_activity")

        return {
            "source":  source,
            "skipped": False,
            "error":   False,
            "flagged": bool(flagged),
            "details": details,
        }

    except requests.exceptions.RequestException as exc:
        return _error_result(source, str(exc))


# ---------------------------------------------------------------------------
# 3. Holehe (subprocess)
# ---------------------------------------------------------------------------

def check_holehe(email: str) -> dict:
    """
    Run holehe to discover which online services use this email address.

    Args:
        email: Email address to check.

    Returns:
        Structured result dict listing discovered accounts.
    """
    source = "Holehe"
    import shutil
    if not shutil.which("holehe") and not _holehe_importable():
        return _skipped_result(source, "holehe not installed. Run: pip install holehe")

    try:
        result = subprocess.run(
            ["holehe", email, "--only-used", "--no-color"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        output = result.stdout + result.stderr
        lines  = [ln.strip() for ln in output.splitlines() if ln.strip()]

        # Parse [+] lines as found accounts
        found = [ln for ln in lines if ln.startswith("[+]")]
        maybe = [ln for ln in lines if ln.startswith("[?]")]

        account_names = [ln[3:].strip() for ln in found]
        maybe_names   = [ln[3:].strip() for ln in maybe]

        details: dict = {
            "Email":            email,
            "Accounts Found":   len(account_names),
            "Accounts (Maybe)": len(maybe_names),
        }

        if account_names:
            details["Found On"] = ", ".join(account_names[:20])
        if maybe_names:
            details["Possible"] = ", ".join(maybe_names[:10])

        return {
            "source":  source,
            "skipped": False,
            "error":   False,
            "flagged": len(account_names) > 0,
            "details": details,
        }

    except subprocess.TimeoutExpired:
        return _error_result(source, "holehe timed out after 120 seconds.")
    except FileNotFoundError:
        return _skipped_result(source, "holehe binary not found. Run: pip install holehe")
    except Exception as exc:
        return _error_result(source, str(exc))


def _holehe_importable() -> bool:
    import importlib.util
    return importlib.util.find_spec("holehe") is not None


# ---------------------------------------------------------------------------
# 4. Email DNS Security (SPF/DKIM/DMARC/BIMI)
# ---------------------------------------------------------------------------

def check_email_dns(domain: str) -> dict:
    """
    Check DNS security records for an email domain: MX, SPF, DKIM, DMARC, BIMI.

    Args:
        domain: Domain portion of an email address (e.g. gmail.com).

    Returns:
        Structured result dict with DNS security analysis and score.
    """
    source = "Email DNS Security"

    try:
        import dns.resolver
    except ImportError:
        return _skipped_result(source, "dnspython not installed. Run: pip install dnspython")

    details: dict = {"Domain": domain}
    score = 0

    # MX records
    try:
        mx_records = dns.resolver.resolve(domain, "MX")
        mx_list    = sorted([str(r.exchange).rstrip(".") for r in mx_records])
        details["MX Records"] = ", ".join(mx_list[:3])
        score += 10
    except Exception:
        details["MX Records"] = "none / error"

    # SPF
    spf_record = _dns_txt_search(dns, domain, "v=spf1")
    if spf_record:
        details["SPF Record"] = spf_record[:100]
        score += 20
        if "~all" in spf_record:
            details["SPF Policy"] = "softfail (~all)"
        elif "-all" in spf_record:
            details["SPF Policy"] = "fail (-all) — strict"
            score += 10
        elif "?all" in spf_record:
            details["SPF Policy"] = "neutral (?all)"
        else:
            details["SPF Policy"] = "none (+all or missing)"
    else:
        details["SPF Record"] = "missing"

    # DMARC
    dmarc_record = _dns_txt_search(dns, f"_dmarc.{domain}", "v=DMARC1")
    if dmarc_record:
        details["DMARC Record"] = dmarc_record[:100]
        score += 20
        if "p=reject" in dmarc_record:
            details["DMARC Policy"] = "reject — strict"
            score += 15
        elif "p=quarantine" in dmarc_record:
            details["DMARC Policy"] = "quarantine — moderate"
            score += 10
        elif "p=none" in dmarc_record:
            details["DMARC Policy"] = "none — monitoring only"
    else:
        details["DMARC Record"] = "missing"

    # DKIM — try common selectors
    dkim_found = False
    for selector in ("google", "default", "mail", "selector1", "selector2", "k1", "smtp"):
        dkim_record = _dns_txt_search(dns, f"{selector}._domainkey.{domain}", "v=DKIM1")
        if dkim_record:
            details["DKIM Record"] = f"selector={selector} ({dkim_record[:60]}...)"
            score += 20
            dkim_found = True
            break
    if not dkim_found:
        details["DKIM Record"] = "not found (checked common selectors)"

    # BIMI
    bimi_record = _dns_txt_search(dns, f"default._bimi.{domain}", "v=BIMI1")
    if bimi_record:
        details["BIMI Record"] = bimi_record[:80]
        score += 5
    else:
        details["BIMI Record"] = "not configured"

    # Score and grade
    score = min(score, 100)
    if score >= 90:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 55:
        grade = "C"
    elif score >= 35:
        grade = "D"
    else:
        grade = "F"

    details["Security Score"] = f"{score}/100"
    details["Grade"]          = grade

    flagged = score < 40

    return {
        "source":  source,
        "skipped": False,
        "error":   False,
        "flagged": flagged,
        "details": details,
    }


def _dns_txt_search(dns_module: object, name: str, prefix: str) -> Optional[str]:
    """Resolve TXT records for name, return first containing prefix."""
    try:
        records = dns_module.resolver.resolve(name, "TXT")
        for r in records:
            txt = b"".join(r.strings).decode("utf-8", errors="ignore")
            if prefix in txt:
                return txt
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Menu
# ---------------------------------------------------------------------------

def handle_email_menu() -> None:
    """Interactive email intelligence menu."""
    from rich.prompt import Prompt

    while True:
        console.print("\n[bold cyan]Email Intelligence[/bold cyan]")
        console.print("  [white]1[/white]  Check HaveIBeenPwned (breaches)")
        console.print("  [white]2[/white]  Check EmailRep.io (reputation)")
        console.print("  [white]3[/white]  Run Holehe (account discovery)")
        console.print("  [white]4[/white]  Check DNS security (SPF/DKIM/DMARC)")
        console.print("  [white]5[/white]  Full report (all checks)")
        console.print("  [white]0[/white]  Back\n")

        choice = Prompt.ask("[bold cyan]Select option[/bold cyan]", default="0").strip()

        if choice == "0":
            break

        if choice in ("1", "2", "3"):
            email = Prompt.ask("[bold cyan]Enter email address[/bold cyan]").strip()
            if not email or "@" not in email:
                console.print("[yellow]Invalid email address.[/yellow]")
                continue

        if choice == "1":
            with _spinner("Querying HaveIBeenPwned..."):
                result = check_hibp(email)
            _display_result(result, f"HaveIBeenPwned: {email}")

        elif choice == "2":
            with _spinner("Querying EmailRep.io..."):
                result = check_emailrep(email)
            _display_result(result, f"EmailRep.io: {email}")

        elif choice == "3":
            console.print("[dim]Running holehe — this may take up to 2 minutes...[/dim]")
            result = check_holehe(email)
            _display_result(result, f"Holehe: {email}")

        elif choice == "4":
            domain = Prompt.ask("[bold cyan]Enter domain (e.g. gmail.com)[/bold cyan]").strip()
            if not domain:
                console.print("[yellow]Invalid domain.[/yellow]")
                continue
            with _spinner("Checking DNS records..."):
                result = check_email_dns(domain)
            _display_result(result, f"DNS Security: {domain}")

        elif choice == "5":
            email = Prompt.ask("[bold cyan]Enter email address[/bold cyan]").strip()
            if not email or "@" not in email:
                console.print("[yellow]Invalid email address.[/yellow]")
                continue
            domain = email.split("@", 1)[1]

            console.print(f"\n[cyan]Running full email intelligence for:[/cyan] {email}\n")
            results: dict = {}

            with ThreadPoolExecutor(max_workers=4) as executor:
                futures = {
                    executor.submit(check_hibp,       email):      "HaveIBeenPwned",
                    executor.submit(check_emailrep,   email):      "EmailRep.io",
                    executor.submit(check_holehe,     email):      "Holehe",
                    executor.submit(check_email_dns,  domain):     "DNS Security",
                }
                for future in as_completed(futures):
                    name = futures[future]
                    try:
                        results[name] = future.result()
                    except Exception as exc:
                        results[name] = _error_result(name, str(exc))

            print_section_header(f"Email Intel Report: {email}")
            for name, result in results.items():
                _display_result(result, name)
        else:
            console.print("[yellow]Invalid option.[/yellow]")


def _display_result(result: dict, title: str) -> None:
    """Display a result dict; handle skipped/error states."""
    if result.get("skipped"):
        reason = result.get("details", {}).get("reason", "No API key")
        console.print(f"  [dim]○ {title}: SKIPPED — {reason}[/dim]\n")
        return
    if result.get("error"):
        err = result.get("details", {}).get("Error", "Unknown error")
        console.print(f"  [bold red]✗ {title}: ERROR — {err}[/bold red]\n")
        return
    print_result_table(result, title)


def _spinner(message: str):
    """Return a Progress context manager with a spinner."""
    from rich.progress import Progress, SpinnerColumn, TextColumn
    return Progress(SpinnerColumn(), TextColumn(f"[cyan]{message}"), transient=True, console=console)
