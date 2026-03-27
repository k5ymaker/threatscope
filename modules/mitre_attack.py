"""
mitre_attack.py — MITRE ATT&CK framework lookups using GitHub STIX bundle.

Downloads the enterprise-attack.json bundle from GitHub on first use, caches
it to ~/.threatscope/enterprise-attack.json, and queries it locally — no
TAXII server required.

Each public function:
  - Returns a structured dict: source, skipped, error, flagged, details.
  - Never raises exceptions to the caller.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path
from typing import Optional

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import CONFIG  # noqa: E402

from modules.utils import console, print_result_table, print_section_header

REQUEST_TIMEOUT = 30

# GitHub URL for MITRE ATT&CK Enterprise STIX bundle
_STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)

# Local cache location
_CACHE_DIR  = Path.home() / ".threatscope"
_CACHE_FILE = _CACHE_DIR / "enterprise-attack.json"

# No external lib required — always available
MITRE_AVAILABLE: bool = True

# Module-level cached data store
_attack_client: Optional["_AttackDataStore"] = None


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _skipped_result(source: str, reason: str = "ATT&CK data unavailable") -> dict:
    return {"source": source, "skipped": True, "error": False, "flagged": False, "details": {"reason": reason}}


def _error_result(source: str, message: str) -> dict:
    return {"source": source, "skipped": False, "error": True, "flagged": False, "details": {"Error": message}}


def _not_found_result(source: str, message: str) -> dict:
    return {"source": source, "skipped": False, "error": False, "flagged": False, "details": {"Status": message}}


def _no_attackcti(source: str) -> dict:
    return _skipped_result(source, "ATT&CK data could not be loaded.")


# ---------------------------------------------------------------------------
# In-memory STIX store (no TAXII / no stix2 library required)
# ---------------------------------------------------------------------------

class _AttackDataStore:
    """Thin wrapper around the raw STIX bundle list of objects."""

    def __init__(self, objects: list) -> None:
        self._objects = objects
        self._by_id: dict = {o.get("id"): o for o in objects if o.get("id")}

    def get_by_id(self, obj_id: str) -> Optional[dict]:
        return self._by_id.get(obj_id)

    def _query_type(self, type_name: str) -> list:
        return [
            o for o in self._objects
            if o.get("type") == type_name and not o.get("revoked")
        ]

    def get_techniques(self, include_subtechniques: bool = True) -> list:
        techs = self._query_type("attack-pattern")
        if not include_subtechniques:
            techs = [t for t in techs if not t.get("x_mitre_is_subtechnique")]
        return techs

    def get_groups(self) -> list:
        return self._query_type("intrusion-set")

    def get_software(self) -> list:
        return self._query_type("malware") + self._query_type("tool")

    def get_tactics(self) -> list:
        return self._query_type("x-mitre-tactic")

    def _rels_from(self, source_id: str, rel_type: str = "uses") -> list:
        return [
            o for o in self._objects
            if o.get("type") == "relationship"
            and o.get("relationship_type") == rel_type
            and o.get("source_ref") == source_id
        ]

    def get_techniques_used_by_group(self, group: dict) -> list:
        rels = self._rels_from(group.get("id", ""))
        return [
            self._by_id[r["target_ref"]]
            for r in rels
            if r.get("target_ref") in self._by_id
            and self._by_id[r["target_ref"]].get("type") == "attack-pattern"
        ]

    def get_techniques_used_by_software(self, sw: dict) -> list:
        rels = self._rels_from(sw.get("id", ""))
        return [
            self._by_id[r["target_ref"]]
            for r in rels
            if r.get("target_ref") in self._by_id
            and self._by_id[r["target_ref"]].get("type") == "attack-pattern"
        ]


# ---------------------------------------------------------------------------
# ATT&CK data load / cache
# ---------------------------------------------------------------------------

def _get_client() -> Optional[_AttackDataStore]:
    """
    Return the cached ATT&CK data store, loading on first call.

    Loads from ~/.threatscope/enterprise-attack.json if present, otherwise
    downloads from GitHub (one-time, ~12 MB).
    """
    global _attack_client
    if _attack_client is not None:
        return _attack_client

    from rich.progress import Progress, SpinnerColumn, TextColumn

    try:
        if _CACHE_FILE.exists():
            with Progress(
                SpinnerColumn(),
                TextColumn("[cyan]Loading MITRE ATT&CK data from cache..."),
                transient=True,
                console=console,
            ) as progress:
                progress.add_task("load")
                with open(_CACHE_FILE, "r", encoding="utf-8") as fh:
                    bundle = json.load(fh)
        else:
            _CACHE_DIR.mkdir(parents=True, exist_ok=True)
            console.print(
                "[bold cyan]First-time setup:[/bold cyan] Downloading MITRE ATT&CK Enterprise "
                "data from GitHub (~12 MB). This is cached after the first run."
            )
            with Progress(
                SpinnerColumn(),
                TextColumn("[cyan]Downloading enterprise-attack.json..."),
                transient=False,
                console=console,
            ) as progress:
                progress.add_task("download")
                resp = requests.get(_STIX_URL, timeout=60)
                resp.raise_for_status()
                bundle = resp.json()

            with open(_CACHE_FILE, "w", encoding="utf-8") as fh:
                json.dump(bundle, fh)
            console.print(f"[bold green]✓ ATT&CK data cached →[/bold green] {_CACHE_FILE}")

        objects = bundle.get("objects", [])
        _attack_client = _AttackDataStore(objects)
        return _attack_client

    except Exception as exc:
        console.print(f"  [bold red]ATT&CK client init failed:[/bold red] {exc}")
        return None


# ---------------------------------------------------------------------------
# 1. Technique lookup
# ---------------------------------------------------------------------------

def lookup_technique(technique_id: str) -> dict:
    """
    Look up a MITRE ATT&CK technique by ID (e.g. T1059 or T1059.001).
    """
    source = "MITRE ATT&CK"

    client = _get_client()
    if client is None:
        return _error_result(source, "Could not load MITRE ATT&CK data.")

    try:
        technique_id = technique_id.strip().upper()
        all_techniques = client.get_techniques(include_subtechniques=True)
        match = None

        for tech in all_techniques:
            for ref in tech.get("external_references", []):
                if ref.get("external_id", "").upper() == technique_id:
                    match = tech
                    break
            if match:
                break

        if match is None:
            return _not_found_result(source, f"Technique {technique_id} not found in ATT&CK.")

        name        = match.get("name", "")
        description = (match.get("description") or "")[:400]
        platforms   = ", ".join(match.get("x_mitre_platforms") or [])
        tactics     = []
        for phase in match.get("kill_chain_phases") or []:
            if phase.get("kill_chain_name") == "mitre-attack":
                tactics.append(phase.get("phase_name", "").replace("-", " ").title())

        detection        = (match.get("x_mitre_detection") or "")[:300]
        data_sources     = ", ".join(match.get("x_mitre_data_sources") or [])[:200]
        is_subtechnique  = match.get("x_mitre_is_subtechnique", False)
        defense_bypassed = ", ".join(match.get("x_mitre_defense_bypassed") or [])

        url = ""
        for ref in match.get("external_references") or []:
            if ref.get("source_name") == "mitre-attack":
                url = ref.get("url", "")
                break

        details: dict = {
            "Technique ID":     technique_id,
            "Name":             name,
            "Is Sub-technique": "yes" if is_subtechnique else "no",
            "Tactics":          ", ".join(tactics),
            "Platforms":        platforms,
            "Defense Bypassed": defense_bypassed or "N/A",
            "Data Sources":     data_sources or "N/A",
            "Detection":        detection + ("..." if len(match.get("x_mitre_detection") or "") > 300 else ""),
            "Description":      description + ("..." if len(match.get("description") or "") > 400 else ""),
            "ATT&CK URL":       url,
        }

        return {"source": source, "skipped": False, "error": False, "flagged": False, "details": details}

    except Exception as exc:
        return _error_result(source, str(exc))


# ---------------------------------------------------------------------------
# 2. Group lookup
# ---------------------------------------------------------------------------

def lookup_group(group_name_or_id: str) -> dict:
    """
    Look up a MITRE ATT&CK threat group by name or ID (e.g. G0007 or APT28).
    """
    source = "MITRE ATT&CK"

    client = _get_client()
    if client is None:
        return _error_result(source, "Could not load MITRE ATT&CK data.")

    try:
        query      = group_name_or_id.strip()
        all_groups = client.get_groups()
        match      = None

        for group in all_groups:
            if group.get("name", "").lower() == query.lower():
                match = group
                break
            for alias in group.get("aliases") or []:
                if alias.lower() == query.lower():
                    match = group
                    break
            for ref in group.get("external_references") or []:
                if ref.get("external_id", "").upper() == query.upper():
                    match = group
                    break
            if match:
                break

        if match is None:
            return _not_found_result(source, f"Group '{group_name_or_id}' not found in ATT&CK.")

        name        = match.get("name", "")
        description = (match.get("description") or "")[:400]
        aliases     = ", ".join(match.get("aliases") or [])

        group_id = ""
        url      = ""
        for ref in match.get("external_references") or []:
            if ref.get("source_name") == "mitre-attack":
                group_id = ref.get("external_id", "")
                url      = ref.get("url", "")
                break

        try:
            group_techniques = client.get_techniques_used_by_group(match)
            tech_names = []
            for tech in group_techniques[:10]:
                for ref in tech.get("external_references") or []:
                    if ref.get("source_name") == "mitre-attack":
                        tech_names.append(f"{ref.get('external_id', '')} {tech.get('name', '')}")
                        break
        except Exception:
            tech_names = []

        details: dict = {
            "Group ID":            group_id,
            "Name":                name,
            "Aliases":             aliases,
            "Description":         description + ("..." if len(match.get("description") or "") > 400 else ""),
            "Techniques (sample)": ", ".join(tech_names[:8]) or "N/A",
            "ATT&CK URL":          url,
        }

        return {"source": source, "skipped": False, "error": False, "flagged": False, "details": details}

    except Exception as exc:
        return _error_result(source, str(exc))


# ---------------------------------------------------------------------------
# 3. Software lookup
# ---------------------------------------------------------------------------

def lookup_software(software_name: str) -> dict:
    """
    Look up a MITRE ATT&CK software entry (malware/tool) by name or ID.
    """
    source = "MITRE ATT&CK"

    client = _get_client()
    if client is None:
        return _error_result(source, "Could not load MITRE ATT&CK data.")

    try:
        query  = software_name.strip()
        all_sw = client.get_software()
        match  = None

        for sw in all_sw:
            if sw.get("name", "").lower() == query.lower():
                match = sw
                break
            for ref in sw.get("external_references") or []:
                if ref.get("external_id", "").upper() == query.upper():
                    match = sw
                    break
            if match:
                break

        if match is None:
            # Partial name match fallback
            for sw in all_sw:
                if query.lower() in sw.get("name", "").lower():
                    match = sw
                    break

        if match is None:
            return _not_found_result(source, f"Software '{software_name}' not found in ATT&CK.")

        name        = match.get("name", "")
        sw_type     = match.get("type", "")
        description = (match.get("description") or "")[:400]
        labels      = ", ".join(match.get("labels") or [])
        platforms   = ", ".join(match.get("x_mitre_platforms") or [])
        aliases     = ", ".join(match.get("x_mitre_aliases") or [])

        sw_id = ""
        url   = ""
        for ref in match.get("external_references") or []:
            if ref.get("source_name") == "mitre-attack":
                sw_id = ref.get("external_id", "")
                url   = ref.get("url", "")
                break

        details: dict = {
            "Software ID": sw_id,
            "Name":        name,
            "Type":        sw_type,
            "Labels":      labels,
            "Aliases":     aliases or "N/A",
            "Platforms":   platforms or "N/A",
            "Description": description + ("..." if len(match.get("description") or "") > 400 else ""),
            "ATT&CK URL":  url,
        }

        return {
            "source":  source,
            "skipped": False,
            "error":   False,
            "flagged": sw_type == "malware",
            "details": details,
        }

    except Exception as exc:
        return _error_result(source, str(exc))


# ---------------------------------------------------------------------------
# 4. IOC to ATT&CK mapping
# ---------------------------------------------------------------------------

def map_ioc_to_attack(ioc: str, ioc_type: str = "auto") -> dict:
    """
    Attempt to map an IOC to relevant MITRE ATT&CK techniques.
    """
    source = "MITRE ATT&CK IOC Mapping"

    client = _get_client()
    if client is None:
        return _error_result(source, "Could not load MITRE ATT&CK data.")

    try:
        ioc   = ioc.strip()
        found: dict = {}

        if ioc_type in ("auto", "software"):
            try:
                sw_result = lookup_software(ioc)
                if not sw_result.get("skipped") and not sw_result.get("error") and sw_result.get("details", {}).get("Software ID"):
                    found["Software Match"] = (
                        sw_result["details"].get("Name", "")
                        + " (" + sw_result["details"].get("Software ID", "") + ")"
                    )
            except Exception:
                pass

        if ioc_type in ("auto", "group"):
            try:
                grp_result = lookup_group(ioc)
                if not grp_result.get("skipped") and not grp_result.get("error") and grp_result.get("details", {}).get("Group ID"):
                    found["Group Match"] = (
                        grp_result["details"].get("Name", "")
                        + " (" + grp_result["details"].get("Group ID", "") + ")"
                    )
            except Exception:
                pass

        if ioc_type in ("auto", "technique"):
            try:
                tech_result = lookup_technique(ioc)
                if not tech_result.get("skipped") and not tech_result.get("error") and tech_result.get("details", {}).get("Technique ID"):
                    found["Technique Match"] = (
                        tech_result["details"].get("Name", "")
                        + " (" + tech_result["details"].get("Technique ID", "") + ")"
                    )
            except Exception:
                pass

        if not found:
            return _not_found_result(source, f"No ATT&CK matches found for: {ioc}")

        details: dict = {"IOC": ioc, "IOC Type": ioc_type}
        details.update(found)

        return {"source": source, "skipped": False, "error": False, "flagged": False, "details": details}

    except Exception as exc:
        return _error_result(source, str(exc))


# ---------------------------------------------------------------------------
# MITRE Tactics reference
# ---------------------------------------------------------------------------

MITRE_TACTICS: list = [
    {"id": "TA0043", "name": "Reconnaissance",        "phase": "reconnaissance"},
    {"id": "TA0042", "name": "Resource Development",  "phase": "resource-development"},
    {"id": "TA0001", "name": "Initial Access",         "phase": "initial-access"},
    {"id": "TA0002", "name": "Execution",              "phase": "execution"},
    {"id": "TA0003", "name": "Persistence",            "phase": "persistence"},
    {"id": "TA0004", "name": "Privilege Escalation",   "phase": "privilege-escalation"},
    {"id": "TA0005", "name": "Defense Evasion",        "phase": "defense-evasion"},
    {"id": "TA0006", "name": "Credential Access",      "phase": "credential-access"},
    {"id": "TA0007", "name": "Discovery",              "phase": "discovery"},
    {"id": "TA0008", "name": "Lateral Movement",       "phase": "lateral-movement"},
    {"id": "TA0009", "name": "Collection",             "phase": "collection"},
    {"id": "TA0011", "name": "Command and Control",    "phase": "command-and-control"},
    {"id": "TA0010", "name": "Exfiltration",           "phase": "exfiltration"},
    {"id": "TA0040", "name": "Impact",                 "phase": "impact"},
]


# ---------------------------------------------------------------------------
# Menu
# ---------------------------------------------------------------------------

def handle_mitre_menu() -> None:
    """Interactive MITRE ATT&CK menu."""
    from rich import box
    from rich.prompt import Prompt
    from rich.table import Table

    while True:
        console.print("\n[bold cyan]MITRE ATT&CK Intelligence[/bold cyan]")
        console.print("  [white]1[/white]  Technique lookup (e.g. T1059)")
        console.print("  [white]2[/white]  Threat group lookup (e.g. APT28)")
        console.print("  [white]3[/white]  Software/malware lookup (e.g. Cobalt Strike)")
        console.print("  [white]4[/white]  IOC to ATT&CK mapping")
        console.print("  [white]5[/white]  Tactic explorer")
        console.print("  [white]0[/white]  Back\n")

        choice = Prompt.ask("[bold cyan]Select option[/bold cyan]", default="0").strip()

        if choice == "0":
            break

        elif choice == "1":
            tech_id = Prompt.ask("[bold cyan]Enter technique ID (e.g. T1059 or T1059.001)[/bold cyan]").strip()
            if not tech_id:
                console.print("[yellow]Invalid input.[/yellow]")
                continue
            with _spinner(f"Looking up {tech_id.upper()}..."):
                result = lookup_technique(tech_id)
            _display_result(result, f"Technique: {tech_id.upper()}")

        elif choice == "2":
            group = Prompt.ask("[bold cyan]Enter group name or ID (e.g. APT28 or G0007)[/bold cyan]").strip()
            if not group:
                console.print("[yellow]Invalid input.[/yellow]")
                continue
            with _spinner(f"Looking up group: {group}..."):
                result = lookup_group(group)
            _display_result(result, f"Group: {group}")

        elif choice == "3":
            sw = Prompt.ask("[bold cyan]Enter software/malware name or ID[/bold cyan]").strip()
            if not sw:
                console.print("[yellow]Invalid input.[/yellow]")
                continue
            with _spinner(f"Looking up software: {sw}..."):
                result = lookup_software(sw)
            _display_result(result, f"Software: {sw}")

        elif choice == "4":
            ioc = Prompt.ask("[bold cyan]Enter IOC or name to map[/bold cyan]").strip()
            if not ioc:
                console.print("[yellow]Invalid input.[/yellow]")
                continue
            with _spinner(f"Mapping {ioc} to ATT&CK..."):
                result = map_ioc_to_attack(ioc)
            _display_result(result, f"IOC Mapping: {ioc}")

        elif choice == "5":
            _tactic_explorer()

        else:
            console.print("[yellow]Invalid option.[/yellow]")


def _tactic_explorer() -> None:
    """Show 14 tactics, let user pick one, list techniques, user picks for details."""
    from rich import box
    from rich.prompt import Prompt
    from rich.table import Table

    table = Table(title="MITRE ATT&CK Tactics", box=box.ROUNDED, header_style="bold cyan")
    table.add_column("#",      min_width=4)
    table.add_column("ID",     min_width=8)
    table.add_column("Tactic", min_width=28)

    for i, tactic in enumerate(MITRE_TACTICS, 1):
        table.add_row(str(i), tactic["id"], tactic["name"])

    console.print(table)

    choice = Prompt.ask("[bold cyan]Select tactic number (or 0 to cancel)[/bold cyan]", default="0").strip()
    try:
        num = int(choice)
    except ValueError:
        return

    if num == 0 or not (1 <= num <= len(MITRE_TACTICS)):
        return

    selected_tactic = MITRE_TACTICS[num - 1]
    phase_name      = selected_tactic["phase"]
    tactic_name     = selected_tactic["name"]

    client = _get_client()
    if client is None:
        console.print("[bold red]Failed to load MITRE ATT&CK data.[/bold red]")
        return

    console.print(f"\n[cyan]Loading techniques for:[/cyan] {tactic_name}\n")

    try:
        all_techniques = client.get_techniques(include_subtechniques=False)
        tactic_techs   = []
        for tech in all_techniques:
            for phase in tech.get("kill_chain_phases") or []:
                if phase.get("kill_chain_name") == "mitre-attack" and phase.get("phase_name") == phase_name:
                    tactic_techs.append(tech)
                    break

        if not tactic_techs:
            console.print(f"[yellow]No techniques found for tactic: {tactic_name}[/yellow]")
            return

        tech_table = Table(
            title=f"Techniques: {tactic_name}",
            box=box.ROUNDED,
            header_style="bold cyan",
            show_lines=False,
        )
        tech_table.add_column("#",    min_width=4)
        tech_table.add_column("ID",   min_width=10)
        tech_table.add_column("Name", min_width=40)

        for i, tech in enumerate(tactic_techs[:30], 1):
            tech_id = ""
            for ref in tech.get("external_references") or []:
                if ref.get("source_name") == "mitre-attack":
                    tech_id = ref.get("external_id", "")
                    break
            tech_table.add_row(str(i), tech_id, tech.get("name", ""))

        console.print(tech_table)
        if len(tactic_techs) > 30:
            console.print(f"[dim](Showing 30 of {len(tactic_techs)} techniques)[/dim]")

        tech_choice = Prompt.ask(
            "[bold cyan]Enter technique number for details (or 0 to cancel)[/bold cyan]",
            default="0",
        ).strip()
        try:
            tech_num = int(tech_choice)
        except ValueError:
            return

        if tech_num == 0 or not (1 <= tech_num <= min(30, len(tactic_techs))):
            return

        selected_tech = tactic_techs[tech_num - 1]
        tech_id_str   = ""
        for ref in selected_tech.get("external_references") or []:
            if ref.get("source_name") == "mitre-attack":
                tech_id_str = ref.get("external_id", "")
                break

        with _spinner(f"Loading {tech_id_str}..."):
            result = lookup_technique(tech_id_str)
        _display_result(result, f"Technique: {tech_id_str}")

    except Exception as exc:
        console.print(f"[bold red]Tactic explorer error:[/bold red] {exc}")


def _display_result(result: dict, title: str) -> None:
    if result.get("skipped"):
        reason = result.get("details", {}).get("reason", "unavailable")
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
