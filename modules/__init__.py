# threatscope/modules/__init__.py
# Makes the modules directory a Python package.
# Uses try/except so ThreatScope starts even if optional modules are missing.

import importlib as _importlib

def _try_import(name: str):
    try:
        return _importlib.import_module(f"modules.{name}")
    except ImportError:
        return None

# Core modules (always required)
from modules import dns_tools        # noqa: F401
from modules import ip_intel         # noqa: F401
from modules import url_intel        # noqa: F401
from modules import utils            # noqa: F401

# Optional modules (graceful degradation if dependencies missing)
nmap_scanner            = _try_import("nmap_scanner")
nmap_menus              = _try_import("nmap_menus")
web_fingerprint         = _try_import("web_fingerprint")
web_fingerprint_menus   = _try_import("web_fingerprint_menus")
hash_intel              = _try_import("hash_intel")
hash_menus              = _try_import("hash_menus")
osint_recon             = _try_import("osint_recon")
osint_menus             = _try_import("osint_menus")
dependency_checker      = _try_import("dependency_checker")
dependency_menus        = _try_import("dependency_menus")
email_intel             = _try_import("email_intel")
subdomain_recon         = _try_import("subdomain_recon")
subdomain_menus         = _try_import("subdomain_menus")
cve_intel               = _try_import("cve_intel")
ssl_analyzer            = _try_import("ssl_analyzer")
threat_feeds            = _try_import("threat_feeds")
mitre_attack            = _try_import("mitre_attack")
