```
  _____ _                    _    ____
 |_   _| |__  _ __ ___  __ _| |_ / ___|  ___ ___  _ __   ___
   | | | '_ \| '__/ _ \/ _` | __\___ \ / __/ _ \| '_ \ / _ \
   | | | | | | | |  __/ (_| | |_ ___) | (_| (_) | |_) |  __/
   |_| |_| |_|_|  \___|\__,_|\__|____/ \___\___/| .__/ \___|
                                                  |_|
         Terminal-based Threat Intelligence · v1.0 · by arunjitk
```

<div align="center">

![Python](https://img.shields.io/badge/Python-3.9%2B-blue?style=flat-square&logo=python)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Terminal](https://img.shields.io/badge/UI-Rich%20Terminal-cyan?style=flat-square)
![APIs](https://img.shields.io/badge/APIs-20%2B%20Integrated-orange?style=flat-square)

</div>

---

**ThreatScope** is a production-ready, terminal-based Python threat intelligence platform for security analysts. Investigate URLs, IP addresses, domains, file hashes, emails, CVEs, and SSL certificates across 20+ threat intelligence sources — all from a single animated interactive menu.

- **No crashes** on missing API keys — every source degrades gracefully to `SKIPPED`
- **Animated live spinners** on every network call with elapsed time display
- **Concurrent scanning** via ThreadPoolExecutor for multi-source reports
- **Export everywhere** — JSON, CSV, TXT output to `reports/`
- **Dependency Manager** built-in — scans, installs, and verifies all tools + API keys

---

## Table of Contents

- [Main Menu](#main-menu)
- [Module Reference](#module-reference)
- [API Keys](#api-keys)
- [System Dependencies](#system-dependencies)
- [Installation](#installation)
  - [Linux / Kali / macOS](#linux--kali--macos)
  - [Windows](#windows)
- [Configuration](#configuration)
- [Usage Examples](#usage-examples)
  - [Interactive Mode](#interactive-mode)
  - [Non-Interactive CLI Mode](#non-interactive-cli-mode)
- [Verdict Levels](#verdict-levels)
- [Project Structure](#project-structure)
- [Module Function Reference](#module-function-reference)
- [Full Dependency Reference](#full-dependency-reference)

---

## Main Menu

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                      THREATSCOPE — MAIN MENU                                ║
╠═══════╦══════════════════════════╦═════════════════════════════════════════╣
║  KEY  ║  MODULE                  ║  SOURCES / DESCRIPTION                  ║
╠═══════╬══════════════════════════╬═════════════════════════════════════════╣
║   1   ║  URL Reputation Check    ║  VirusTotal · PhishTank · GSB · APIVoid ║
║   2   ║  URL Scan & Analysis     ║  URLScan.io live browser scan           ║
║  ─── IP INTELLIGENCE ───                                                    ║
║   3   ║  IP Reputation           ║  AbuseIPDB · VirusTotal · GreyNoise     ║
║   4   ║  IP Geolocation & Info   ║  IPInfo · AlienVault OTX                ║
║   5   ║  Shodan Lookup           ║  Open ports · Services · CVEs           ║
║  ─── DNS & WHOIS ───                                                        ║
║   6   ║  DNS Lookup              ║  A · AAAA · MX · TXT · NS · CNAME · SOA║
║   7   ║  Reverse DNS             ║  PTR record resolution                  ║
║   8   ║  WHOIS Information       ║  Registrar · Dates · Nameservers        ║
║  ─── REPORTS ───                                                            ║
║   9   ║  Full IOC Report         ║  All checks concurrent + JSON export    ║
║  ─── ADVANCED TOOLS ───                                                     ║
║   N   ║  Nmap Scanner            ║  Port scan · Vuln scripts · OS detect   ║
║   W   ║  Web Fingerprint         ║  WhatWeb · Wappalyzer · WafW00f         ║
║   H   ║  Hash & File Intel       ║  MalwareBazaar · VT · Hybrid Analysis   ║
║   O   ║  OSINT Recon             ║  theHarvester · Wayback · Metadata      ║
║  ─── EXTENDED INTELLIGENCE ───                                              ║
║   E   ║  Email Intelligence      ║  HIBP · EmailRep · Holehe · DNS audit   ║
║   S   ║  Subdomain & ASN Recon   ║  crt.sh · HackerTarget · Sublist3r      ║
║   C   ║  CVE Intelligence        ║  NVD · CISA KEV · searchsploit · EPSS   ║
║   T   ║  SSL/TLS Analyzer        ║  Cert info · Qualys SSL Labs            ║
║   F   ║  Live Threat Feeds       ║  URLhaus · ThreatFox · Feodo · SSLBL    ║
║   M   ║  MITRE ATT&CK Mapper     ║  Technique · Group · Software · Tactic  ║
║  ─── UTILITIES ───                                                          ║
║   D   ║  Dependency Manager      ║  Scan · install · verify tools + keys   ║
║   0   ║  Exit                    ║                                         ║
╚═══════╩══════════════════════════╩═════════════════════════════════════════╝
```

---

## Module Reference

### `[1]` URL Reputation Check
Checks a URL across four independent reputation engines simultaneously.

| Source | What it checks |
|---|---|
| **VirusTotal** | 90+ AV/security engine verdicts |
| **PhishTank** | Known phishing URL database |
| **Google Safe Browsing** | Malware and phishing detection (v4 API) |
| **APIVoid** | Domain/URL blacklist reputation score |

---

### `[2]` URL Scan & Analysis
Submits a URL to URLScan.io for a live headless browser scan. Returns page screenshot metadata, contacted IPs, loaded domains, TLS info, and an overall verdict.

---

### `[3]` IP Reputation
Multi-source reputation check for any IPv4/IPv6 address.

| Source | What it checks |
|---|---|
| **AbuseIPDB** | Abuse report count, confidence score, categories |
| **VirusTotal** | Community votes and engine detections |
| **GreyNoise** | Internet noise / scanner classification |
| **Spamhaus DNSBL** | zen.spamhaus.org · SpamCop · Barracuda blacklist |

---

### `[4]` IP Geolocation & Info
| Source | Data returned |
|---|---|
| **IPInfo** | City, region, country, ISP, timezone, lat/lng |
| **AlienVault OTX** | Pulse count, malware families, threat score |

---

### `[5]` Shodan Lookup
Returns open ports, running services, service banners, operating system fingerprint, hostnames, and CVEs associated with the IP — sourced directly from Shodan's passive scan data.

---

### `[6–8]` DNS Lookup / Reverse DNS / WHOIS
- **DNS Lookup** — Queries all record types: `A`, `AAAA`, `MX`, `NS`, `TXT`, `CNAME`, `SOA`
- **Reverse DNS** — PTR record resolution for any IP
- **WHOIS** — Registrar, creation/expiry dates, nameservers, registrant country

---

### `[9]` Full IOC Report
Auto-detects the input type (URL / IP / domain) and fans out all relevant checks concurrently via `ThreadPoolExecutor`. Produces a consolidated verdict banner and offers JSON export to `reports/`.

**Verdict levels:** `CLEAN` → `LOW` → `MEDIUM` → `HIGH` → `CRITICAL`

---

### `[N]` Nmap Scanner
Full-featured port scanner with 70+ scan profiles and 100+ NSE vulnerability scripts.

**Scan types:**
- Generic · Service version · OS detection · SYN stealth · ACK · UDP · Aggressive
- Discovery ping · Scan from file · Custom port ranges

**NSE script categories** (100+ scripts across 12 categories):

| Category | Examples |
|---|---|
| SMB / Windows | smb-vuln-ms17-010 (EternalBlue), smb-vuln-ms08-067, smb2-security-mode |
| HTTP / Web | http-title, http-methods, http-auth, http-shellshock, http-slowloris |
| SSL / TLS | ssl-heartbleed, ssl-poodle, ssl-ccs-injection, ssl-enum-ciphers |
| FTP | ftp-anon, ftp-bounce, ftp-vsftpd-backdoor |
| SMTP / Mail | smtp-vuln-cve2010-4344, smtp-open-relay |
| Databases | ms-sql-info, mysql-info, redis-info, mongodb-info |
| RDP / VNC | rdp-vuln-ms12-020, vnc-info, vnc-brute |
| IPMI / ICS | ipmi-version, ipmi-cipher-zero |
| DNS | dns-zone-transfer, dns-recursion, dns-brute |
| CVE database | vulners (queries Vulners for CVEs by service/version) |

> Root/sudo required for SYN stealth, ACK, UDP, OS detection, and aggressive scans.

---

### `[W]` Web Fingerprint
Comprehensive technology stack and WAF identification.

| Tool | Purpose |
|---|---|
| **WhatWeb** | CMS, framework, server, analytics detection (aggression 1–4) |
| **Wappalyzer** | Passive technology profiling via `python-wappalyzer` |
| **WafW00f** | WAF/IDS detection with bypass evasion hints |
| **Full scan** | All three run concurrently, results merged into a unified technology report |

---

### `[H]` Hash & File Intel
Lookup or upload files/hashes across five threat intelligence sources.

| Source | Capabilities |
|---|---|
| **VirusTotal** | 90+ engine scan, file upload, family classification |
| **MalwareBazaar** | YARA hits, malware family, download count (no key needed) |
| **Hybrid Analysis** | Full sandbox detonation, MITRE ATT&CK mapping, network IOCs |
| **Malshare** | Malware sample repository lookup |
| **ThreatFox** | C2 association, malware family, confidence (no key needed) |

Accepts MD5, SHA1, and SHA256. Auto-detects hash type. Supports local file upload with pre-scan hash computation.

---

### `[O]` OSINT Recon
Full domain reconnaissance suite.

| Feature | Details |
|---|---|
| **theHarvester** | Email addresses + subdomains from Google, Bing, crt.sh, OTX, Baidu |
| **Tech Stack** | BuiltWith API + Wappalyzer — frameworks, CDNs, analytics, security headers |
| **Wayback Machine** | Domain history, snapshot listing, earliest/latest capture dates |
| **Exposed Files** | 80+ sensitive path checks (admin panels, `.env`, `.git`, backups, config files) |
| **Metadata Extraction** | GPS, author, device, software from remote or local files via exiftool / PyMuPDF |
| **Full Recon** | All sources run in one combined report |

---

### `[E]` Email Intelligence
| Source | What it checks |
|---|---|
| **HaveIBeenPwned** | Breach database lookups — breach names, dates, data classes |
| **EmailRep.io** | Reputation score, suspicious flags, deliverability signals |
| **Holehe** | Checks 100+ services to see if the email is registered |
| **DNS Security Audit** | MX, SPF, DKIM, DMARC, BIMI record validation for the sender domain |

---

### `[S]` Subdomain & ASN Recon
| Option | Source | Details |
|---|---|---|
| 1 | **crt.sh** | Certificate Transparency log enumeration |
| 2 | **HackerTarget** | Passive DNS hostsearch |
| 3 | **BGPView** | ASN or IP prefix → name, country, RIR, description |
| 4 | **RIPEstat** | IP/prefix → routing data, ASN holder, geolocation |
| 5 | **SecurityTrails** | Historical DNS + subdomain data (API key required) |
| 6 | **Sublist3r** | Multi-engine subdomain enumeration (Quick / Standard / Full+Brute) |
| 7 | **Full Report** | crt.sh + HackerTarget + SecurityTrails + Sublist3r combined, deduped, exportable |

All results offer **CSV / TXT / JSON export** to `reports/` after each scan. The full report runs all sources concurrently and merges unique subdomains across all.

> Brute-force mode (Sublist3r option 3) requires typing `YES` at a red confirmation prompt.

---

### `[C]` CVE Intelligence
| Source | Details |
|---|---|
| **NVD NIST** | CVSS v3/v2 scores, description, CWE, reference links |
| **CISA KEV** | Checks if CVE is in the Known Exploited Vulnerabilities catalog |
| **searchsploit** | Local ExploitDB search — returns matching module paths |
| **Vulners** | Full CVE details + EPSS exploit probability score |

---

### `[T]` SSL/TLS Analyzer
| Feature | Details |
|---|---|
| **Certificate grab** | Subject, issuer, SANs, validity window, fingerprint, signature algorithm |
| **Qualys SSL Labs** | Full A–F grade scan including cipher strength, protocol support, known vulnerabilities |

---

### `[F]` Live Threat Feeds
Real-time lookups against abuse.ch and allied blocklists. No API keys required for any source.

| Feed | Lookup target |
|---|---|
| **URLhaus** | URL, domain, or IP — malware distribution status |
| **ThreatFox** | IP, domain, or URL IOC — malware family, C2 confidence |
| **Feodo Tracker** | IP → C2 botnet blocklist (Emotet, Dridex, QakBot, etc.) |
| **SSL Blacklist (SSLBL)** | SSL certificate fingerprint or JA3 hash |
| **Feed Summary** | Live statistics from all abuse.ch feeds |

---

### `[M]` MITRE ATT&CK Mapper
Offline-capable ATT&CK explorer using the official STIX bundle (cached at `~/.threatscope/enterprise-attack.json`).

| Option | Details |
|---|---|
| **Technique lookup** | T-ID or subtechnique (e.g. `T1059.001`) → name, tactic, platforms, description |
| **Group lookup** | APT group by name or G-ID → aliases, techniques used, description |
| **Software lookup** | Malware/tool by name or S-ID → type, techniques, associated groups |
| **IOC → ATT&CK mapping** | Attempts to correlate an IOC to relevant techniques |
| **Tactic explorer** | Browse all 14 tactics and their techniques |

> Downloaded from GitHub on first use. No TAXII server required.

---

### `[D]` Dependency Manager
Built-in tool management system.

| Option | Function |
|---|---|
| **1** | Full dependency report — Python packages, system binaries, API key status |
| **2** | Auto-install all missing required dependencies |
| **3** | Install a single dependency (pick from table) |
| **4** | Show OS-appropriate install commands for all tools |
| **5** | API key registration URLs |
| **6** | Missing required dependencies only |
| **7** | Missing API keys only |
| **8** | Re-scan all dependencies |
| **9** | Combined API key status + dependency health view |

---

## API Keys

Copy `config.yaml.example` to `config.yaml` and fill in your keys. Missing keys are skipped — the tool runs normally with any subset.

```yaml
api_keys:

  # ── URL INTELLIGENCE ─────────────────────────────────────────────────────
  virustotal:           "YOUR_KEY"   # virustotal.com/gui/sign-in
  phishtank:            "YOUR_KEY"   # phishtank.com/register.php
  google_safe_browsing: "YOUR_KEY"   # developers.google.com/safe-browsing
  urlscan:              "YOUR_KEY"   # urlscan.io/user/signup
  apivoid:              "YOUR_KEY"   # apivoid.com/register/

  # ── IP INTELLIGENCE ──────────────────────────────────────────────────────
  shodan:               "YOUR_KEY"   # account.shodan.io/register
  greynoise:            "YOUR_KEY"   # greynoise.io/signup  (free community key works)
  alienvault_otx:       "YOUR_KEY"   # otx.alienvault.com
  ipinfo:               ""           # works without key (50k req/month free)
  abstractapi_ip:       "YOUR_KEY"   # app.abstractapi.com/users/signup
  abuseipdb:            "YOUR_KEY"   # abuseipdb.com/register

  # ── HASH & FILE INTELLIGENCE ─────────────────────────────────────────────
  hybrid_analysis:      "YOUR_KEY"   # hybrid-analysis.com/apikeys/info
  malshare:             "YOUR_KEY"   # malshare.com/register.php

  # ── OSINT / WEB FINGERPRINT ──────────────────────────────────────────────
  builtwith:            "YOUR_KEY"   # api.builtwith.com/signup  (free tier)

  # ── EMAIL INTELLIGENCE ───────────────────────────────────────────────────
  hibp:                 "YOUR_KEY"   # haveibeenpwned.com/API/Key  (~$3.50/month)
  emailrep:             "YOUR_KEY"   # emailrep.io/key

  # ── SUBDOMAIN & ASN RECON ────────────────────────────────────────────────
  securitytrails:       "YOUR_KEY"   # securitytrails.com/corp/api  (free tier)

  # ── CVE INTELLIGENCE ─────────────────────────────────────────────────────
  nvd:                  "YOUR_KEY"   # nvd.nist.gov/developers/request-an-api-key (free)
  vulners:              "YOUR_KEY"   # vulners.com/userinfo  (free tier)

  # ── GEO / PROXY INTELLIGENCE ─────────────────────────────────────────────
  iphub:                "YOUR_KEY"   # iphub.info/apiKey/newFree  (free tier)
```

**No-key sources** (always active, zero configuration):

| Source | Module |
|---|---|
| MalwareBazaar, ThreatFox | Hash & File Intel |
| Wayback Machine | OSINT Recon |
| crt.sh, HackerTarget, BGPView, RIPEstat | Subdomain Recon |
| CISA KEV | CVE Intelligence |
| URLhaus, Feodo Tracker, SSL Blacklist, ThreatFox IOC | Live Threat Feeds |
| Qualys SSL Labs | SSL/TLS Analyzer |
| MITRE ATT&CK (GitHub STIX bundle) | MITRE ATT&CK Mapper |

Alternatively, set keys via environment variables:

```bash
export VT_API_KEY="..."
export ABUSEIPDB_API_KEY="..."
export SHODAN_API_KEY="..."
export OTX_API_KEY="..."
# See config.py for the full env var mapping
```

---

## System Dependencies

These binaries are separate from Python packages and must be installed at the OS level. All are optional — ThreatScope degrades gracefully if missing.

| Binary | Used By | Install |
|---|---|---|
| `nmap` | Nmap Scanner | `sudo apt install nmap` · `brew install nmap` |
| `theHarvester` | OSINT Recon | `sudo apt install theharvester` · `pip install theHarvester` |
| `exiftool` | OSINT Recon | `sudo apt install libimage-exiftool-perl` · `brew install exiftool` |
| `searchsploit` | CVE Intelligence | `sudo apt install exploitdb` · `brew install exploitdb` |
| `holehe` | Email Intelligence | `pip install holehe` |
| `sublist3r` | Subdomain Recon | `sudo apt install sublist3r` · `pip install sublist3r` |
| `whatweb` | Web Fingerprint | `sudo apt install whatweb` · `brew install whatweb` |
| `wafw00f` | Web Fingerprint | `pip install wafw00f` · `sudo apt install wafw00f` |

> Use the **Dependency Manager** (`D` from the main menu) to check which tools are installed and auto-install missing Python packages.

---

## Installation

### Linux / Kali / macOS

```bash
# 1. Clone the repository
git clone <repository_url>
cd threatscope

# 2. Create and activate a virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. Configure API keys
cp config.yaml.example config.yaml
nano config.yaml        # fill in your keys — leave unused keys as ""

# 5. (Optional) Install system tools for full functionality
sudo apt install nmap theharvester libimage-exiftool-perl exploitdb sublist3r whatweb wafw00f
# macOS:
brew install nmap exiftool exploitdb whatweb
pip install holehe sublist3r wafw00f theHarvester

# 6. Run
python main.py
```

For Nmap scans requiring root (SYN stealth, OS detection, UDP, ACK, aggressive):

```bash
sudo python main.py
```

---

### Windows

#### Step 1 — Install Python

1. Download from **python.org/downloads/windows** (Python 3.9 or later)
2. **Check "Add Python to PATH"** before clicking Install Now
3. Verify: open Command Prompt and run `python --version`

#### Step 2 — Install Git

Download from **git-scm.com/download/win**, keep all defaults. Verify: `git --version`

#### Step 3 — Clone and install

Open Command Prompt (`Win+R` → `cmd`):

```cmd
git clone <repository_url>
cd threatscope
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

#### Step 4 — Configure API keys

```cmd
copy config.yaml.example config.yaml
notepad config.yaml
```

#### Step 5 — Run

```cmd
python main.py
```

#### Windows Troubleshooting

| Problem | Fix |
|---|---|
| `'python' is not recognized` | Re-run the Python installer and tick **"Add Python to PATH"** |
| `'pip' is not recognized` | Run `python -m pip install -r requirements.txt` instead |
| PowerShell script execution blocked | `Set-ExecutionPolicy RemoteSigned -Scope CurrentUser` |
| `ModuleNotFoundError: No module named 'yaml'` | Activate the venv first: `venv\Scripts\activate` |
| Box/colour characters display as `?` | Install **Windows Terminal** from the Microsoft Store |
| `SSL: CERTIFICATE_VERIFY_FAILED` | `pip install --upgrade certifi` |

---

## Configuration

ThreatScope loads API keys from **`config.yaml`** (project root). Falls back to environment variables if a key is absent from the file. Keys left blank or missing produce a `○ SKIPPED` notice and never cause a crash.

The **Dependency Manager** (`D` → option 9) shows a live combined view of:
- Which API keys are `● ACTIVE` (config.yaml or env var) vs `○ SKIPPED`
- Which Python packages are installed
- Which system binaries are found in PATH

---

## Usage Examples

### Interactive Mode

```
$ python main.py
```

```
[1]  Enter URL:   https://suspicious-site.ru/payload.exe
     → VirusTotal · PhishTank · Google Safe Browsing · APIVoid

[3]  Enter IP:    45.142.212.100
     → AbuseIPDB · VirusTotal · GreyNoise · Spamhaus DNSBL

[6]  Enter domain: example.com
     → A · MX · TXT · NS · CNAME · SOA records

[9]  Enter IOC:   8.8.4.4                   ← auto-detected as IP
     → All IP checks concurrently → verdict + JSON export

[9]  Enter IOC:   https://phishing.example.com/login
     → All URL checks + DNS/WHOIS concurrently

[H]  Enter hash:  44d88612fea8a8f36de82e1278abb02f
     → MalwareBazaar · VirusTotal · Hybrid Analysis · ThreatFox

[S]  Option 7:    Full subdomain report for target.com
     → crt.sh + HackerTarget + SecurityTrails + Sublist3r
     → Merged, deduplicated → export to CSV/TXT/JSON

[M]  Enter ID:    T1059.001
     → Technique: Command and Scripting Interpreter: PowerShell

[C]  Enter CVE:   CVE-2021-44228
     → NVD CVSS · CISA KEV status · searchsploit · Vulners EPSS
```

### Non-Interactive CLI Mode

ThreatScope supports command-line arguments for scripting and automation:

```bash
# URL reputation check
python main.py --url "https://example.com"

# IP reputation check
python main.py --ip "8.8.8.8"

# DNS lookup and WHOIS
python main.py --domain "example.com"

# File hash lookup
python main.py --hash "44d88612fea8a8f36de82e1278abb02f"

# CVE lookup
python main.py --cve "CVE-2021-44228"

# Full IOC report (all checks)
python main.py --report "example.com"

# Subdomain enumeration
python main.py --subdomains "example.com"

# Email intelligence
python main.py --email "test@example.com"

# SSL certificate analysis
python main.py --ssl "example.com"

# Quiet mode (suppress banner)
python main.py --domain "example.com" --quiet

# Export to file
python main.py --report "example.com" --output "reports/myreport.json"
```

For full CLI help:
```bash
python main.py --help
```

---

## Verdict Levels

| Verdict | Colour | Meaning |
|---|---|---|
| `CLEAN` | Green | No sources flagged — low risk |
| `LOW` | Cyan | < 25% of active sources flagged |
| `MEDIUM` | Yellow | 25–50% of active sources flagged |
| `HIGH` | Orange | 50–75% of active sources flagged |
| `CRITICAL` | Red | > 75% of active sources flagged — block immediately |
| `UNKNOWN` | Grey | No APIs returned usable data |

---

## Project Structure

```
threatscope/
├── main.py                    # Entry point — menu loop, IOC dispatching
├── config.py                  # API key loading (config.yaml + env var fallback)
├── config.yaml                # Your API keys  ← gitignored, copy from .example
├── config.yaml.example        # Safe template to commit
├── requirements.txt           # Python package dependencies
├── reports/                   # Auto-created — JSON/CSV/TXT exports  ← gitignored
│
└── modules/
    ├── __init__.py            # Graceful try/except imports for all optional modules
    ├── utils.py               # Shared console, validators, Rich output helpers
    │
    ├── url_intel.py           # VirusTotal · PhishTank · GSB · URLScan · APIVoid
    ├── ip_intel.py            # AbuseIPDB · VirusTotal · GreyNoise · IPInfo · OTX · Shodan
    ├── dns_tools.py           # DNS lookup · Reverse DNS · WHOIS · DNSBL checks
    │
    ├── nmap_scanner.py        # 70+ nmap scan profiles + 100+ NSE vuln scripts
    ├── nmap_menus.py          # Interactive Nmap menu
    │
    ├── hash_intel.py          # VirusTotal · MalwareBazaar · Hybrid Analysis · Malshare · ThreatFox
    ├── hash_menus.py          # Interactive hash/file menu
    │
    ├── web_fingerprint.py     # WhatWeb · Wappalyzer · WafW00f
    ├── web_fingerprint_menus.py
    │
    ├── osint_recon.py         # theHarvester · BuiltWith · Wayback · Exposed files · Metadata
    ├── osint_menus.py
    │
    ├── email_intel.py         # HIBP · EmailRep · Holehe · SPF/DKIM/DMARC
    │
    ├── subdomain_recon.py     # crt.sh · HackerTarget · BGPView · RIPEstat · SecurityTrails · Sublist3r
    ├── subdomain_menus.py     # Animated menu · export prompt · Sublist3r sub-menu
    │
    ├── cve_intel.py           # NVD · CISA KEV · searchsploit · Vulners · EPSS
    ├── ssl_analyzer.py        # Certificate grab · Qualys SSL Labs
    ├── threat_feeds.py        # URLhaus · ThreatFox · Feodo Tracker · SSL Blacklist
    │
    ├── mitre_attack.py        # ATT&CK STIX bundle (GitHub, cached) — no TAXII needed
    │
    ├── dependency_checker.py  # OS detection · binary/package/API key checks · install commands
    └── dependency_menus.py    # Interactive dependency manager menu
```

---

## Module Function Reference

This section documents the public function names in each module for programmatic use:

### URL Intelligence (`modules/url_intel.py`)

| Function | Description |
|---|---|
| `check_virustotal_url(url)` | Check URL against VirusTotal |
| `check_phishtank(url)` | Check URL against PhishTank |
| `check_google_safe_browsing(url)` | Check URL against Google Safe Browsing |
| `check_apivoid_url(url)` | Check URL against APIVoid |
| `scan_urlscan(url)` | Submit URL to URLScan.io |

### IP Intelligence (`modules/ip_intel.py`)

| Function | Description |
|---|---|
| `check_virustotal_ip(ip)` | Check IP against VirusTotal |
| `check_abuseipdb(ip)` | Check IP against AbuseIPDB |
| `check_greynoise_ip(ip)` | Check IP against GreyNoise |
| `get_ipinfo(ip)` | Get IP geolocation from IPInfo |
| `check_alienvault_ip(ip)` | Get IP info from AlienVault OTX |
| `lookup_shodan_ip(ip)` | Lookup IP in Shodan |

### DNS & WHOIS (`modules/dns_tools.py`)

| Function | Description |
|---|---|
| `dns_lookup(domain)` | Perform DNS lookup (A, AAAA, MX, NS, TXT, CNAME, SOA) |
| `reverse_dns_lookup(ip)` | Perform reverse DNS lookup |
| `get_whois(domain)` | Get WHOIS information |
| `spamhaus_dnsbl_check(ip)` | Check IP against Spamhaus DNSBL |

### Hash Intelligence (`modules/hash_intel.py`)

| Function | Description |
|---|---|
| `check_virustotal_hash(hash)` | Check hash against VirusTotal |
| `check_malwarebazaar(hash)` | Check hash against MalwareBazaar |
| `check_hybrid_analysis(hash)` | Check hash against Hybrid Analysis |
| `check_threatfox(hash)` | Check hash against ThreatFox |
| `check_malshare(hash)` | Check hash against Malshare |

### CVE Intelligence (`modules/cve_intel.py`)

| Function | Description |
|---|---|
| `lookup_nvd(cve_id)` | Lookup CVE in NVD NIST |
| `check_cisa_kev(cve_id)` | Check if CVE is in CISA KEV |
| `search_exploitdb(cve_id)` | Search ExploitDB for exploits |
| `search_vulners(cve_id)` | Search Vulners for CVE details |

### Threat Feeds (`modules/threat_feeds.py`)

| Function | Description |
|---|---|
| `check_urlhaus(ioc)` | Check URL/domain/IP against URLhaus |
| `check_threatfox_ioc(ioc)` | Check IOC against ThreatFox |
| `check_feodo_tracker(ip)` | Check IP against Feodo Tracker |
| `check_ssl_blacklist(fingerprint)` | Check SSL fingerprint against SSLBL |

### Subdomain Recon (`modules/subdomain_recon.py`)

| Function | Description |
|---|---|
| `enumerate_subdomains_crtsh(domain)` | Enumerate subdomains via crt.sh |
| `enumerate_subdomains_hackertarget(domain)` | Enumerate subdomains via HackerTarget |
| `asn_lookup_bgpview(ip_or_asn)` | Lookup ASN via BGPView |
| `securitytrails_lookup(domain)` | Lookup subdomains via SecurityTrails |

### SSL Analyzer (`modules/ssl_analyzer.py`)

| Function | Description |
|---|---|
| `grab_certificate(hostname)` | Grab and parse SSL certificate |
| `ssllabs_scan(hostname)` | Run Qualys SSL Labs scan |

### Email Intelligence (`modules/email_intel.py`)

| Function | Description |
|---|---|
| `check_hibp(email)` | Check email against Have I Been Pwned |
| `check_emailrep(email)` | Check email reputation via EmailRep |

### MITRE ATT&CK (`modules/mitre_attack.py`)

| Function | Description |
|---|---|
| `lookup_technique(technique_id)` | Lookup ATT&CK technique |
| `lookup_group(group_name)` | Lookup APT group |
| `lookup_software(software_name)` | Lookup malware/tool |
| `map_ioc_to_attack(ioc)` | Map IOC to ATT&CK techniques |

---

## Full Dependency Reference

### Python Packages (`requirements.txt`)

| Package | Purpose | Required |
|---|---|---|
| `requests` | All HTTP API calls | Core |
| `rich` | Terminal UI — tables, panels, spinners | Core |
| `dnspython` | DNS resolution and DNSBL checks | Core |
| `python-whois` | WHOIS data retrieval | Core |
| `PyYAML` | `config.yaml` parsing | Core |
| `python-nmap` | Nmap Python bindings | Nmap Scanner |
| `python-wappalyzer` | Wappalyzer technology detection | Web Fingerprint / OSINT |
| `PyMuPDF` | PDF metadata extraction | OSINT Recon |
| `cryptography` | SSL certificate parsing | SSL Analyzer |
| `sublist3r` | Multi-source subdomain enumeration | Subdomain Recon (optional) |
| `reportlab` | PDF report generation | Report Generator (optional) |
| `python-docx` | Word document generation | Report Generator (optional) |
| `Jinja2` | HTML report templating | Report Generator (optional) |

### System Binaries

| Binary | Package | Module | Notes |
|---|---|---|---|
| `nmap` | nmap | Nmap Scanner | Root required for stealth/OS/UDP scans |
| `theHarvester` | theharvester | OSINT Recon | `sudo apt install theharvester` or `pip install theHarvester` |
| `exiftool` | libimage-exiftool-perl | OSINT Recon | File metadata extraction |
| `searchsploit` | exploitdb | CVE Intelligence | Local ExploitDB database required |
| `holehe` | holehe (pip) | Email Intelligence | Account enumeration across 100+ services |
| `sublist3r` | sublist3r | Subdomain Recon | Binary mode preferred; falls back to `python -m sublist3r` |
| `whatweb` | whatweb | Web Fingerprint | Ruby-based; `sudo apt install whatweb` |
| `wafw00f` | wafw00f (pip) | Web Fingerprint | WAF detection |

---

*Built for security analysts, red teamers, and threat hunters who live in the terminal.*
