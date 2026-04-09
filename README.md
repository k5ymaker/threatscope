<p align="center">
  <img src="https://readme-typing-svg.herokuapp.com?font=Fira+Code&weight=700&size=50&color=00F0FF&center=true&vCenter=true&height=70&lines=ThreatScope" alt="ThreatScope">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.9%2B-3776AB?style=for-the-badge&logo=python" alt="Python">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=for-the-badge&logo=linux">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge">
  <img src="https://img.shields.io/badge/UI-Rich%20Terminal-cyan?style=for-the-badge&logo=terminal">
  <img src="https://img.shields.io/badge/APIs-20%2B%20Integrated-orange?style=for-the-badge">
</p>

---

<p align="center">
  <strong>ThreatScope</strong> is a production-ready, terminal-based threat intelligence platform for security analysts, red teamers, and threat hunters. Investigate URLs, IP addresses, domains, file hashes, emails, CVEs, and SSL certificates across 20+ threat intelligence sources — all from a single animated interactive menu.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/No%20crashes-graceful%20degradation-success?style=flat&color=brightgreen">
  <img src="https://img.shields.io/badge/Animated%20spinners-live%20progress-cyan?style=flat&color=00F0FF">
  <img src="https://img.shields.io/badge/Concurrent%20scanning-ThreadPoolExecutor-blue?style=flat&color=4361ee">
  <img src="https://img.shields.io/badge/Export-JSON%2FCSV%2FTXT-orange?style=flat&color=f77f00">
</p>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Architecture](#-architecture)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Usage](#-usage)
- [Module Reference](#-module-reference)
- [API Keys](#-api-keys)
- [System Dependencies](#-system-dependencies)
- [Project Structure](#-project-structure)
- [License](#-license)

---

## 🚀 Overview

ThreatScope is a **comprehensive threat intelligence platform** that runs entirely in your terminal. It provides unified access to dozens of security APIs and tools, enabling security professionals to quickly assess Indicators of Compromise (IOCs) across multiple threat intelligence sources simultaneously.

### Why ThreatScope?

| Feature | Description |
|---------|-------------|
| **Unified Interface** | Single menu for all threat intelligence operations |
| **20+ Integrated Sources** | VirusTotal, AbuseIPDB, Shodan, GreyNoise, NVD, and more |
| **Concurrent Scanning** | Multi-threaded queries for faster results |
| **Graceful Degradation** | No crashes on missing API keys — tools skip elegantly |
| **Rich Terminal UI** | Beautiful colored tables, spinners, and progress indicators |
| **Export Ready** | JSON, CSV, and TXT export to `reports/` directory |
| **Built-in Dependency Manager** | Auto-installs and verifies tools |

---

## ✨ Features

### Core Capabilities

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           THREATSCOPE MENU                                   │
├───────┬─────────────────────────────┬──────────────────────────────────────┤
│  KEY  │  MODULE                     │  SOURCES / DESCRIPTION               │
├───────┼─────────────────────────────┼──────────────────────────────────────┤
│   1   │  URL Reputation Check       │  VirusTotal · PhishTank · GSB        │
│   2   │  URL Scan & Analysis        │  URLScan.io live browser scan         │
├───────┼─────────────────────────────┼──────────────────────────────────────┤
│   3   │  IP Reputation              │  AbuseIPDB · VirusTotal · GreyNoise   │
│   4   │  IP Geolocation & Info      │  IPInfo · AlienVault OTX              │
│   5   │  Shodan Lookup              │  Open ports · Services · CVEs        │
├───────┼─────────────────────────────┼──────────────────────────────────────┤
│   6   │  DNS Lookup                 │  A · AAAA · MX · TXT · NS            │
│   7   │  Reverse DNS                 │  PTR record resolution               │
│   8   │  WHOIS Information          │  Registrar · Dates · Nameservers     │
├───────┼─────────────────────────────┼──────────────────────────────────────┤
│   9   │  Full IOC Report            │  All checks concurrently             │
├───────┼─────────────────────────────┼──────────────────────────────────────┤
│   N   │  Nmap Scanner               │  Port scan · Vuln scripts · OS       │
│   W   │  Web Fingerprint             │  WhatWeb · Wappalyzer · WafW00f      │
│   H   │  Hash & File Intel          │  MalwareBazaar · VT · Hybrid Analysis│
│   O   │  OSINT Recon                │  theHarvester · Wayback · Metadata   │
│   P   │  Web App Pentest             │  Headers · CORS · CSP · Nikto · Nuclei│
├───────┼─────────────────────────────┼──────────────────────────────────────┤
│   E   │  Email Intelligence         │  HIBP · EmailRep · Holehe           │
│   S   │  Subdomain & ASN Recon      │  crt.sh · HackerTarget · Sublist3r   │
│   C   │  CVE Intelligence           │  NVD · CISA KEV · searchsploit        │
│   T   │  SSL/TLS Analyzer           │  Cert info · Qualys SSL Labs          │
│   F   │  Live Threat Feeds          │  URLhaus · ThreatFox · Feodo          │
│   M   │  MITRE ATT&CK Mapper        │  Technique · Group · Software         │
├───────┼─────────────────────────────┼──────────────────────────────────────┤
│   D   │  Dependency Manager         │  Scan · install · verify all tools   │
│   0   │  Exit                       │                                      │
└───────┴─────────────────────────────┴──────────────────────────────────────┘
```

### Verdict Levels

| Verdict | Color | Meaning |
|---------|-------|---------|
| `CLEAN` | 🟢 Green | No sources flagged — low risk |
| `LOW` | 🔵 Cyan | < 25% of active sources flagged |
| `MEDIUM` | 🟡 Yellow | 25–50% of active sources flagged |
| `HIGH` | 🟠 Orange | 50–75% of active sources flagged |
| `CRITICAL` | 🔴 Red | > 75% of active sources flagged |
| `UNKNOWN` | ⚪ Grey | No APIs returned usable data |

---

## 🏗 Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              THREATSCOPE ARCHITECTURE                       │
└─────────────────────────────────────────────────────────────────────────────┘

                              ┌─────────────────────┐
                              │      main.py        │
                              │  (Entry Point)      │
                              │  - Menu System      │
                              │  - CLI Parser       │
                              │  - IOC Dispatcher   │
                              └──────────┬──────────┘
                                         │
                                         ▼
                         ┌───────────────────────────────┐
                         │         config.py              │
                         │   (API Key Management)         │
                         │   - config.yaml loading        │
                         │   - Environment variables       │
                         │   - CONFIG dict                 │
                         └───────────────────────────────┘
                                         │
                                         ▼
                         ┌───────────────────────────────┐
                         │         modules/               │
                         │   ┌─────────────────────┐     │
                         │   │     utils.py        │     │
                         │   │  - Validation       │     │
                         │   │  - Output formatting│     │
                         │   │  - Risk aggregation │     │
                         │   └─────────────────────┘     │
                         │   ┌─────────────────────┐     │
                         │   │    url_intel.py     │     │
                         │   │  - VirusTotal       │     │
                         │   │  - PhishTank        │     │
                         │   │  - Google Safe Brows│     │
                         │   │  - URLScan          │     │
                         │   │  - APIVoid          │     │
                         │   └─────────────────────┘     │
                         │   ┌─────────────────────┐     │
                         │   │    ip_intel.py     │     │
                         │   │  - AbuseIPDB       │     │
                         │   │  - GreyNoise       │     │
                         │   │  - Shodan          │     │
                         │   │  - IPInfo          │     │
                         │   │  - AlienVault OTX  │     │
                         │   └─────────────────────┘     │
                         │   ┌─────────────────────┐     │
                         │   │   dns_tools.py     │     │
                         │   │  - DNS Lookup      │     │
                         │   │  - Reverse DNS     │     │
                         │   │  - WHOIS           │     │
                         │   └─────────────────────┘     │
                         │              .                │
                         │              .                │
                         │              .                │
                         │   ┌─────────────────────┐     │
                         │   │dependency_checker.py│     │
                         │   │  - Tool scanning    │     │
                         │   │  - Auto-install     │     │
                         │   │  - Verification     │     │
                         │   └─────────────────────┘     │
                         └───────────────────────────────┘
                                         │
                                         ▼
                         ┌───────────────────────────────┐
                         │      External APIs            │
                         │  ┌─────────┐ ┌─────────┐       │
                         │  │VirusTotal│ │AbuseIPDB│       │
                         │  │Shodan   │ │GreyNoise│       │
                         │  │NVD NIST │ │URLhaus  │       │
                         │  │Hybrid   │ │CISA KEV │       │
                         │  └─────────┘ └─────────┘       │
                         └───────────────────────────────┘
```

### Design Principles

1. **Modular Architecture**: Each intelligence type has its own module for easy maintenance
2. **Graceful Degradation**: Missing API keys never crash the tool
3. **Concurrent Processing**: ThreadPoolExecutor for parallel API queries
4. **Rich Terminal UI**: Professional color-coded output with spinners and progress bars
5. **Export Flexibility**: Multiple output formats (JSON, CSV, TXT)

---

## 📦 Installation

### Linux / Kali / macOS

```bash
# 1. Clone the repository
git clone <repository_url>
cd threatscope

# 2. Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. Configure API keys
cp config.yaml.example config.yaml
nano config.yaml

# 5. (Optional) Install system tools
sudo apt install nmap theharvester libimage-exiftool-perl exploitdb sublist3r whatweb wafw00f

# 6. Run
python main.py
```

### Windows

```cmd
# 1. Install Python 3.9+ from python.org

# 2. Clone and setup
git clone <repository_url>
cd threatscope
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt

# 3. Configure and run
copy config.yaml.example config.yaml
python main.py
```

---

## ⚙️ Configuration

ThreatScope loads API keys from **`config.yaml`** in the project root. It also supports environment variables as a fallback.

### config.yaml.example

```yaml
api_keys:
  # URL Intelligence
  virustotal:           "YOUR_KEY"
  phishtank:            "YOUR_KEY"
  google_safe_browsing: "YOUR_KEY"
  urlscan:              "YOUR_KEY"
  apivoid:              "YOUR_KEY"

  # IP Intelligence
  shodan:               "YOUR_KEY"
  greynoise:            "YOUR_KEY"
  alienvault_otx:       "YOUR_KEY"
  ipinfo:               ""
  abuseipdb:            "YOUR_KEY"

  # Hash Intelligence
  hybrid_analysis:      "YOUR_KEY"
  malshare:             "YOUR_KEY"

  # OSINT
  builtwith:            "YOUR_KEY"

  # Email
  hibp:                 "YOUR_KEY"
  emailrep:             "YOUR_KEY"

  # Subdomain
  securitytrails:       "YOUR_KEY"

  # CVE
  nvd:                  "YOUR_KEY"
  vulners:              "YOUR_KEY"
```

### Environment Variables

```bash
export VT_API_KEY="..."
export ABUSEIPDB_API_KEY="..."
export SHODAN_API_KEY="..."
```

---

## 🎮 Usage

### Interactive Mode

```bash
python main.py
```

Select options from the menu by entering the corresponding key.

### CLI Mode

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

# Full IOC report
python main.py --report "example.com"

# Quiet mode (suppress banner)
python main.py --domain "example.com" --quiet

# Export to file
python main.py --report "example.com" --output "reports/myreport.json"
```

---

## 📖 Module Reference

### URL Intelligence (`modules/url_intel.py`)

| Source | Description |
|--------|-------------|
| VirusTotal | 90+ AV/security engine verdicts |
| PhishTank | Known phishing URL database |
| Google Safe Browsing | Malware and phishing detection |
| URLScan.io | Live browser scan with screenshots |
| APIVoid | Domain blacklist reputation score |

### IP Intelligence (`modules/ip_intel.py`)

| Source | Description |
|--------|-------------|
| AbuseIPDB | Abuse reports, confidence score |
| VirusTotal | Community votes and detections |
| GreyNoise | Internet noise classification |
| Shodan | Open ports, services, CVEs |
| IPInfo | Geolocation data |
| AlienVault OTX | Threat pulses and malware families |

### Hash Intelligence (`modules/hash_intel.py`)

| Source | Capabilities |
|--------|--------------|
| VirusTotal | 90+ engine scan, file families |
| MalwareBazaar | YARA hits, malware families |
| Hybrid Analysis | Sandbox detonation, ATT&CK mapping |
| ThreatFox | C2 associations |
| Malshare | Malware sample repository |

### CVE Intelligence (`modules/cve_intel.py`)

| Source | Details |
|--------|---------|
| NVD NIST | CVSS scores, descriptions, CWEs |
| CISA KEV | Known exploited vulnerabilities |
| searchsploit | ExploitDB local search |
| Vulners | CVE details with EPSS scores |

### Other Modules

- **DNS & WHOIS** — Full DNS record lookup and WHOIS information
- **Nmap Scanner** — 70+ scan profiles, 100+ NSE scripts
- **Web Fingerprint** — WhatWeb, Wappalyzer, WafW00f
- **OSINT Recon** — theHarvester, Wayback, exposed files
- **Email Intelligence** — HIBP, EmailRep, Holehe
- **Subdomain Recon** — crt.sh, HackerTarget, Sublist3r
- **SSL/TLS Analyzer** — Certificate analysis, Qualys grades
- **Live Threat Feeds** — URLhaus, ThreatFox, Feodo Tracker
- **MITRE ATT&CK** — Technique, group, software explorer

---

## 🔑 API Keys

### Required API Keys

| Service | Required | Free Tier |
|---------|----------|-----------|
| VirusTotal | Yes | 4 lookups/minute |
| AbuseIPDB | Yes | 1,000 lookups/day |
| Shodan | Yes | Limited |
| GreyNoise | No | Community key works |
| IPInfo | No | 50k req/month |
| HaveIBeenPwned | Yes | Paid |

### No-Key Sources (Always Active)

- MalwareBazaar, ThreatFox
- Wayback Machine
- crt.sh, HackerTarget, BGPView
- CISA KEV
- URLhaus, Feodo Tracker, SSL Blacklist
- Qualys SSL Labs
- MITRE ATT&CK

---

## 🛠 System Dependencies

| Binary | Purpose | Install Command |
|--------|---------|-----------------|
| `nmap` | Port scanning | `sudo apt install nmap` |
| `theHarvester` | Email harvesting | `pip install theHarvester` |
| `exiftool` | Metadata extraction | `sudo apt install libimage-exiftool-perl` |
| `searchsploit` | ExploitDB | `sudo apt install exploitdb` |
| `sublist3r` | Subdomain enum | `pip install sublist3r` |
| `whatweb` | Web fingerprinting | `sudo apt install whatweb` |
| `wafw00f` | WAF detection | `pip install wafw00f` |

---

## 📂 Project Structure

```
threatscope/
├── main.py                    # Entry point with menu system
├── config.py                  # API key configuration
├── config.yaml                # Your API keys (gitignored)
├── config.yaml.example        # Template for config.yaml
├── requirements.txt           # Python dependencies
│
├── modules/
│   ├── __init__.py            # Graceful imports
│   ├── utils.py               # Validation, formatting, risk aggregation
│   │
│   ├── url_intel.py           # URL reputation modules
│   ├── ip_intel.py            # IP intelligence modules
│   ├── dns_tools.py           # DNS & WHOIS tools
│   │
│   ├── nmap_scanner.py        # Nmap port scanner
│   ├── nmap_menus.py          # Nmap menu
│   │
│   ├── hash_intel.py          # Hash/malware intelligence
│   ├── hash_menus.py          # Hash menu
│   │
│   ├── web_fingerprint.py     # Technology fingerprinting
│   ├── web_fingerprint_menus.py
│   │
│   ├── osint_recon.py         # OSINT reconnaissance
│   ├── osint_menus.py         # OSINT menu
│   │
│   ├── email_intel.py         # Email intelligence
│   ├── subdomain_recon.py    # Subdomain enumeration
│   ├── subdomain_menus.py    # Subdomain menu
│   │
│   ├── cve_intel.py           # CVE intelligence
│   ├── ssl_analyzer.py        # SSL/TLS analysis
│   ├── threat_feeds.py        # Live threat feeds
│   ├── mitre_attack.py       # MITRE ATT&CK mapper
│   │
│   ├── dependency_checker.py # Dependency checker
│   └── dependency_menus.py   # Dependency manager menu
│
└── reports/                   # Auto-created — exports go here
```

---

## 📝 License

<p align="center">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge">
</p>

<p align="center">
  This project is licensed under the MIT License.
</p>

---

<p align="center">
  <strong>Built for security analysts, red teamers, and threat hunters who live in the terminal.</strong>
</p>

<p align="center">
  <img src="https://komarev.com/ghpvc/?username=threatscope&label=ThreatScope+Views&color=00F0FF&style=flat" alt="Profile views">
</p>
