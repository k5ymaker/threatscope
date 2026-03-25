# ThreatScope v1.0

**ThreatScope** is a production-ready, terminal-based Python threat intelligence
application that lets analysts rapidly investigate Indicators of Compromise (IOCs)
— URLs, IP addresses, and domains — against multiple free/freemium threat intel
APIs from a single interactive menu.

```
  _____ _                    _    ____
 |_   _| |__  _ __ ___  __ _| |_ / ___|  ___ ___  _ __   ___
   | | | '_ \| '__/ _ \/ _` | __\___ \ / __/ _ \| '_ \ / _ \
   | | | | | | | |  __/ (_| | |_ ___) | (_| (_) | |_) |  __/
   |_| |_| |_|_|  \___|\__,_|\__|____/ \___\___/| .__/ \___|
                                                  |_|
  Terminal-based Threat Intelligence · Investigate URLs, IPs & Domains
```

> **Screenshot placeholder** — run `python main.py` to see the live terminal UI.

---

## Features

| Menu Option | What It Does |
|---|---|
| **[1] URL Reputation** | VirusTotal engine scan · PhishTank phishing check · Google Safe Browsing · APIVoid |
| **[2] URL Scan** | URLScan.io live browser scan — page metadata, contacted domains/IPs, verdict |
| **[3] IP Reputation** | AbuseIPDB abuse history · VirusTotal votes · GreyNoise · Spamhaus/SpamCop DNSBL |
| **[4] IP Geolocation** | IPInfo (city, org, timezone, lat/lng) · AlienVault OTX (pulse count, threat score) |
| **[5] Shodan Lookup** | Open ports, service banners, OS fingerprint, known CVEs |
| **[6] DNS Lookup** | A · AAAA · MX · NS · TXT · CNAME · SOA records via dnspython |
| **[7] Reverse DNS** | PTR record lookup for any IP address |
| **[8] WHOIS** | Registrar, creation/expiry dates, nameservers, registrant info |
| **[9] Full IOC Report** | All relevant checks run **concurrently** (ThreadPoolExecutor) → aggregated verdict + optional JSON export |
| **[N] Nmap Scanner** | Generic port scan · 9 common scan types (SYN/SYN-stealth/UDP/ACK/OS/version/aggressive/discovery/file) · 105 NSE vuln scripts across 12 categories (SMB/Windows, HTTP/Web, SSL/TLS, FTP, SMTP, Databases, RDP/VNC, IPMI, IRC, Misc, CVE-DB) |

Additional capabilities:
- **Auto-detects IOC type** (URL / IP / domain) for the Full IOC Report
- **Graceful API handling** — missing keys produce a `SKIPPED` notice, never a crash
- **Colour-coded risk output** — red = malicious, yellow = suspicious, green = clean
- **API key status table** on every startup showing ACTIVE vs SKIPPED sources
- **JSON export** of full reports to `reports/<timestamp>_<ioc>.json`

---

## Nmap Prerequisites

ThreatScope's Nmap module requires the **nmap binary** installed separately from `python-nmap`:

```bash
# Debian / Ubuntu / Kali (recommended)
sudo apt install nmap

# macOS
brew install nmap

# Windows — download installer from https://nmap.org/download.html
# Tick "Add Nmap to PATH" during installation
```

Scans requiring root/sudo (OS detection, SYN stealth, ACK, UDP, aggressive):

```bash
sudo python main.py
```

Non-privileged scans (generic, version, specific ports, vuln scripts):

```bash
python main.py
```

---

## Installation

---

### Windows — Detailed Setup Guide

#### Step 1 — Install Python

1. Open your browser and go to **https://www.python.org/downloads/windows/**
2. Click **"Download Python 3.11.x"** (or the latest 3.x release shown)
3. Run the downloaded `.exe` installer
4. **IMPORTANT:** On the first screen, tick **"Add Python to PATH"** before clicking Install Now

   ```
   ☑  Add Python 3.x to PATH    ← must be checked
   ```

5. Click **"Install Now"** and wait for it to finish
6. Verify the installation — open **Command Prompt** (`Win + R` → type `cmd` → Enter) and run:

   ```cmd
   python --version
   ```

   Expected output:
   ```
   Python 3.11.x
   ```

---

#### Step 2 — Install Git

1. Go to **https://git-scm.com/download/win**
2. Download and run the installer (keep all defaults)
3. Verify:

   ```cmd
   git --version
   ```

   Expected output:
   ```
   git version 2.x.x.windows.x
   ```

> If you don't want to use Git, you can also click **"Download ZIP"** on the GitHub repository page, extract it, and `cd` into the extracted folder instead.

---

#### Step 3 — Open a Terminal

Press `Win + R`, type `cmd`, press **Enter**.

Or use **Windows Terminal** (recommended — install from the Microsoft Store for better colour support):
- Press `Win`, search **"Windows Terminal"**, open it
- It defaults to PowerShell — either is fine for the steps below

---

#### Step 4 — Clone the Repository

```cmd
git clone <repository_url>
cd threatscope
```

Verify you are in the right folder:

```cmd
dir
```

You should see `main.py`, `config.py`, `requirements.txt`, and the `modules\` folder listed.

---

#### Step 5 — Create a Virtual Environment

A virtual environment keeps ThreatScope's dependencies isolated from your system Python.

```cmd
python -m venv venv
```

This creates a `venv\` folder in the project directory.

---

#### Step 6 — Activate the Virtual Environment

```cmd
venv\Scripts\activate
```

Your prompt will change to show `(venv)` at the start:

```
(venv) C:\Users\YourName\threatscope>
```

> **PowerShell users:** If you get a `cannot be loaded because running scripts is disabled` error, run this once:
> ```powershell
> Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
> ```
> Then activate again:
> ```powershell
> venv\Scripts\Activate.ps1
> ```

---

#### Step 7 — Install Dependencies

```cmd
pip install -r requirements.txt
```

This installs: `requests`, `rich`, `dnspython`, `python-whois`, `PyYAML`.

Expected output ends with:
```
Successfully installed ... rich-xx.x.x requests-x.x.x dnspython-x.x.x ...
```

Verify the key packages installed correctly:

```cmd
pip list
```

---

#### Step 8 — Configure API Keys

Copy the example config file:

```cmd
copy config.yaml.example config.yaml
```

Open it in Notepad:

```cmd
notepad config.yaml
```

Fill in your API keys between the quotes. Example:

```yaml
api_keys:
  virustotal:           "YOUR_VIRUSTOTAL_KEY_HERE"
  phishtank:            ""
  google_safe_browsing: "YOUR_GSB_KEY_HERE"
  urlscan:              "YOUR_URLSCAN_KEY_HERE"
  apivoid:              ""
  shodan:               "YOUR_SHODAN_KEY_HERE"
  greynoise:            ""
  alienvault_otx:       "YOUR_OTX_KEY_HERE"
  ipinfo:               ""
  abstractapi_ip:       ""
  abuseipdb:            "YOUR_ABUSEIPDB_KEY_HERE"
```

Save and close Notepad (`Ctrl+S`, then close).

> Keys left as `""` are simply skipped — ThreatScope will show them as `○ SKIPPED` on startup and still run all other checks normally.

---

#### Step 9 — Run ThreatScope

```cmd
python main.py
```

You should see the ASCII banner, the API key status table, and the main menu.

---

#### Returning to ThreatScope Later

Every time you open a new terminal window, you must re-activate the virtual environment before running:

```cmd
cd C:\Users\YourName\threatscope
venv\Scripts\activate
python main.py
```

---

#### Troubleshooting (Windows)

| Problem | Fix |
|---|---|
| `'python' is not recognized` | Re-run the Python installer and tick **"Add Python to PATH"** |
| `'pip' is not recognized` | Run `python -m pip install -r requirements.txt` instead |
| PowerShell script execution blocked | Run `Set-ExecutionPolicy RemoteSigned -Scope CurrentUser` |
| `ModuleNotFoundError: No module named 'yaml'` | Make sure the venv is activated (`venv\Scripts\activate`) then re-run `pip install -r requirements.txt` |
| Colour/box characters display as `?` or boxes | Install **Windows Terminal** from the Microsoft Store for full Unicode/colour support |
| `SSL: CERTIFICATE_VERIFY_FAILED` | Run `pip install --upgrade certifi` |

---

### macOS / Linux

```bash
# 1. Clone the repo
git clone <repository_url>
cd threatscope

# 2. Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure API keys
cp config.yaml.example config.yaml
nano config.yaml          # or: open config.yaml (macOS), gedit config.yaml (Linux)

# 5. Run
python main.py
```

---

## Configuration

ThreatScope loads API keys from **`config.yaml`** (in the project root).
If a key is missing from the file, it falls back to the corresponding
**environment variable**. Missing keys are skipped gracefully — the tool
still works with any subset of configured APIs.

Edit `config.yaml`:

```yaml
api_keys:
  virustotal:           "YOUR_KEY_HERE"
  phishtank:            "YOUR_KEY_HERE"          # optional — works without key (rate-limited)
  google_safe_browsing: "YOUR_KEY_HERE"
  urlscan:              "YOUR_KEY_HERE"
  apivoid:              "YOUR_KEY_HERE"
  shodan:               "YOUR_KEY_HERE"
  greynoise:            "YOUR_KEY_HERE"          # free community key is sufficient
  alienvault_otx:       "YOUR_KEY_HERE"
  ipinfo:               ""                       # works without key (50 k req/month free)
  abstractapi_ip:       ""
  abuseipdb:            "YOUR_KEY_HERE"
```

Alternatively, set environment variables:

```bash
export VT_API_KEY="..."
export ABUSEIPDB_API_KEY="..."
export GSB_API_KEY="..."
# etc.
```

### Free-tier API registration links

| Service | Free Tier Link |
|---|---|
| **VirusTotal** | https://www.virustotal.com/gui/sign-in |
| **PhishTank** | https://www.phishtank.com/register.php |
| **Google Safe Browsing** | https://developers.google.com/safe-browsing/v4/get-started |
| **URLScan.io** | https://urlscan.io/user/signup |
| **AbuseIPDB** | https://www.abuseipdb.com/register |
| **GreyNoise** | https://www.greynoise.io/signup |
| **AlienVault OTX** | https://otx.alienvault.com/ |
| **Shodan** | https://account.shodan.io/register |
| **IPInfo** | https://ipinfo.io/signup |
| **APIVoid** | https://www.apivoid.com/register/ |

---

## Usage Examples

```
$ python main.py

# Interactive menu — type the option number and press Enter

[1]  → Enter: https://suspicious-site.ru/payload.exe
      → Checks VirusTotal, PhishTank, Google Safe Browsing, APIVoid

[3]  → Enter: 45.142.212.100
      → Checks AbuseIPDB, VirusTotal, GreyNoise, Spamhaus DNSBL

[6]  → Enter: example.com
      → Returns A, MX, TXT, NS, CNAME, SOA records

[9]  → Enter: 8.8.4.4          (auto-detected as IP)
      → Runs all IP checks concurrently, prints verdict + offers JSON export

[9]  → Enter: https://phishing.example.com/login
      → Runs all URL checks + DNS/WHOIS on the domain concurrently
```

### Verdict levels

| Verdict | Meaning |
|---|---|
| **CLEAN** | No sources flagged — low risk |
| **LOW** | < 25 % of active sources flagged |
| **MEDIUM** | 25–50 % of active sources flagged |
| **HIGH** | 50–75 % of active sources flagged |
| **CRITICAL** | > 75 % of active sources flagged — block immediately |
| **UNKNOWN** | No APIs returned usable data |

---

## Project Structure

```
threatscope/
├── main.py              # Entry point, interactive menu loop
├── config.py            # Centralised API key management
├── config.yaml          # API keys (gitignored — copy from config.yaml.example)
├── config.yaml.example  # Safe template to commit
├── requirements.txt
├── reports/             # Auto-created; JSON exports stored here (gitignored)
├── modules/
│   ├── __init__.py
│   ├── url_intel.py     # URL reputation checks
│   ├── ip_intel.py      # IP reputation, geolocation, Shodan
│   ├── dns_tools.py     # DNS lookup, reverse DNS, WHOIS, DNSBL
│   └── utils.py         # Input validation, rich output, risk aggregation
└── README.md
```

---

## Dependencies

```
requests>=2.31.0      # HTTP client for all API calls
rich>=13.0.0          # Terminal formatting (tables, panels, progress bars)
dnspython>=2.4.0      # DNS resolution (lookup + reverse + DNSBL)
python-whois>=0.9.0   # WHOIS data retrieval
PyYAML>=6.0           # config.yaml parsing
```

`ipaddress` is part of the Python standard library — no installation needed.

---