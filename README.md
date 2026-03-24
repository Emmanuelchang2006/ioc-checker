# 🔍 IOC Checker — Threat Intelligence Triage Tool

![Python](https://img.shields.io/badge/Python-3.8+-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)
![Blue Team](https://img.shields.io/badge/Team-Blue-0078D4?style=flat-square)

A command-line threat intelligence triage tool that enriches **Indicators of Compromise (IOCs)** against multiple open-source intelligence (OSINT) sources. Built to replicate the IOC enrichment workflow performed by **SOC Tier 1 analysts** during alert triage.

## Background

During alert triage in a SOC environment, analysts routinely need to enrich IOCs — checking whether an IP, domain, URL, or file hash has been seen in malicious activity. This tool automates that process by querying three major threat intelligence platforms simultaneously and producing a structured verdict, replacing what would otherwise be manual lookups across multiple browser tabs.

## Features

- **Automatic IOC classification** — regex-based detection of IPv4, domain, URL, MD5, SHA1, SHA256
- **Multi-source enrichment** — queries VirusTotal, AbuseIPDB, and Shodan
- **Structured verdict engine** — aggregates signals into `CLEAN` / `SUSPICIOUS` / `MALICIOUS`
- **Colour-coded terminal output** — built with `rich` for readable, analyst-friendly display
- **JSON report generation** — saves structured reports per IOC for documentation and ticketing
- **Batch mode** — accepts a file of IOCs for bulk triage with a final summary table
- **TOR exit node detection** via AbuseIPDB
- **CVE exposure enumeration** via Shodan
- **Open port and service banner** retrieval

## Data Sources

| Source | IOC Types Supported | Key Data Points |
|--------|-------------------|-----------------|
| [VirusTotal](https://www.virustotal.com) | IP, Domain, URL, Hash | Detection ratio across 90+ AV engines, malware family |
| [AbuseIPDB](https://www.abuseipdb.com) | IP | Abuse confidence score (0–100%), report history, ISP, TOR flag |
| [Shodan](https://www.shodan.io) | IP | Open ports, service banners, CVEs, ASN, geolocation |

## Workflow

```
User Input (IP / Domain / Hash / URL)
        │
        ▼
  IOC Type Detection (regex classifier)
        │
        ├──► IP ──────► VirusTotal + AbuseIPDB + Shodan
        │
        ├──► Domain ──► VirusTotal
        │
        ├──► URL ─────► VirusTotal
        │
        └──► Hash ────► VirusTotal (MD5 / SHA1 / SHA256)
        │
        ▼
  Verdict Engine
  (aggregates scores → CLEAN / SUSPICIOUS / MALICIOUS)
        │
        ▼
  Terminal Output (rich tables) + JSON Report
```

## Installation

**1. Clone the repository**
```bash
git clone https://github.com/Emmanuelchang2006/ioc-checker.git
cd ioc-checker
```

**2. Create a virtual environment**
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux / macOS
python3 -m venv venv
source venv/bin/activate
```

**3. Install dependencies**
```bash
pip install -r requirements.txt
```

**4. Configure API keys**

Copy the template and fill in your keys:
```bash
cp .env.example .env
```

```
VT_API_KEY=your_virustotal_api_key
ABUSEIPDB_API_KEY=your_abuseipdb_api_key
SHODAN_API_KEY=your_shodan_api_key
```

All three APIs offer **free tier** access — no credit card required:

| API | Registration Link |
|-----|------------------|
| VirusTotal | https://www.virustotal.com/gui/join-us |
| AbuseIPDB | https://www.abuseipdb.com/register |
| Shodan | https://account.shodan.io/register |

## Usage

**Single IOC lookup**
```bash
# IPv4 address
python main.py 185.220.101.45

# Domain
python main.py malicious-domain.com

# URL
python main.py https://phishing-site.example.com/login

# File hash (MD5 / SHA1 / SHA256)
python main.py 44d88612fea8a8f36de82e1278abb02f
```

**Batch mode — one IOC per line**
```bash
python main.py --batch iocs.txt
```

**iocs.txt format:**
```
# Lines starting with # are ignored
185.220.101.45
malicious-domain.com
44d88612fea8a8f36de82e1278abb02f
```

**Skip saving report**
```bash
python main.py 8.8.8.8 --no-save
```

## Example Output

### Single IP Lookup

![Single IP lookup showing VirusTotal detections and AbuseIPDB results](https://github.com/user-attachments/assets/abb83bab-dc7f-4945-badb-8cd9b856ebb3)

### Full Verdict — MALICIOUS Result

![Full MALICIOUS verdict output across all three sources](https://github.com/user-attachments/assets/95141011-80d5-4940-9f6b-b1f6d88a99cf)

### AbuseIPDB and Shodan Results

![AbuseIPDB confidence score and Shodan open ports output](https://github.com/user-attachments/assets/27480dca-1974-45ec-852d-7232dcdc4793)

### Batch Mode Summary Table

![Batch summary table showing verdict breakdown across multiple IOCs](https://github.com/user-attachments/assets/eee787f7-557e-4a07-9c98-5a3a337453d8)

## Project Structure

```
ioc-checker/
│
├── ioc_checker/
│   ├── __init__.py
│   ├── classifier.py       # Regex-based IOC type detection
│   ├── virustotal.py       # VirusTotal v3 API wrapper
│   ├── abuseipdb.py        # AbuseIPDB v2 API wrapper
│   ├── shodan_lookup.py    # Shodan host lookup wrapper
│   └── verdict.py          # Score aggregation + rich terminal output
│
├── reports/                # JSON reports saved here (gitignored)
├── main.py                 # CLI entry point
├── .env.example            # API key template
├── requirements.txt
└── README.md
```

## Verdict Logic

| Condition | Verdict |
|-----------|---------|
| VT detections ≥ 10% of engines OR AbuseIPDB score ≥ 80% | `MALICIOUS` |
| Any VT hit OR AbuseIPDB score ≥ 30% OR CVEs present | `SUSPICIOUS` |
| All scores zero/low | `CLEAN` |

## Limitations

- VirusTotal free tier: 4 requests/min, 500/day
- AbuseIPDB free tier: 1,000 checks/day
- Shodan free tier: host lookups only, no search filters
- AbuseIPDB and Shodan support IP lookups only — domains, URLs and hashes use VirusTotal exclusively

## Roadmap

- [ ] Add GreyNoise API integration for noise vs targeted attack classification
- [ ] Add IPv6 support to the IOC classifier
- [ ] Add `--quiet` flag for verdict-only output in batch mode
- [ ] HTML report export
- [ ] MISP integration for enterprise threat sharing

## Disclaimer

This tool is intended for **educational purposes and authorised defensive security use only**. Always ensure you have permission before investigating infrastructure. Do not use against systems you do not own or have explicit authorisation to test.

## Author

**Emmanuel Chang**
Information Security Student
[GitHub](https://github.com/Emmanuelchang2006) | [LinkedIn](https://www.linkedin.com/in/emmanuel-chang)
