# 🔍 IOC Checker — Threat Intelligence Triage Tool

A command-line tool that enriches **Indicators of Compromise (IOCs)** against multiple open-source threat intelligence sources. Built for blue team analysts who need rapid, structured IOC context during triage.

---

## Features

- **Auto-classifies IOC type** via regex — IPv4, domain, URL, MD5, SHA1, SHA256
- **Multi-source enrichment** — VirusTotal, AbuseIPDB, Shodan in parallel
- **Colour-coded terminal verdict** — `CLEAN` / `SUSPICIOUS` / `MALICIOUS`
- **Structured JSON reports** saved per IOC for documentation/ticketing
- **Batch mode** — feed a list of IOCs from a file for bulk triage
- **TOR exit node detection**, CVE exposure, open port enumeration

---

## Data Sources

| Source | IOC Types Supported | Key Data Points |
|--------|-------------------|-----------------|
| [VirusTotal](https://www.virustotal.com) | IP, Domain, URL, Hash | Detection ratio across 90+ AV engines, malware family |
| [AbuseIPDB](https://www.abuseipdb.com) | IP | Abuse confidence score (0–100%), report history, ISP, TOR flag |
| [Shodan](https://www.shodan.io) | IP | Open ports, service banners, CVEs, ASN, geolocation |

---

## Installation

### 1. Clone the repository
```bash
git clone https://github.com/YOUR_USERNAME/ioc-checker.git
cd ioc-checker
```

### 2. Create a virtual environment (recommended)
```bash
python3 -m venv venv
source venv/bin/activate        # Linux/macOS
venv\Scripts\activate           # Windows
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure API keys
```bash
cp .env.example .env
nano .env    # fill in your keys
```

All APIs offer **free tier** access — no credit card required:
- VirusTotal: https://www.virustotal.com/gui/join-us
- AbuseIPDB: https://www.abuseipdb.com/register
- Shodan: https://account.shodan.io/register

---

## Usage

### Single IOC
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

### Batch mode (one IOC per line)
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

### Skip saving report
```bash
python main.py 8.8.8.8 --no-save
```

---

## Example Output

![IOC Checker Demo](https://github.com/user-attachments/assets/924d74c8-97bf-4088-aba6-25cba8671eab)

```

---

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

---

## Verdict Logic

| Condition | Verdict |
|-----------|---------|
| VT detections ≥ 10% of engines OR AbuseIPDB score ≥ 80% | `MALICIOUS` |
| Any VT hit OR AbuseIPDB score ≥ 30% OR CVEs present | `SUSPICIOUS` |
| All scores zero/low | `CLEAN` |

---

## Limitations

- VirusTotal free tier: 4 requests/min, 500/day
- AbuseIPDB free tier: 1,000 checks/day
- Shodan free tier: host lookups only (no search filters)
- AbuseIPDB and Shodan only support IP lookups — domains/URLs/hashes use VirusTotal only

---

## Disclaimer

This tool is intended for **educational purposes and authorised defensive security use only**. Always ensure you have permission before investigating infrastructure. Do not use against systems you do not own or have explicit authorisation to test.

---

## Author

**Emmanuel Chang**
Information Security Student
[GitHub](https://github.com/Emmanuelchang2006) | [LinkedIn](www.linkedin.com/in/emmanuel-chang)
