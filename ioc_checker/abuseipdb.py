import requests
import os


BASE_URL = "https://api.abuseipdb.com/api/v2"


def check_ip(ip: str) -> dict:
    """
    Query AbuseIPDB for an IPv4 address.
    Returns abuse confidence score, ISP, usage type, country, and total reports.
    Only applies to IPs — AbuseIPDB does not support domains or hashes.
    """
    try:
        headers = {
            "Key": os.getenv("ABUSEIPDB_API_KEY"),
            "Accept": "application/json"
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90,   # look back 90 days of reports
            "verbose": True
        }
        r = requests.get(f"{BASE_URL}/check", headers=headers, params=params, timeout=10)
        r.raise_for_status()
        data = r.json().get("data", {})
        return {
            "source": "AbuseIPDB",
            "abuse_confidence_score": data.get("abuseConfidenceScore", 0),   # 0-100%
            "total_reports": data.get("totalReports", 0),
            "country": data.get("countryCode", "N/A"),
            "isp": data.get("isp", "N/A"),
            "usage_type": data.get("usageType", "N/A"),   # e.g. "Data Center/Web Hosting", "TOR Proxy"
            "domain": data.get("domain", "N/A"),
            "is_tor": data.get("isTor", False),
            "is_whitelisted": data.get("isWhitelisted", False),
            "last_reported": data.get("lastReportedAt", "Never"),
            "error": None
        }
    except Exception as e:
        return {"source": "AbuseIPDB", "error": str(e)}
