import requests
import os
import base64


BASE_URL = "https://www.virustotal.com/api/v3"

    
def _headers():
    return {"x-apikey": os.getenv("VT_API_KEY")}


def check_ip(ip: str) -> dict:
    """Query VirusTotal for an IPv4 address."""
    try:
        r = requests.get(f"{BASE_URL}/ip_addresses/{ip}", headers=_headers(), timeout=10)
        r.raise_for_status()
        attrs = r.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        total = sum(stats.values())
        return {
            "source": "VirusTotal",
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "undetected": stats.get("undetected", 0),
            "total_engines": total,
            "country": attrs.get("country", "N/A"),
            "owner": attrs.get("as_owner", "N/A"),
            "reputation": attrs.get("reputation", 0),
            "error": None
        }
    except Exception as e:
        return {"source": "VirusTotal", "error": str(e)}


def check_domain(domain: str) -> dict:
    """Query VirusTotal for a domain."""
    try:
        r = requests.get(f"{BASE_URL}/domains/{domain}", headers=_headers(), timeout=10)
        r.raise_for_status()
        attrs = r.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        total = sum(stats.values())
        categories = attrs.get("categories", {})
        return {
            "source": "VirusTotal",
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "undetected": stats.get("undetected", 0),
            "total_engines": total,
            "categories": list(categories.values())[:3],  # top 3 category labels
            "reputation": attrs.get("reputation", 0),
            "creation_date": attrs.get("creation_date", "N/A"),
            "error": None
        }
    except Exception as e:
        return {"source": "VirusTotal", "error": str(e)}


def check_url(url: str) -> dict:
    """
    Query VirusTotal for a URL.
    VT v3 requires the URL to be base64url-encoded (no padding).
    """
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        r = requests.get(f"{BASE_URL}/urls/{url_id}", headers=_headers(), timeout=10)
        r.raise_for_status()
        attrs = r.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        total = sum(stats.values())
        return {
            "source": "VirusTotal",
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "undetected": stats.get("undetected", 0),
            "total_engines": total,
            "final_url": attrs.get("last_final_url", url),
            "title": attrs.get("title", "N/A"),
            "error": None
        }
    except Exception as e:
        return {"source": "VirusTotal", "error": str(e)}


def check_hash(file_hash: str) -> dict:
    """Query VirusTotal for a file hash (MD5, SHA1, or SHA256)."""
    try:
        r = requests.get(f"{BASE_URL}/files/{file_hash}", headers=_headers(), timeout=10)
        r.raise_for_status()
        attrs = r.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        total = sum(stats.values())
        return {
            "source": "VirusTotal",
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "undetected": stats.get("undetected", 0),
            "total_engines": total,
            "malware_name": attrs.get("meaningful_name", "N/A"),
            "file_type": attrs.get("type_description", "N/A"),
            "file_size": attrs.get("size", "N/A"),
            "sha256": attrs.get("sha256", "N/A"),
            "error": None
        }
    except Exception as e:
        return {"source": "VirusTotal", "error": str(e)}
