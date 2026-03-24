import shodan
import os


def lookup_ip(ip: str) -> dict:
    try:
        api = shodan.Shodan(os.getenv("SHODAN_API_KEY"))
        host = api.host(ip)

        # Extract open ports and their associated service banners
        ports = []
        for item in host.get("data", []):
            port_info = {
                "port": item.get("port"),
                "transport": item.get("transport", "tcp"),
                "product": item.get("product", ""),
                "version": item.get("version", ""),
                "banner": item.get("data", "")[:100]  # truncate banner to 100 chars
            }
            ports.append(port_info)

        # CVEs across all services
        cves = []
        for item in host.get("data", []):
            vulns = item.get("vulns", {})
            for cve_id, cve_data in vulns.items():
                cves.append({
                    "cve": cve_id,
                    "cvss": cve_data.get("cvss", "N/A"),
                    "summary": cve_data.get("summary", "")[:100]
                })

        return {
            "source": "Shodan",
            "ip": host.get("ip_str", ip),
            "org": host.get("org", "N/A"),
            "isp": host.get("isp", "N/A"),
            "country": host.get("country_name", "N/A"),
            "city": host.get("city", "N/A"),
            "hostnames": host.get("hostnames", []),
            "domains": host.get("domains", []),
            "os": host.get("os", "N/A"),
            "open_ports": [item.get("port") for item in host.get("data", [])],
            "port_details": ports,
            "cves": cves,
            "tags": host.get("tags", []),   # e.g. ["cloud", "tor", "vpn"]
            "last_update": host.get("last_update", "N/A"),
            "error": None
        }
    except shodan.APIError as e:
        # Common: "No information available for that IP" on private/clean IPs
        return {"source": "Shodan", "error": str(e)}
    except Exception as e:
        return {"source": "Shodan", "error": str(e)}
