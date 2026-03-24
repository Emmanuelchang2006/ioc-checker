from rich.console import Console
from rich.table import Table
from rich import box
from rich.text import Text

console = Console()


def _verdict_label(malicious: int, total: int, abuse_score: int = 0, cves: list = []) -> tuple:
    """
    Determine verdict based on aggregated signals:
    - VT detection ratio
    - AbuseIPDB confidence score
    - Presence of CVEs from Shodan

    Returns: (verdict_str, color_str)
    """
    vt_ratio = (malicious / total * 100) if total > 0 else 0

    if vt_ratio >= 10 or abuse_score >= 80:
        return "MALICIOUS", "bold red"
    elif vt_ratio > 0 or abuse_score >= 30 or len(cves) > 0:
        return "SUSPICIOUS", "bold yellow"
    else:
        return "CLEAN", "bold green"


def render_verdict(results: dict, ioc_type: str):
    """
    Aggregate all API results and render a formatted verdict table in the terminal.
    Called after all API lookups are complete.
    """
    total_malicious = 0
    total_engines = 0
    abuse_score = 0
    cves = []

    # --- VirusTotal block ---
    vt = results.get("virustotal", {})
    if vt and not vt.get("error"):
        total_malicious = vt.get("malicious", 0)
        total_engines = vt.get("total_engines", 0)

    # --- AbuseIPDB block ---
    abuse = results.get("abuseipdb", {})
    if abuse and not abuse.get("error"):
        abuse_score = abuse.get("abuse_confidence_score", 0)

    # --- Shodan block ---
    shodan_data = results.get("shodan", {})
    if shodan_data and not shodan_data.get("error"):
        cves = shodan_data.get("cves", [])

    verdict, color = _verdict_label(total_malicious, total_engines, abuse_score, cves)

    # ── Verdict banner ──────────────────────────────────────────────
    console.print()
    console.rule(f"[{color}]  VERDICT: {verdict}  ")
    console.print()

    # ── VirusTotal Table ────────────────────────────────────────────
    if vt:
        vt_table = Table(title="VirusTotal", box=box.SIMPLE_HEAVY, show_header=True)
        vt_table.add_column("Field", style="cyan", no_wrap=True)
        vt_table.add_column("Value", style="white")

        if vt.get("error"):
            vt_table.add_row("Error", f"[red]{vt['error']}[/red]")
        else:
            detection = f"{vt['malicious']}/{vt['total_engines']} engines flagged"
            flag_color = "red" if vt["malicious"] > 0 else "green"
            vt_table.add_row("Detections", f"[{flag_color}]{detection}[/{flag_color}]")
            vt_table.add_row("Suspicious", str(vt.get("suspicious", 0)))

            if ioc_type == "IP":
                vt_table.add_row("Country", vt.get("country", "N/A"))
                vt_table.add_row("Owner/ASN", vt.get("owner", "N/A"))
                vt_table.add_row("Reputation", str(vt.get("reputation", 0)))
            elif ioc_type == "DOMAIN":
                vt_table.add_row("Categories", ", ".join(vt.get("categories", [])) or "N/A")
                vt_table.add_row("Reputation", str(vt.get("reputation", 0)))
            elif ioc_type in ("MD5", "SHA1", "SHA256"):
                vt_table.add_row("Malware Name", vt.get("malware_name", "N/A"))
                vt_table.add_row("File Type", vt.get("file_type", "N/A"))
                vt_table.add_row("File Size", str(vt.get("file_size", "N/A")) + " bytes")
                vt_table.add_row("SHA256", vt.get("sha256", "N/A"))
            elif ioc_type == "URL":
                vt_table.add_row("Final URL", vt.get("final_url", "N/A"))
                vt_table.add_row("Page Title", vt.get("title", "N/A"))

        console.print(vt_table)

    # ── AbuseIPDB Table ─────────────────────────────────────────────
    if abuse:
        abuse_table = Table(title="AbuseIPDB", box=box.SIMPLE_HEAVY, show_header=True)
        abuse_table.add_column("Field", style="cyan", no_wrap=True)
        abuse_table.add_column("Value", style="white")

        if abuse.get("error"):
            abuse_table.add_row("Error", f"[red]{abuse['error']}[/red]")
        else:
            score = abuse.get("abuse_confidence_score", 0)
            score_color = "red" if score >= 80 else "yellow" if score >= 30 else "green"
            abuse_table.add_row("Abuse Confidence", f"[{score_color}]{score}%[/{score_color}]")
            abuse_table.add_row("Total Reports", str(abuse.get("total_reports", 0)))
            abuse_table.add_row("ISP", abuse.get("isp", "N/A"))
            abuse_table.add_row("Usage Type", abuse.get("usage_type", "N/A"))
            abuse_table.add_row("Country", abuse.get("country", "N/A"))
            abuse_table.add_row("Is TOR Exit Node", "[red]YES[/red]" if abuse.get("is_tor") else "No")
            abuse_table.add_row("Whitelisted", "[green]YES[/green]" if abuse.get("is_whitelisted") else "No")
            abuse_table.add_row("Last Reported", abuse.get("last_reported", "Never"))

        console.print(abuse_table)

    # ── Shodan Table ────────────────────────────────────────────────
    if shodan_data:
        sh_table = Table(title="Shodan", box=box.SIMPLE_HEAVY, show_header=True)
        sh_table.add_column("Field", style="cyan", no_wrap=True)
        sh_table.add_column("Value", style="white")

        if shodan_data.get("error"):
            sh_table.add_row("Error", f"[yellow]{shodan_data['error']}[/yellow]")
        else:
            ports = shodan_data.get("open_ports", [])
            sh_table.add_row("Org", shodan_data.get("org", "N/A"))
            sh_table.add_row("ISP", shodan_data.get("isp", "N/A"))
            sh_table.add_row("Country", shodan_data.get("country", "N/A"))
            sh_table.add_row("City", shodan_data.get("city", "N/A"))
            sh_table.add_row("OS", str(shodan_data.get("os", "N/A")))
            sh_table.add_row("Open Ports", ", ".join(map(str, ports)) if ports else "None")
            sh_table.add_row("Hostnames", ", ".join(shodan_data.get("hostnames", [])) or "None")
            sh_table.add_row("Tags", ", ".join(shodan_data.get("tags", [])) or "None")

            # CVE sub-section
            if cves:
                cve_lines = [f"[red]{c['cve']}[/red] (CVSS: {c['cvss']})" for c in cves[:5]]
                sh_table.add_row("CVEs Found", "\n".join(cve_lines))
            else:
                sh_table.add_row("CVEs Found", "[green]None[/green]")

        console.print(sh_table)

    console.print()
