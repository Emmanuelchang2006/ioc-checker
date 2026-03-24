#!/usr/bin/env python3
"""
IOC Checker — Threat Intelligence Triage Tool
----------------------------------------------
Enriches Indicators of Compromise (IOCs) against VirusTotal,
AbuseIPDB, and Shodan. Supports IPs, domains, URLs, and file hashes.

Usage:
    python main.py <IOC>
    python main.py 185.220.101.45
    python main.py malicious-domain.com
    python main.py https://phishing-site.example.com/login
    python main.py 44d88612fea8a8f36de82e1278abb02f   # MD5
    python main.py --batch iocs.txt                    # bulk mode
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel

from ioc_checker.classifier import classify_ioc
from ioc_checker import virustotal, abuseipdb, shodan_lookup
from ioc_checker.verdict import render_verdict

# Load API keys from .env file
load_dotenv()

console = Console()


def check_env():
    """Warn if any API keys are missing from the environment."""
    missing = []
    for key in ["VT_API_KEY", "ABUSEIPDB_API_KEY", "SHODAN_API_KEY"]:
        if not os.getenv(key):
            missing.append(key)
    if missing:
        console.print(f"[yellow]⚠  Missing API keys: {', '.join(missing)}[/yellow]")
        console.print("[yellow]   Copy .env.example to .env and fill in your keys.[/yellow]\n")


def run_single(ioc: str) -> dict:
    """
    Run IOC enrichment for a single indicator.
    Returns a dict of all raw results for JSON export.
    """
    ioc = ioc.strip()
    ioc_type = classify_ioc(ioc)

    if ioc_type == "UNKNOWN":
        console.print(f"[red]✗  Could not classify IOC: {ioc}[/red]")
        console.print("    Accepted formats: IPv4, domain, URL, MD5, SHA1, SHA256\n")
        return {}

    console.print(Panel(
        f"[bold white]{ioc}[/bold white]\n[dim]Type: {ioc_type}[/dim]",
        title="[bold cyan]🔍 IOC Checker[/bold cyan]",
        border_style="cyan"
    ))

    results = {}

    # Route to correct API modules based on IOC type
    if ioc_type == "IP":
        console.print("[dim]Querying VirusTotal...[/dim]")
        results["virustotal"] = virustotal.check_ip(ioc)

        console.print("[dim]Querying AbuseIPDB...[/dim]")
        results["abuseipdb"] = abuseipdb.check_ip(ioc)

        console.print("[dim]Querying Shodan...[/dim]")
        results["shodan"] = shodan_lookup.lookup_ip(ioc)

    elif ioc_type in ("MD5", "SHA1", "SHA256"):
        console.print("[dim]Querying VirusTotal...[/dim]")
        results["virustotal"] = virustotal.check_hash(ioc)

    elif ioc_type == "DOMAIN":
        console.print("[dim]Querying VirusTotal...[/dim]")
        results["virustotal"] = virustotal.check_domain(ioc)

    elif ioc_type == "URL":
        console.print("[dim]Querying VirusTotal...[/dim]")
        results["virustotal"] = virustotal.check_url(ioc)

    # Render verdict tables in terminal
    render_verdict(results, ioc_type)

    # Attach metadata for JSON report
    results["_meta"] = {
        "ioc": ioc,
        "type": ioc_type,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

    return results


def save_report(ioc: str, results: dict):
    """Save results as a JSON file in the reports/ directory."""
    Path("reports").mkdir(exist_ok=True)
    safe_name = ioc.replace("/", "_").replace(":", "_").replace(".", "_")
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"reports/{safe_name}_{timestamp}.json"
    with open(filename, "w") as f:
        json.dump(results, f, indent=2)
    console.print(f"[dim]📄 Report saved: {filename}[/dim]\n")


def run_batch(filepath: str):
    """Read a file of IOCs (one per line) and run each through the checker."""
    try:
        with open(filepath, "r") as f:
            iocs = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        console.print(f"[red]✗  File not found: {filepath}[/red]")
        sys.exit(1)

    console.print(f"[cyan]📋 Batch mode: {len(iocs)} IOCs loaded from {filepath}[/cyan]\n")
    for ioc in iocs:
        results = run_single(ioc)
        if results:
            save_report(ioc, results)


def main():
    parser = argparse.ArgumentParser(
        description="IOC Checker — Threat Intelligence Triage Tool",
        epilog="Examples:\n"
               "  python main.py 8.8.8.8\n"
               "  python main.py malicious.com\n"
               "  python main.py https://phishing.example.com\n"
               "  python main.py 44d88612fea8a8f36de82e1278abb02f\n"
               "  python main.py --batch iocs.txt",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("ioc", nargs="?", help="Single IOC to check (IP, domain, URL, or hash)")
    parser.add_argument("--batch", metavar="FILE", help="Path to file with one IOC per line")
    parser.add_argument("--no-save", action="store_true", help="Skip saving JSON report")

    args = parser.parse_args()

    check_env()

    if args.batch:
        run_batch(args.batch)
    elif args.ioc:
        results = run_single(args.ioc)
        if results and not args.no_save:
            save_report(args.ioc, results)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
