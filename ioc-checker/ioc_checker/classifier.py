import re


def classify_ioc(ioc: str) -> str:
    """
    Classifies an IOC string into its type using regex pattern matching.
    Supports: IPv4, MD5, SHA1, SHA256, URL, Domain
    """
    ioc = ioc.strip()

    # IPv4 address
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ioc):
        # Extra validation: each octet must be 0-255
        parts = ioc.split(".")
        if all(0 <= int(p) <= 255 for p in parts):
            return "IP"

    # File hashes
    if re.match(r"^[a-fA-F0-9]{32}$", ioc):
        return "MD5"
    if re.match(r"^[a-fA-F0-9]{40}$", ioc):
        return "SHA1"
    if re.match(r"^[a-fA-F0-9]{64}$", ioc):
        return "SHA256"

    # URL (must start with http:// or https://)
    if re.match(r"^https?://[^\s/$.?#].[^\s]*$", ioc, re.IGNORECASE):
        return "URL"

    # Domain (e.g. malicious-site.com, sub.domain.org)
    if re.match(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$", ioc):
        return "DOMAIN"

    return "UNKNOWN"
