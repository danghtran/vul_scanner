"""Best-effort product/version hints from service banners (for validation / NVD keywords)."""
import re
from typing import Any, Dict, Optional


def parse_banner_version(banner: str) -> Optional[Dict[str, Any]]:
    if not banner or not banner.strip():
        return None
    b = banner.strip()

    m = re.search(r"OpenSSH[_\s]([\d.]+(?:p\d+)?)", b, re.I)
    if m:
        return {
            "product": "openssh",
            "version_token": m.group(1),
            "confidence": "banner_regex",
        }

    m = re.search(r"nginx/([\d.]+)", b, re.I)
    if m:
        return {"product": "nginx", "version_token": m.group(1), "confidence": "banner_regex"}

    m = re.search(r"Apache(?:/|\s+)([\d.]+)", b, re.I)
    if m:
        return {"product": "apache", "version_token": m.group(1), "confidence": "banner_regex"}

    m = re.search(r"Microsoft-IIS/([\d.]+)", b, re.I)
    if m:
        return {"product": "iis", "version_token": m.group(1), "confidence": "banner_regex"}

    m = re.search(r"MySQL(?:.*?)([\d.]+)", b, re.I)
    if m:
        return {"product": "mysql", "version_token": m.group(1), "confidence": "banner_regex"}

    return None
