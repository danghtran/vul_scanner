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

    m = re.search(r"PostgreSQL\s+([\d.]+)", b, re.I)
    if m:
        return {"product": "postgresql", "version_token": m.group(1), "confidence": "banner_regex"}

    m = re.search(r"redis_version:([\d.]+)", b, re.I)
    if m:
        return {"product": "redis", "version_token": m.group(1), "confidence": "banner_regex"}

    m = re.search(r"Microsoft SQL Server\s+([\d.]+)", b, re.I)
    if m:
        return {"product": "mssql", "version_token": m.group(1), "confidence": "banner_regex"}

    m = re.search(r"vsftpd\s+([\d.]+)", b, re.I)
    if m:
        return {"product": "vsftpd", "version_token": m.group(1), "confidence": "banner_regex"}

    m = re.search(r"(?:Apache-Coyote|Tomcat)/([\d.]+)", b, re.I)
    if m:
        return {"product": "tomcat", "version_token": m.group(1), "confidence": "banner_regex"}

    m = re.search(r"Postfix", b, re.I)
    if m:
        vm = re.search(r"Postfix\s*\(([^)]+)\)", b, re.I)
        if vm:
            vm2 = re.search(r"([\d.]+)", vm.group(1))
            if vm2:
                return {
                    "product": "postfix",
                    "version_token": vm2.group(1),
                    "confidence": "banner_regex",
                }

    m = re.search(r"220[ -](\S+)\s+FTP", b, re.I)
    if m:
        return {"product": "ftp", "version_token": m.group(1), "confidence": "banner_regex"}

    return None
