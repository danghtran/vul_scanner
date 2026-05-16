"""TCP port lists for recon profiles (curated common services)."""

# Original default set
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 443, 3306, 3389, 8080,
]

# Broader external footprint (~enterprise + dev services)
EXTENDED_PORTS = sorted(
    {
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
        465, 587, 993, 995, 1433, 1521, 2049, 2375, 3000, 3306, 3389,
        5432, 5900, 5985, 6379, 6443, 8000, 8080, 8443, 8888, 9200,
        11211, 27017,
    }
)

# Extended + additional admin/app ports
FULL_PORTS = sorted(
    set(EXTENDED_PORTS)
    | {
        69, 79, 88, 102, 389, 636, 873, 1080, 1434, 1883, 3128, 3260,
        4444, 5000, 5001, 5060, 5222, 5269, 5433, 5601, 5672, 5901,
        5986, 7001, 7002, 7474, 8008, 8161, 9000, 9042, 9090, 9201,
        10000, 27018, 28017,
    }
)

_PROFILES = {
    "common": COMMON_PORTS,
    "extended": EXTENDED_PORTS,
    "full": FULL_PORTS,
}

DEFAULT_PROFILE = "extended"

TLS_PROBE_PORTS = [443, 8443, 465, 993, 636]
HTTP_PROBE_PORTS = [443, 8443, 80, 8080, 8000, 8888]


def ports_for_profile(profile: str) -> list:
    key = (profile or DEFAULT_PROFILE).strip().lower()
    if key not in _PROFILES:
        return list(_PROFILES[DEFAULT_PROFILE])
    return list(_PROFILES[key])


def list_profiles() -> list:
    return list(_PROFILES.keys())
