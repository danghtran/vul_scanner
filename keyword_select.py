"""
Select and order NVD search keywords: version-first, fewer generic port/header noise.
"""
from typing import Iterator, List, Set, Tuple

from nvd_noise import has_version_evidence, should_skip_nvd_keyword

_SOURCE_PRIORITY = (
    "version",
    "inventory",
    "banner_token",
    "port_hint",
    "tls",
    "header",
)


def _rank_key(entry: dict) -> Tuple[int, str]:
    src = entry.get("source") or "port_hint"
    pri = len(_SOURCE_PRIORITY) - _SOURCE_PRIORITY.index(src) if src in _SOURCE_PRIORITY else 0
    return (pri, entry.get("keyword") or "")


def rank_keyword_entries(entries: List[dict]) -> List[dict]:
    return sorted(entries, key=_rank_key, reverse=True)


def scan_has_product_keywords(observations: List[dict]) -> bool:
    return has_version_evidence(observations)


def should_query_nvd(
    entry: dict,
    *,
    has_versioned: bool,
    scan_target: str = "",
    cdn_opaque: bool = False,
) -> bool:
    kw = (entry.get("keyword") or "").strip()
    src = entry.get("source") or ""
    return not should_skip_nvd_keyword(
        kw,
        src,
        target_host=scan_target,
        has_version_evidence=has_versioned,
        cdn_opaque=cdn_opaque,
    )


def iter_nvd_keyword_queries(
    observations: List[dict],
    max_queries: int = 40,
    scan_target: str = "",
    cdn_opaque: bool = False,
) -> Iterator[Tuple[str, str, str]]:
    """
    Yield (observation_id, keyword, source) in priority order, deduped globally.
    """
    has_versioned = has_version_evidence(observations)
    seen: Set[str] = set()
    versioned_products: Set[str] = set()
    count = 0

    by_obs = []
    for obs in observations:
        ranked = rank_keyword_entries(obs.get("nvd_keywords") or [])
        by_obs.append((obs.get("id") or "", ranked))

    for src in _SOURCE_PRIORITY:
        for obs_id, entries in by_obs:
            for entry in entries:
                if entry.get("source") != src:
                    continue
                kw = (entry.get("keyword") or "").strip()
                key = kw.lower()
                if key in seen:
                    continue
                if " " in kw:
                    versioned_products.add(kw.split(None, 1)[0].lower())
                elif versioned_products and key in versioned_products and src in (
                    "version",
                    "inventory",
                ):
                    continue
                if not should_query_nvd(
                    entry,
                    has_versioned=has_versioned,
                    scan_target=scan_target,
                    cdn_opaque=cdn_opaque,
                ):
                    continue
                seen.add(key)
                yield obs_id, kw, src
                count += 1
                if count >= max_queries:
                    return
