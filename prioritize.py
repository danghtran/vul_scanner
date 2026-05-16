"""Threat- and context-aware priority scoring (transparent heuristics, not enterprise SLA)."""
from typing import Optional

_VALIDATION_WEIGHT = {"corroborated": 1.0, "potential": 0.88, "heuristic": 0.72}


def compute_priority_score(
    cvss: Optional[float],
    known_exploited: bool,
    validation_status: str,
    context: Optional[dict],
) -> float:
    ctx = context or {}
    score = 0.0
    if cvss is not None:
        score += float(cvss) * 12.0
    if known_exploited:
        score += 160.0
    if ctx.get("internet_facing"):
        score += 28.0
    if (ctx.get("environment") or "").lower() == "prod":
        score += 18.0
    mult = _VALIDATION_WEIGHT.get(validation_status, 0.85)
    return round(score * mult, 2)


def tier_from_score(score: float) -> str:
    if score >= 220:
        return "P1"
    if score >= 150:
        return "P2"
    if score >= 90:
        return "P3"
    if score > 0:
        return "P4"
    return "P5"


def build_rationale(
    cvss: Optional[float],
    known_exploited: bool,
    validation_status: str,
    context: Optional[dict],
) -> str:
    ctx = context or {}
    parts = []
    if known_exploited:
        parts.append("listed in CISA KEV")
    if cvss is not None:
        parts.append(f"CVSS base {cvss}")
    parts.append(f"match confidence: {validation_status}")
    if ctx.get("internet_facing"):
        parts.append("internet-facing context")
    if (ctx.get("environment") or "").lower() == "prod":
        parts.append("production context")
    return "; ".join(parts) if parts else "prioritized by default rules"
