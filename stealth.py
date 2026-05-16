"""
Low-and-slow scan settings to reduce burst traffic (not evasion-grade).
"""
import random
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class StealthConfig:
    enabled: bool = False
    port_workers: int = 1
    port_timeout: float = 2.5
    port_delay_min: float = 0.5
    port_delay_max: float = 2.0
    shuffle_ports: bool = True
    minimal_probes: bool = True
    phase_delay_min: float = 0.8
    phase_delay_max: float = 2.5
    nvd_delay_min: float = 0.6
    nvd_delay_max: float = 1.4
    max_nvd_queries: int = 22
    max_cves: int = 40
    dns_query_delay: float = 0.4
    http_delay: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "port_workers": self.port_workers,
            "port_timeout": self.port_timeout,
            "port_delay_min": self.port_delay_min,
            "port_delay_max": self.port_delay_max,
            "shuffle_ports": self.shuffle_ports,
            "minimal_probes": self.minimal_probes,
            "max_nvd_queries": self.max_nvd_queries,
        }


def from_scan_context(ctx: Optional[dict]) -> StealthConfig:
    ctx = ctx or {}
    if not ctx.get("stealth"):
        return StealthConfig(enabled=False)
    return StealthConfig(
        enabled=True,
        port_workers=int(ctx.get("stealth_workers") or 1),
        port_timeout=float(ctx.get("stealth_port_timeout") or 2.5),
        port_delay_min=float(ctx.get("stealth_port_delay_min") or 0.5),
        port_delay_max=float(ctx.get("stealth_port_delay_max") or 2.0),
        shuffle_ports=ctx.get("stealth_shuffle", True) is not False,
        minimal_probes=ctx.get("stealth_minimal_probes", True) is not False,
        max_nvd_queries=int(ctx.get("stealth_max_nvd") or 22),
        max_cves=int(ctx.get("stealth_max_cves") or 40),
    )


def jitter_sleep(min_s: float, max_s: float) -> None:
    if max_s <= 0:
        return
    lo = min(min_s, max_s)
    hi = max(min_s, max_s)
    if hi > 0:
        time.sleep(random.uniform(lo, hi))


def phase_pause(cfg: StealthConfig) -> None:
    if cfg.enabled:
        jitter_sleep(cfg.phase_delay_min, cfg.phase_delay_max)


def nvd_pause(cfg: StealthConfig) -> None:
    if cfg.enabled:
        jitter_sleep(cfg.nvd_delay_min, cfg.nvd_delay_max)
