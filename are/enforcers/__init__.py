"""Enforcement drivers. Config picks which one runs; dry_run is the default."""
from __future__ import annotations

import time
from typing import Callable

from ..config import Config
from .base import Enforcer, EnforcerError
from .dry_run import DryRunEnforcer

__all__ = ["Enforcer", "EnforcerError", "DryRunEnforcer", "build_enforcer"]


def build_enforcer(cfg: Config, clock: Callable[[], float] = time.time, force_dry_run: bool = False) -> Enforcer:
    hosts = cfg.network.management_hosts
    if cfg.engine.driver == "nftables" and not force_dry_run:
        from .nftables import NftablesEnforcer      # imported lazily: only needed on the router

        return NftablesEnforcer(cfg.nftables, hosts)
    return DryRunEnforcer(cfg.nftables, hosts, clock)
