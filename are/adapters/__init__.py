"""Alert-source adapters. The core never imports anything from this package
except through the wiring layer (are/app.py)."""
from __future__ import annotations

import time
from typing import Callable

from ..config import Config
from .base import Adapter, AdapterError, MemoryState, PollResult, StateStore

__all__ = ["Adapter", "AdapterError", "MemoryState", "PollResult", "StateStore", "build_adapters", "build_nids_adapter"]


def build_nids_adapter(cfg: Config, state: StateStore, clock: Callable[[], float] = time.time, db_path: str | None = None):
    """Build the NIDS adapter from its config section; db_path overrides the configured database."""
    from .nids import NidsAdapter, NidsAdapterConfig

    section = dict(cfg.adapters.get("nids") or {})
    if db_path is not None:
        section["db_path"] = db_path
    adapter_cfg = NidsAdapterConfig.model_validate(section)
    if db_path is None:
        adapter_cfg.db_path = str(cfg.resolve(adapter_cfg.db_path))
    return NidsAdapter(adapter_cfg, state, clock)


_BUILDERS = {"nids": build_nids_adapter}


def build_adapters(cfg: Config, state: StateStore, clock: Callable[[], float] = time.time) -> list[Adapter]:
    adapters: list[Adapter] = []
    for name, section in cfg.adapters.items():
        if not (section or {}).get("enabled", True):
            continue
        if name not in _BUILDERS:
            raise AdapterError(f"config names adapter '{name}', but no such adapter exists")
        adapters.append(_BUILDERS[name](cfg, state, clock))
    return adapters
