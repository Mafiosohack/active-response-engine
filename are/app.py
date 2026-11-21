"""Wiring: builds the pieces from config and runs the polling loop.

This is the only module that knows about both the core and the concrete
adapters and drivers.
"""
from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass

from .adapters import Adapter, AdapterError, build_adapters
from .config import Config
from .enforcers import Enforcer, build_enforcer
from .engine import Engine
from .enrichment import Enricher
from .policy import Policy
from .store import Store

logger = logging.getLogger(__name__)

_ADAPTER_ERROR_LOG_INTERVAL_SECONDS = 60.0
PRUNE_INTERVAL_SECONDS = 3600.0     # how often old rows are deleted from ips.db
_SECONDS_PER_DAY = 86400.0


@dataclass
class Runtime:
    cfg: Config
    store: Store
    enricher: Enricher
    enforcer: Enforcer
    engine: Engine
    adapters: list[Adapter]


def build_runtime(cfg: Config) -> Runtime:
    enricher = Enricher.from_config(cfg)             # fails here if pinned data is missing or wrong
    store = Store(str(cfg.resolve(cfg.engine.db_path)))
    enforcer = build_enforcer(cfg)
    engine = Engine(cfg, store, Policy(cfg, enricher), enricher, enforcer)
    adapters = build_adapters(cfg, store)
    if not enforcer.health():
        logger.error("driver %s reports it cannot enforce; decisions will record the failures", enforcer.name)
    if cfg.engine.driver != "dry_run":
        # Enforcing with an unfinished network section can cut off the router or the management host.
        for name, value in (("internal_networks", cfg.network.internal_networks),
                            ("management_hosts", cfg.network.management_hosts)):
            if not value:
                logger.warning("network.%s is empty in config while the %s driver is enforcing", name, enforcer.name)
    return Runtime(cfg, store, enricher, enforcer, engine, adapters)


class Service:
    """The live loop: poll adapters, feed the engine, expire, tick."""

    def __init__(self, runtime: Runtime) -> None:
        self.rt = runtime
        self._stop = threading.Event()
        self._last_tick = 0.0
        self._last_error_log: dict[str, float] = {}
        self._last_prune = float("-inf")

    def stop(self) -> None:
        self._stop.set()

    def _prune_if_due(self) -> None:
        """Delete rows past engine.retention_days, at startup and then once an hour."""
        days = self.rt.cfg.engine.retention_days
        if days is None:
            return
        now = self.rt.engine.clock()
        # The lower bound keeps pruning going if the system clock is ever set back.
        if 0 <= now - self._last_prune < PRUNE_INTERVAL_SECONDS:
            return
        self._last_prune = now
        removed = self.rt.store.prune(before=now - days * _SECONDS_PER_DAY, now=now)
        if any(removed.values()):
            logger.info("retention: deleted %s older than %g day(s)",
                        ", ".join(f"{n} {table} row(s)" for table, n in removed.items() if n), days)

    def step(self) -> None:
        engine = self.rt.engine
        for adapter in self.rt.adapters:
            try:
                result = adapter.poll()
            except AdapterError as exc:
                # The source being briefly unreadable must not stop enforcement or expiry.
                now = time.monotonic()
                if now - self._last_error_log.get(adapter.name, float("-inf")) >= _ADAPTER_ERROR_LOG_INTERVAL_SECONDS:
                    self._last_error_log[adapter.name] = now
                    logger.error("adapter %s: %s", adapter.name, exc)
                continue
            for ev in result.evidence:
                engine.ingest(ev)
            for event in result.triage:
                engine.triage(event)
        engine.expire_due()
        now = time.monotonic()
        if now - self._last_tick >= self.rt.cfg.engine.tick_seconds:
            self._last_tick = now
            engine.tick()
        self._prune_if_due()

    def run_forever(self) -> None:
        self.rt.engine.restore()
        logger.info("engine running: driver=%s, adapters=%s", self.rt.enforcer.name,
                    [a.name for a in self.rt.adapters] or "none")
        while not self._stop.is_set():
            try:
                self.step()
            except Exception:  # noqa: BLE001 - one bad cycle must not kill the loop; entries still expire on their own
                logger.exception("engine cycle failed")
            self._stop.wait(self.rt.cfg.engine.poll_interval_seconds)
        logger.info("engine stopped; active firewall entries will expire on their own")
