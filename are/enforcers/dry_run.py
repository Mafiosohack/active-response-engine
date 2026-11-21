"""dry_run driver: logs the exact nftables operations and changes nothing.

It is the default driver and the one replay always uses. It keeps its own table
of entries with expiry, on whatever clock it is given, so list_active behaves
like the real driver under a simulated clock.
"""
from __future__ import annotations

import logging
import time
from collections import deque
from typing import Callable

from ..config import NftablesConfig
from ..models import Action, ActionKind, ActiveEntry
from . import nft_script

logger = logging.getLogger(__name__)

_MAX_REMEMBERED_OPERATIONS = 5000


class DryRunEnforcer:
    name = "dry_run"

    def __init__(self, cfg: NftablesConfig, management_hosts: list[str], clock: Callable[[], float] = time.time) -> None:
        self._clock = clock
        self._entries: dict[tuple[ActionKind, str], float] = {}     # (kind, ip) -> expires_at
        self.operations: deque[tuple[float, str]] = deque(maxlen=_MAX_REMEMBERED_OPERATIONS)
        self._record(nft_script.base_ruleset(management_hosts, cfg.throttle_rate_per_second, cfg.hook_priority))

    def _record(self, script: str) -> None:
        self.operations.append((self._clock(), script))
        for line in script.splitlines():
            logger.info("[dry-run] nft would run: %s", line)

    def apply(self, action: Action) -> str:
        # Same two steps as the real driver: clear any old entry, then add with a fresh timeout.
        script = nft_script.delete_element(action.ip, action.kind) + nft_script.add_element(action)
        self._record(script)
        self._entries[(action.kind, nft_script.ipv4(action.ip))] = self._clock() + int(action.ttl_seconds)
        return "dry run, nothing changed"

    def remove(self, ip: str, kind: ActionKind) -> None:
        self._record(nft_script.delete_element(ip, kind))
        self._entries.pop((ActionKind(kind), nft_script.ipv4(ip)), None)

    def list_active(self) -> list[ActiveEntry]:
        now = self._clock()
        self._entries = {k: exp for k, exp in self._entries.items() if exp > now}
        return [ActiveEntry(kind, ip, exp - now) for (kind, ip), exp in sorted(self._entries.items())]

    def health(self) -> bool:
        return True
