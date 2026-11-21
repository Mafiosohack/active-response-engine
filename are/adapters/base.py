"""The adapter interface: how alert sources plug into the core.

An adapter turns one source's alerts into Evidence records and its analyst
verdicts into TriageEvents. It is the only code that knows that source's schema.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from ..models import Evidence, TriageEvent


class AdapterError(RuntimeError):
    """The source cannot be read (missing database, unexpected schema, ...)."""


@dataclass
class PollResult:
    evidence: list[Evidence] = field(default_factory=list)
    triage: list[TriageEvent] = field(default_factory=list)


class StateStore(Protocol):
    """Small durable key/value store an adapter uses for its cursor and per-row counts."""

    def get_state(self, key: str) -> Any | None: ...

    def set_states(self, items: dict[str, Any]) -> None: ...

    def delete_states(self, prefix: str) -> None: ...


class MemoryState:
    """In-memory StateStore, for replay and tests."""

    def __init__(self) -> None:
        self._data: dict[str, Any] = {}

    def get_state(self, key: str) -> Any | None:
        return self._data.get(key)

    def set_states(self, items: dict[str, Any]) -> None:
        self._data.update(items)

    def delete_states(self, prefix: str) -> None:
        self._data = {k: v for k, v in self._data.items() if not k.startswith(prefix)}


@runtime_checkable
class Adapter(Protocol):
    name: str
    stats: dict[str, int]

    def poll(self) -> PollResult:
        """Return whatever is new since the last call."""
