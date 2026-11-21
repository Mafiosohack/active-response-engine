"""The enforcer interface: the only way the core touches a firewall.

A driver is idempotent and never makes a decision. Any failure is raised as
EnforcerError so the core can write it into the decision log.
"""
from __future__ import annotations

from typing import Protocol, runtime_checkable

from ..models import Action, ActionKind, ActiveEntry


class EnforcerError(RuntimeError):
    """A driver could not carry out what the core asked."""


@runtime_checkable
class Enforcer(Protocol):
    name: str

    def apply(self, action: Action) -> str:
        """Enforce one action for action.ttl_seconds. Returns a short detail string."""

    def remove(self, ip: str, kind: ActionKind) -> None:
        """Lift one action early. Removing something that is not there is not an error."""

    def list_active(self) -> list[ActiveEntry]:
        """Current entries with the time each has left."""

    def health(self) -> bool:
        """True when the driver can enforce."""
