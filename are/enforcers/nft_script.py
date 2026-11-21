"""Generates the nftables ruleset text. Pure functions, no side effects.

Both drivers use this module: nftables feeds the text to `nft -f`, dry_run only
logs it. Every value interpolated here is validated first (IPv4 via the
ipaddress module, integers, a fixed set name map), so nothing from an alert can
ever change the shape of a rule.
"""
from __future__ import annotations

import ipaddress
import re

from ..models import Action, ActionKind
from .base import EnforcerError

FAMILY = "inet"
TABLE = "are"
THROTTLE_METER = "throttle_meter_v4"
SETS: dict[ActionKind, str] = {
    ActionKind.THROTTLE: "throttle_v4",
    ActionKind.RESET: "reset_v4",
    ActionKind.BLOCK: "block_v4",
    ActionKind.QUARANTINE: "quarantine_v4",
    ActionKind.BLOCK_DST: "block_dst_v4",
}
KIND_BY_SET = {name: kind for kind, name in SETS.items()}

_DECISION_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_MAX_TTL_SECONDS = 7 * 24 * 3600
_METER_SIZE = 65535
_METER_IDLE_TIMEOUT = "1m"


def ipv4(value: str) -> str:
    """Canonical IPv4 text, or EnforcerError. Version 1 enforces IPv4 only."""
    try:
        return str(ipaddress.IPv4Address(str(value).strip()))
    except ValueError as exc:
        raise EnforcerError(f"not an IPv4 address: {value!r}") from exc


def set_name(kind: ActionKind) -> str:
    try:
        return SETS[ActionKind(kind)]
    except (KeyError, ValueError) as exc:
        raise EnforcerError(f"action kind {kind!r} is not enforceable") from exc


def base_ruleset(management_hosts: list[str], throttle_rate: int, hook_priority: int) -> str:
    """The table, sets and chains. Safe to load repeatedly.

    `add` is a no-op for objects that already exist, so reloading keeps the
    timed set elements (active blocks survive an engine restart). Only the two
    chains are flushed and rebuilt, inside one atomic `nft -f` transaction.
    """
    rate, prio = int(throttle_rate), int(hook_priority)
    if rate < 1:
        raise EnforcerError("throttle rate must be at least 1 packet/s")
    mgmt = sorted({ipv4(h) for h in management_hosts})
    t = f"{FAMILY} {TABLE}"

    lines = [f"add table {t}"]
    lines += [f"add set {t} {name} {{ type ipv4_addr; flags timeout; }}" for name in SETS.values()]
    # One rate-limit state per source address. A single global limit rule would
    # throttle every listed source together.
    lines.append(
        f"add set {t} {THROTTLE_METER} "
        f"{{ type ipv4_addr; size {_METER_SIZE}; flags dynamic,timeout; timeout {_METER_IDLE_TIMEOUT}; }}"
    )
    lines += [
        f"add chain {t} forward {{ type filter hook forward priority {prio}; policy accept; }}",
        f"add chain {t} input {{ type filter hook input priority {prio}; policy accept; }}",
        f"flush chain {t} forward",
        f"flush chain {t} input",
        # 1. block: drop everything from the source
        f"add rule {t} forward ip saddr @{SETS[ActionKind.BLOCK]} counter drop",
    ]
    # 2. quarantine: drop in both directions, except to and from the management host
    if mgmt:
        hosts = "{ " + ", ".join(mgmt) + " }"
        lines += [
            f"add rule {t} forward ip saddr @{SETS[ActionKind.QUARANTINE]} ip daddr != {hosts} counter drop",
            f"add rule {t} forward ip daddr @{SETS[ActionKind.QUARANTINE]} ip saddr != {hosts} counter drop",
        ]
    else:
        lines += [
            f"add rule {t} forward ip saddr @{SETS[ActionKind.QUARANTINE]} counter drop",
            f"add rule {t} forward ip daddr @{SETS[ActionKind.QUARANTINE]} counter drop",
        ]
    lines += [
        # 3. block_dst: nobody reaches the external destination
        f"add rule {t} forward ip daddr @{SETS[ActionKind.BLOCK_DST]} counter drop",
        # 4. reset: TCP gets a reset (both ends of its connections), everything else is dropped
        f"add rule {t} forward ip saddr @{SETS[ActionKind.RESET]} meta l4proto tcp counter reject with tcp reset",
        f"add rule {t} forward ip daddr @{SETS[ActionKind.RESET]} meta l4proto tcp counter reject with tcp reset",
        f"add rule {t} forward ip saddr @{SETS[ActionKind.RESET]} counter drop",
        # 5. throttle: per-source rate limit, excess dropped
        f"add rule {t} forward ip saddr @{SETS[ActionKind.THROTTLE]} "
        f"update @{THROTTLE_METER} {{ ip saddr limit rate over {rate}/second }} counter drop",
        # The router itself is protected from blocked sources.
        f"add rule {t} input ip saddr @{SETS[ActionKind.BLOCK]} counter drop",
    ]
    return "\n".join(lines) + "\n"


def add_element(action: Action) -> str:
    ttl = int(action.ttl_seconds)
    if not 1 <= ttl <= _MAX_TTL_SECONDS:
        raise EnforcerError(f"ttl out of range: {action.ttl_seconds!r}")
    if not _DECISION_ID.match(str(action.decision_id)):
        raise EnforcerError(f"invalid decision id: {action.decision_id!r}")
    return (
        f"add element {FAMILY} {TABLE} {set_name(action.kind)} "
        f'{{ {ipv4(action.ip)} timeout {ttl}s comment "decision-{action.decision_id}" }}\n'
    )


def delete_element(ip: str, kind: ActionKind) -> str:
    return f"delete element {FAMILY} {TABLE} {set_name(kind)} {{ {ipv4(ip)} }}\n"
