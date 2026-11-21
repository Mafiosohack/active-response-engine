"""Core data types shared by every module.

Everything that enters the core is an Evidence record (or a TriageEvent).
Everything the core produces is a Decision, optionally carried out as an Action
by an enforcer driver. Adapters and drivers only ever exchange these types with
the core, which is what keeps the core portable.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Family(str, Enum):
    NET_SIGNATURE = "net_signature"
    NET_BEHAVIOR = "net_behavior"
    ANOMALY_ML = "anomaly_ml"
    HOST_SENSOR = "host_sensor"
    CLOUD_SENSOR = "cloud_sensor"
    CORRELATION = "correlation"
    # Reserved for a future honeypot adapter; no version 1 adapter emits it.
    HONEYPOT = "honeypot"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ActionKind(str, Enum):
    OBSERVE = "observe"        # rung 0: log only
    ALERT = "alert"            # log plus high-priority alert, nothing enforced
    THROTTLE = "throttle"
    RESET = "reset"
    BLOCK = "block"
    QUARANTINE = "quarantine"
    BLOCK_DST = "block_dst"


# Kinds that are handed to an enforcer driver. observe/alert never are.
ENFORCED_KINDS = frozenset(
    {ActionKind.THROTTLE, ActionKind.RESET, ActionKind.BLOCK, ActionKind.QUARANTINE, ActionKind.BLOCK_DST}
)
# Kinds that cut a source off completely. Evidence arriving while one of these
# is active is stored with while_blocked = true.
ISOLATING_KINDS = frozenset({ActionKind.BLOCK, ActionKind.QUARANTINE})


class Target(str, Enum):
    ALLOWLISTED = "allowlisted"
    ALERT_ONLY = "alert_only"
    BLOCK_SRC = "block_src"
    QUARANTINE_SRC = "quarantine_src"
    BLOCK_DST = "block_dst"


def normalize_ip(value: Any) -> str:
    """Parse an address with the ipaddress module and return its canonical text.

    Every IP that reaches scoring, policy or a driver has been through this, so
    nothing downstream ever handles an unparsed address string.
    """
    return str(ipaddress.ip_address(str(value).strip()))


@dataclass(frozen=True)
class Evidence:
    """One evidence record: the only shape in which alerts enter the core."""

    evidence_id: str
    source: str
    family: Family
    rule_id: str
    src_ip: str
    dst_ip: str | None
    severity: Severity
    first_seen: float
    last_seen: float
    count_delta: int
    handshake_confirmed: bool
    raw: dict[str, Any] = field(default_factory=dict)
    ml_probability: float | None = None
    ml_attack_type: str | None = None
    technique: str | None = None
    stages: tuple[str, ...] | None = None
    # The source's kill-chain stage for this one alert (correlation evidence uses `stages`).
    stage: str | None = None
    # Set by the core at ingestion, never by an adapter.
    received_at: float = 0.0
    while_blocked: bool = False

    def __post_init__(self) -> None:
        set_ = object.__setattr__
        if not self.evidence_id or not self.source or not self.rule_id:
            raise ValueError("evidence_id, source and rule_id are required")
        set_(self, "family", Family(self.family))
        set_(self, "severity", Severity(self.severity))
        set_(self, "src_ip", normalize_ip(self.src_ip))
        set_(self, "dst_ip", normalize_ip(self.dst_ip) if self.dst_ip else None)
        set_(self, "first_seen", float(self.first_seen))
        set_(self, "last_seen", float(self.last_seen))
        if int(self.count_delta) < 1:
            raise ValueError("count_delta must be >= 1")
        set_(self, "count_delta", int(self.count_delta))
        set_(self, "handshake_confirmed", bool(self.handshake_confirmed))
        if self.ml_probability is not None:
            if self.family is not Family.ANOMALY_ML:
                raise ValueError("ml_probability is only valid for anomaly_ml evidence")
            if not 0.0 <= float(self.ml_probability) <= 1.0:
                raise ValueError("ml_probability must be within [0, 1]")
            set_(self, "ml_probability", float(self.ml_probability))
        if self.stages is not None:
            if self.family is not Family.CORRELATION:
                raise ValueError("stages is only valid for correlation evidence")
            set_(self, "stages", tuple(str(s) for s in self.stages))
        if self.stage is not None:
            if self.family is Family.CORRELATION:
                raise ValueError("correlation evidence carries stages, not a single stage")
            set_(self, "stage", str(self.stage))


@dataclass(frozen=True)
class TriageEvent:
    """An analyst verdict from a source.

    evidence_id_prefix identifies every evidence record the verdict covers, so
    the core never needs to know how a source builds its evidence ids.
    """

    source: str
    evidence_id_prefix: str
    verdict: str          # "false_positive" or "other"
    status: str           # the source's own status text, for the log
    at: float


@dataclass(frozen=True)
class Action:
    """What the core asks a driver to do. Drivers never decide anything."""

    kind: ActionKind
    ip: str
    ttl_seconds: int
    decision_id: str


@dataclass(frozen=True)
class ActiveEntry:
    """One entry a driver currently enforces."""

    kind: ActionKind
    ip: str
    remaining_seconds: float


@dataclass
class Decision:
    """One row of the decision log."""

    ip: str
    target: str
    rung: int
    kind: str
    ttl: int
    created_at: float
    expires_at: float
    evidence_ids: list[str]
    score: float
    families: list[str]
    technique: str | None = None
    tactic: str | None = None
    d3fend: str | None = None
    explanation: str = ""
    driver: str = "none"
    driver_result: str = "pending"
    reversed_at: float | None = None
    reversed_reason: str | None = None
    parent_id: int | None = None
    # Everything the explanation generator needs beyond the columns above.
    detail: dict[str, Any] = field(default_factory=dict)
    decision_id: int | None = None

    @property
    def enforced_ok(self) -> bool:
        return self.driver_result.startswith("ok")
