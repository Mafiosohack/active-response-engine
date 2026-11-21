"""NIDS adapter: the only code that knows the NIDS alert schema.

Reads the NIDS SQLite database strictly read-only and turns alert rows into
Evidence records. Facts about the NIDS this code relies on (all checked against
its source, main.py and detection/*.py):

  * Alerts live in table `alerts`. Address columns are `src` and `dst`.
  * A repeat does not insert a row. It raises `count` and moves `created_at`
    forward on the existing row, so polling by id would miss repeats.
  * Repeat counts are written late (batched), stamped with the time the repeat
    was seen, which can be older than rows already polled. A strict
    `created_at > cursor` would miss those, so each poll re-reads a look-back
    window and the per-row count delta removes the duplicates.
  * "Clear Alerts" deletes every row and restarts ids at 1. A reused id is
    detected from the row's creation marker and starts a new id generation.
  * A suppressed alert is stored already marked false_positive. It is not
    turned into evidence.
  * `timestamp` is local time with no timezone: never used for time logic.
"""
from __future__ import annotations

import fnmatch
import ipaddress
import json
import logging
import sqlite3
import time
from collections import Counter
from pathlib import Path
from typing import Any, Callable, Literal

from pydantic import BaseModel, ConfigDict, Field

from ..models import Evidence, Family, Severity, TriageEvent
from .base import AdapterError, PollResult, StateStore

logger = logging.getLogger(__name__)

SOURCE = "nids"
TABLE = "alerts"
_REQUIRED_COLUMNS = ("id", "rule_id", "severity", "src", "dst", "details", "count", "created_at", "timestamp")
_TRIAGE_COLUMNS = ("triage_status", "triage_at")
_STAGE_KEYS = ("stages", "kill_chain")            # CORRELATED_INCIDENT / ACTIVE_INTRUSION
_MEMBER_RULES_KEY = "rule_ids"
_SOURCE_VERIFIED_KEY = "source_verified"          # set by the NIDS handshake verifier on exploit alerts
_ML_PROBABILITY_KEYS = ("max_attack_probability", "attack_probability")
_ML_ATTACK_TYPE_KEYS = ("attack_type", "predicted_label")
_ML_FALLBACK_OTHER = 0.5                          # severities with no configured fallback score nothing
_UNTRIAGED = "new"
FALSE_POSITIVE = "false_positive"


class FamilyRule(BaseModel):
    model_config = ConfigDict(extra="forbid")
    pattern: str
    family: Family
    handshake: bool = False


class NidsAdapterConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = True
    db_path: str
    # Must be at least the scoring window, so a late-written repeat is still picked up.
    lookback_seconds: float = Field(600.0, ge=0)
    # "now": only alerts raised after the engine first starts. "beginning": everything in the database.
    start_from: Literal["now", "beginning"] = "now"
    busy_timeout_seconds: float = Field(5.0, gt=0)
    false_positive_statuses: list[str] = Field(default_factory=lambda: [FALSE_POSITIVE])
    ml_severity_fallback: dict[str, float] = Field(default_factory=lambda: {"high": 0.85, "medium": 0.65})
    families: list[FamilyRule]
    techniques: dict[str, str] = Field(default_factory=dict)
    # rule_id -> the NIDS kill-chain stage (detection/rules.py), so the policy can
    # see a source advance even when no correlated incident announces it.
    stages: dict[str, str] = Field(default_factory=dict)


def _match(pattern: str, rule_id: str) -> bool:
    return pattern == rule_id or fnmatch.fnmatchcase(rule_id, pattern)


def _lookup(table: dict[str, str], rule_id: str) -> str | None:
    """Exact rule name first, then the first matching wildcard."""
    if rule_id in table:
        return table[rule_id]
    return next((value for pattern, value in table.items() if _match(pattern, rule_id)), None)


def _valid_ip(value: Any) -> str | None:
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


class NidsAdapter:
    name = SOURCE

    def __init__(self, cfg: NidsAdapterConfig, state: StateStore, clock: Callable[[], float] = time.time) -> None:
        self.cfg = cfg
        self._state = state
        self._clock = clock
        self._db_uri = Path(cfg.db_path).resolve().as_uri() + "?mode=ro"
        self._fp_statuses = {s.lower() for s in cfg.false_positive_statuses}
        self.stats: Counter = Counter()
        self._rows: dict[int, dict] = {}        # row id -> {"c": count, "fs": first_seen, "sig": [...], "t": status}
        self._dirty: dict[str, Any] = {}
        self._has_triage: bool | None = None
        self._warned_rules: set[str] = set()
        self._generation = int(state.get_state(f"{SOURCE}:generation") or 0)
        self._cursor = state.get_state(f"{SOURCE}:cursor")
        self._triage_cursor = state.get_state(f"{SOURCE}:triage_cursor") or 0.0

    # ----------------------------------------------------------------- lookups
    def family_of(self, rule_id: str) -> FamilyRule | None:
        """First matching entry of the family table. Exact names are listed before wildcards."""
        return next((r for r in self.cfg.families if _match(r.pattern, rule_id)), None)

    def technique_of(self, rule_id: str) -> str | None:
        return _lookup(self.cfg.techniques, rule_id)

    def stage_of(self, rule_id: str) -> str | None:
        return _lookup(self.cfg.stages, rule_id)

    # ----------------------------------------------------------------- database
    def _connect(self) -> sqlite3.Connection:
        """Open the NIDS database read-only. This adapter never writes to it."""
        if not Path(self.cfg.db_path).is_file():
            raise AdapterError(f"NIDS database not found: {self.cfg.db_path}")
        try:
            conn = sqlite3.connect(self._db_uri, uri=True, timeout=self.cfg.busy_timeout_seconds)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA query_only = ON")      # second lock on the door, on top of mode=ro
            return conn
        except sqlite3.Error as exc:
            raise AdapterError(f"cannot open NIDS database read-only: {exc}") from exc

    def _check_schema(self, conn: sqlite3.Connection) -> None:
        if self._has_triage is not None:
            return
        columns = {r["name"] for r in conn.execute(f"PRAGMA table_info({TABLE})")}
        missing = [c for c in _REQUIRED_COLUMNS if c not in columns]
        if missing:
            raise AdapterError(f"NIDS table '{TABLE}' is missing column(s) {missing}; found {sorted(columns)}")
        self._has_triage = all(c in columns for c in _TRIAGE_COLUMNS)
        if not self._has_triage:
            logger.warning("NIDS database has no triage columns; triage feedback is off until the NIDS is upgraded")

    def _select(self) -> str:
        triage = "triage_status, triage_at" if self._has_triage else "NULL AS triage_status, NULL AS triage_at"
        return (f"SELECT id, rule_id, severity, src, dst, details, COALESCE(count, 1) AS count, created_at, "
                f"timestamp, {triage} FROM {TABLE}")

    # ----------------------------------------------------------------- state
    def _row_key(self, row_id: int) -> str:
        return f"{SOURCE}:row:{self._generation}:{row_id}"

    def _row_state(self, row_id: int) -> dict | None:
        if row_id not in self._rows:
            stored = self._state.get_state(self._row_key(row_id))
            if stored is None:
                return None
            self._rows[row_id] = stored
        return self._rows[row_id]

    def _save_row(self, row_id: int, state: dict) -> None:
        self._rows[row_id] = state
        self._dirty[self._row_key(row_id)] = state

    def _flush(self) -> None:
        self._dirty[f"{SOURCE}:cursor"] = self._cursor
        self._dirty[f"{SOURCE}:triage_cursor"] = self._triage_cursor
        self._dirty[f"{SOURCE}:generation"] = self._generation
        self._state.set_states(self._dirty)
        self._dirty = {}

    def _new_generation(self) -> None:
        """Alert ids restarted (the NIDS alert table was cleared): forget every per-row count."""
        self._generation += 1
        self._rows.clear()
        self._dirty = {k: v for k, v in self._dirty.items() if f"{SOURCE}:row:" not in k}
        self._state.delete_states(f"{SOURCE}:row:")
        self.stats["id_resets_detected"] += 1
        logger.warning("NIDS alert ids restarted; starting id generation %d", self._generation)

    def _alert_ref(self, row_id: int) -> str:
        return str(row_id) if self._generation == 0 else f"g{self._generation}-{row_id}"

    @staticmethod
    def _signature(row: sqlite3.Row) -> list:
        return [row["rule_id"], row["src"], row["dst"], row["timestamp"]]

    # ----------------------------------------------------------------- conversion
    def _to_evidence(self, row: sqlite3.Row, delta: int, first_seen: float, last_seen: float) -> Evidence | None:
        """Convert one alert row. Returns None (and counts why) when the row is not usable."""
        rule_id = row["rule_id"]
        if rule_id is None:
            self.stats["skipped_null_rule"] += 1
            return None
        rule = self.family_of(rule_id)
        if rule is None:
            self.stats["skipped_unmapped_rule"] += 1
            if rule_id not in self._warned_rules:
                self._warned_rules.add(rule_id)
                logger.warning("NIDS rule %r matches no entry in adapters.nids.families; its alerts are skipped", rule_id)
            return None
        src_ip = _valid_ip(row["src"])
        if src_ip is None:
            self.stats["skipped_no_source_ip"] += 1
            return None

        try:
            details = json.loads(row["details"] or "{}")
        except (ValueError, TypeError):
            details = {}
        if not isinstance(details, dict):
            details = {}

        severity = str(row["severity"] or "").lower()
        if severity not in {s.value for s in Severity}:
            self.stats["unknown_severity"] += 1
            severity = Severity.INFO.value

        family = rule.family
        handshake = rule.handshake
        probability = attack_type = stages = None
        if family is Family.ANOMALY_ML:
            probability = self._ml_probability(details, severity)
            attack_type = next((str(details[k]) for k in _ML_ATTACK_TYPE_KEYS if details.get(k)), None)
        elif family is Family.CORRELATION:
            stages = self._stages(details)
            handshake = self._members_handshake(details)      # inherits from its member alerts
        elif isinstance(details.get(_SOURCE_VERIFIED_KEY), bool):
            # The NIDS checked this very connection: trust that over the per-rule default.
            handshake = details[_SOURCE_VERIFIED_KEY]

        return Evidence(
            evidence_id=f"{SOURCE}:{self._alert_ref(row['id'])}:{row['count']}",
            source=SOURCE,
            family=family,
            rule_id=rule_id,
            src_ip=src_ip,
            dst_ip=_valid_ip(row["dst"]),       # host sensors put a hostname here; that becomes null
            severity=severity,
            first_seen=first_seen,
            last_seen=last_seen,
            count_delta=delta,
            handshake_confirmed=handshake,
            raw={**{k: row[k] for k in row.keys() if k != "details"}, "details": details},
            ml_probability=probability,
            ml_attack_type=attack_type,
            technique=self.technique_of(rule_id),
            stages=stages,
            stage=None if family is Family.CORRELATION else self.stage_of(rule_id),
        )

    def _ml_probability(self, details: dict, severity: str) -> float:
        for key in _ML_PROBABILITY_KEYS:
            value = details.get(key)
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                return min(1.0, max(0.0, float(value)))
        return self.cfg.ml_severity_fallback.get(severity, _ML_FALLBACK_OTHER)

    @staticmethod
    def _stages(details: dict) -> tuple[str, ...]:
        raw = next((details[k] for k in _STAGE_KEYS if isinstance(details.get(k), list)), [])
        stages = [s.get("stage") if isinstance(s, dict) else s for s in raw]
        return tuple(str(s) for s in stages if s)

    def _members_handshake(self, details: dict) -> bool:
        members = details.get(_MEMBER_RULES_KEY) or []
        return any((rule := self.family_of(str(m))) is not None and rule.handshake
                   and rule.family is not Family.CORRELATION for m in members)

    def _is_false_positive(self, status: Any) -> bool:
        return str(status or "").lower() in self._fp_statuses

    # ----------------------------------------------------------------- polling
    def poll(self) -> PollResult:
        """New evidence and triage changes since the last poll."""
        conn = self._connect()
        try:
            self._check_schema(conn)
            if self._cursor is None:
                self._prime(conn)
            result = PollResult(self._poll_alerts(conn), self._poll_triage(conn))
        except sqlite3.Error as exc:
            raise AdapterError(f"NIDS database read failed: {exc}") from exc
        finally:
            conn.close()
        self._flush()
        self.stats["evidence_emitted"] += len(result.evidence)
        self.stats["triage_emitted"] += len(result.triage)
        return result

    def _prime(self, conn: sqlite3.Connection) -> None:
        """First ever start: decide where to begin."""
        self._cursor, self._triage_cursor = 0.0, 0.0
        if self.cfg.start_from == "beginning":
            return
        # Remember every existing row's count so only what happens from now on is new.
        for row in conn.execute(self._select()):
            self._save_row(row["id"], {
                "c": row["count"], "fs": float(row["created_at"]), "sig": self._signature(row),
                "t": row["triage_status"] or _UNTRIAGED,
            })
            self._cursor = max(self._cursor, float(row["created_at"]))
            if row["triage_at"] is not None:
                self._triage_cursor = max(self._triage_cursor, float(row["triage_at"]))

    def _poll_alerts(self, conn: sqlite3.Connection) -> list[Evidence]:
        evidence: list[Evidence] = []
        rows = conn.execute(
            self._select() + " WHERE created_at > ? ORDER BY created_at, id",
            (self._cursor - self.cfg.lookback_seconds,),
        ).fetchall()
        for row in rows:
            created_at = float(row["created_at"])
            state = self._row_state(row["id"])
            signature = self._signature(row)
            if state is not None and (
                (state.get("sig") is not None and state["sig"] != signature) or row["count"] < state["c"]
            ):
                self._new_generation()
                state = None
            last_count = state["c"] if state else 0
            delta = row["count"] - last_count       # a new row's delta is its whole count
            self._cursor = max(self._cursor, created_at)
            if delta <= 0:
                continue
            first_seen = state["fs"] if state else created_at
            self._save_row(row["id"], {
                "c": row["count"], "fs": first_seen, "sig": signature,
                "t": state.get("t", _UNTRIAGED) if state else _UNTRIAGED,
            })
            if self._is_false_positive(row["triage_status"]):
                self.stats["skipped_false_positive"] += 1     # suppressed, or repeats of a dismissed alert
                continue
            ev = self._to_evidence(row, delta, first_seen, created_at)
            if ev is not None:
                evidence.append(ev)
        return evidence

    def _poll_triage(self, conn: sqlite3.Connection) -> list[TriageEvent]:
        if not self._has_triage:
            return []
        events: list[TriageEvent] = []
        rows = conn.execute(
            f"SELECT id, triage_status, triage_at FROM {TABLE} WHERE triage_at > ? ORDER BY triage_at, id",
            (self._triage_cursor - self.cfg.lookback_seconds,),
        ).fetchall()
        for row in rows:
            at = float(row["triage_at"])
            self._triage_cursor = max(self._triage_cursor, at)
            status = row["triage_status"] or _UNTRIAGED
            state = self._row_state(row["id"]) or {"c": 0, "fs": at, "sig": None}
            if state.get("t", _UNTRIAGED) == status:
                continue
            self._save_row(row["id"], {**state, "t": status})
            events.append(self._triage_event(row["id"], status, at))
        return events

    def _triage_event(self, row_id: int, status: str, at: float) -> TriageEvent:
        return TriageEvent(
            source=SOURCE,
            evidence_id_prefix=f"{SOURCE}:{self._alert_ref(row_id)}:",
            verdict=FALSE_POSITIVE if self._is_false_positive(status) else "other",
            status=str(status),
            at=at,
        )

    # ----------------------------------------------------------------- replay
    def snapshot(self) -> PollResult:
        """Everything in the database as one batch, for replaying a copy of it.

        Approximate by nature: a row keeps only its final count and the time of
        its last repeat, so each row becomes one evidence record carrying the
        whole count at that last time.
        """
        result = PollResult()
        conn = self._connect()
        try:
            self._check_schema(conn)
            for row in conn.execute(self._select() + " ORDER BY created_at, id"):
                seen = float(row["created_at"])
                dismissed = self._is_false_positive(row["triage_status"]) and row["triage_at"] is not None
                if dismissed:
                    # Evidence must precede its dismissal for the replay to show the reversal.
                    seen = min(seen, float(row["triage_at"]))
                ev = self._to_evidence(row, int(row["count"]), seen, seen)
                if ev is None:
                    continue
                result.evidence.append(ev)
                if dismissed:
                    result.triage.append(self._triage_event(row["id"], row["triage_status"], float(row["triage_at"])))
        except sqlite3.Error as exc:
            raise AdapterError(f"NIDS database read failed: {exc}") from exc
        finally:
            conn.close()
        return result
