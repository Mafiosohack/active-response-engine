"""ips.db: the engine's own SQLite database.

Holds every evidence record exactly as received (the source of truth for
replay), every triage event, the decision log, and small key/value state for
adapters. All SQL is parameterised; nothing here builds a statement from data.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from typing import Any, Iterable

from .models import ActionKind, Decision, Evidence, TriageEvent

_SCHEMA = """
CREATE TABLE IF NOT EXISTS evidence (
    evidence_id         TEXT PRIMARY KEY,
    source              TEXT NOT NULL,
    family              TEXT NOT NULL,
    rule_id             TEXT NOT NULL,
    src_ip              TEXT NOT NULL,
    dst_ip              TEXT,
    severity            TEXT NOT NULL,
    first_seen          REAL NOT NULL,
    last_seen           REAL NOT NULL,
    count_delta         INTEGER NOT NULL,
    ml_probability      REAL,
    ml_attack_type      TEXT,
    technique           TEXT,
    handshake_confirmed INTEGER NOT NULL,
    stages              TEXT,
    raw                 TEXT NOT NULL,
    received_at         REAL NOT NULL,
    while_blocked       INTEGER NOT NULL DEFAULT 0,
    invalidated_at      REAL,
    invalidated_reason  TEXT,
    stage               TEXT
);
CREATE INDEX IF NOT EXISTS idx_evidence_src_seen ON evidence(src_ip, last_seen);
CREATE INDEX IF NOT EXISTS idx_evidence_received ON evidence(received_at);

CREATE TABLE IF NOT EXISTS triage_events (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    source             TEXT NOT NULL,
    evidence_id_prefix TEXT NOT NULL,
    verdict            TEXT NOT NULL,
    status             TEXT NOT NULL,
    at                 REAL NOT NULL,
    received_at        REAL NOT NULL,
    UNIQUE (source, evidence_id_prefix, status, at)
);

CREATE TABLE IF NOT EXISTS decisions (
    decision_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    ip              TEXT NOT NULL,
    target          TEXT NOT NULL,
    rung            INTEGER NOT NULL,
    kind            TEXT NOT NULL,
    ttl             INTEGER NOT NULL,
    created_at      REAL NOT NULL,
    expires_at      REAL NOT NULL,
    evidence_ids    TEXT NOT NULL,
    score           REAL NOT NULL,
    families        TEXT NOT NULL,
    technique       TEXT,
    tactic          TEXT,
    d3fend          TEXT,
    explanation     TEXT NOT NULL,
    driver          TEXT NOT NULL,
    driver_result   TEXT NOT NULL,
    reversed_at     REAL,
    reversed_reason TEXT,
    parent_id       INTEGER,
    detail          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_decisions_ip ON decisions(ip, created_at);
CREATE INDEX IF NOT EXISTS idx_decisions_expires ON decisions(expires_at);

CREATE TABLE IF NOT EXISTS adapter_state (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

_EVIDENCE_COLUMNS = (
    "evidence_id, source, family, rule_id, src_ip, dst_ip, severity, first_seen, last_seen, count_delta, "
    "ml_probability, ml_attack_type, technique, handshake_confirmed, stages, raw, received_at, while_blocked, stage"
)
_EVIDENCE_PARAMS = 19
# Columns added after version 1, applied in place to an existing ips.db.
_ADDED_COLUMNS = {"evidence": {"stage": "TEXT"}}
_DECISION_COLUMNS = (
    "ip, target, rung, kind, ttl, created_at, expires_at, evidence_ids, score, families, technique, tactic, "
    "d3fend, explanation, driver, driver_result, reversed_at, reversed_reason, parent_id, detail"
)
# SQLite's default limit on bound parameters per statement is 999 on older builds.
_MAX_SQL_PARAMS = 900


def _evidence_from_row(row: sqlite3.Row) -> Evidence:
    return Evidence(
        evidence_id=row["evidence_id"],
        source=row["source"],
        family=row["family"],
        rule_id=row["rule_id"],
        src_ip=row["src_ip"],
        dst_ip=row["dst_ip"],
        severity=row["severity"],
        first_seen=row["first_seen"],
        last_seen=row["last_seen"],
        count_delta=row["count_delta"],
        handshake_confirmed=bool(row["handshake_confirmed"]),
        raw=json.loads(row["raw"]),
        ml_probability=row["ml_probability"],
        ml_attack_type=row["ml_attack_type"],
        technique=row["technique"],
        stages=tuple(json.loads(row["stages"])) if row["stages"] else None,
        received_at=row["received_at"],
        while_blocked=bool(row["while_blocked"]),
        stage=row["stage"],
    )


def _decision_from_row(row: sqlite3.Row) -> Decision:
    return Decision(
        decision_id=row["decision_id"],
        ip=row["ip"],
        target=row["target"],
        rung=row["rung"],
        kind=row["kind"],
        ttl=row["ttl"],
        created_at=row["created_at"],
        expires_at=row["expires_at"],
        evidence_ids=json.loads(row["evidence_ids"]),
        score=row["score"],
        families=json.loads(row["families"]),
        technique=row["technique"],
        tactic=row["tactic"],
        d3fend=row["d3fend"],
        explanation=row["explanation"],
        driver=row["driver"],
        driver_result=row["driver_result"],
        reversed_at=row["reversed_at"],
        reversed_reason=row["reversed_reason"],
        parent_id=row["parent_id"],
        detail=json.loads(row["detail"]),
    )


def _decision_values(d: Decision) -> tuple:
    return (
        d.ip, d.target, d.rung, d.kind, d.ttl, d.created_at, d.expires_at, json.dumps(d.evidence_ids), d.score,
        json.dumps(d.families), d.technique, d.tactic, d.d3fend, d.explanation, d.driver, d.driver_result,
        d.reversed_at, d.reversed_reason, d.parent_id, json.dumps(d.detail),
    )


class Store:
    """Thread-safe wrapper around one SQLite connection."""

    def __init__(self, path: str = ":memory:") -> None:
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock, self._conn:
            if path != ":memory:":
                # WAL lets the API read while the engine writes.
                self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.executescript(_SCHEMA)
            self._add_missing_columns()

    def _add_missing_columns(self) -> None:
        for table, columns in _ADDED_COLUMNS.items():
            have = {r["name"] for r in self._conn.execute(f"PRAGMA table_info({table})")}
            for name, sql_type in columns.items():
                if name not in have:
                    self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {sql_type}")

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # --- evidence ------------------------------------------------------------
    def add_evidence(self, ev: Evidence) -> bool:
        """Store one evidence record. Returns False if this evidence_id was already stored."""
        with self._lock, self._conn:
            cur = self._conn.execute(
                f"INSERT OR IGNORE INTO evidence ({_EVIDENCE_COLUMNS}) VALUES ({','.join('?' * _EVIDENCE_PARAMS)})",
                (
                    ev.evidence_id, ev.source, ev.family.value, ev.rule_id, ev.src_ip, ev.dst_ip, ev.severity.value,
                    ev.first_seen, ev.last_seen, ev.count_delta, ev.ml_probability, ev.ml_attack_type, ev.technique,
                    int(ev.handshake_confirmed), json.dumps(list(ev.stages)) if ev.stages is not None else None,
                    json.dumps(ev.raw, default=str), ev.received_at, int(ev.while_blocked), ev.stage,
                ),
            )
            return cur.rowcount == 1

    def window_evidence(self, since: float) -> list[Evidence]:
        """Valid evidence last seen at or after `since`, oldest first."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM evidence WHERE last_seen >= ? AND invalidated_at IS NULL ORDER BY last_seen, evidence_id",
                (since,),
            ).fetchall()
        return [_evidence_from_row(r) for r in rows]

    def evidence_between(self, start: float | None, end: float | None) -> list[Evidence]:
        """Every evidence record received in [start, end], invalidated or not. For replay."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM evidence WHERE received_at >= ? AND received_at <= ? ORDER BY received_at, evidence_id",
                (start if start is not None else float("-inf"), end if end is not None else float("inf")),
            ).fetchall()
        return [_evidence_from_row(r) for r in rows]

    def evidence_by_ids(self, ids: Iterable[str], valid_only: bool = True) -> list[Evidence]:
        ids = list(ids)
        out: list[Evidence] = []
        with self._lock:
            for i in range(0, len(ids), _MAX_SQL_PARAMS):
                chunk = ids[i:i + _MAX_SQL_PARAMS]
                sql = f"SELECT * FROM evidence WHERE evidence_id IN ({','.join('?' * len(chunk))})"
                if valid_only:
                    sql += " AND invalidated_at IS NULL"
                out.extend(_evidence_from_row(r) for r in self._conn.execute(sql, chunk).fetchall())
        return out

    def invalidate_by_prefix(self, prefix: str, at: float, reason: str) -> list[Evidence]:
        """Mark all still-valid evidence whose id starts with `prefix` as invalid; return it."""
        with self._lock, self._conn:
            rows = self._conn.execute(
                "SELECT * FROM evidence WHERE substr(evidence_id, 1, ?) = ? AND invalidated_at IS NULL",
                (len(prefix), prefix),
            ).fetchall()
            self._conn.execute(
                "UPDATE evidence SET invalidated_at = ?, invalidated_reason = ? "
                "WHERE substr(evidence_id, 1, ?) = ? AND invalidated_at IS NULL",
                (at, reason, len(prefix), prefix),
            )
        return [_evidence_from_row(r) for r in rows]

    def invalidate_ids(self, ids: Iterable[str], at: float, reason: str) -> None:
        with self._lock, self._conn:
            self._conn.executemany(
                "UPDATE evidence SET invalidated_at = ?, invalidated_reason = ? "
                "WHERE evidence_id = ? AND invalidated_at IS NULL",
                [(at, reason, i) for i in ids],
            )

    # --- triage --------------------------------------------------------------
    def add_triage(self, event: TriageEvent, received_at: float) -> bool:
        """Record a triage event. Returns False if the same event was already recorded."""
        with self._lock, self._conn:
            cur = self._conn.execute(
                "INSERT OR IGNORE INTO triage_events (source, evidence_id_prefix, verdict, status, at, received_at) "
                "VALUES (?,?,?,?,?,?)",
                (event.source, event.evidence_id_prefix, event.verdict, event.status, event.at, received_at),
            )
            return cur.rowcount == 1

    def triage_between(self, start: float | None, end: float | None) -> list[tuple[float, TriageEvent]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM triage_events WHERE received_at >= ? AND received_at <= ? ORDER BY received_at, id",
                (start if start is not None else float("-inf"), end if end is not None else float("inf")),
            ).fetchall()
        return [
            (r["received_at"], TriageEvent(r["source"], r["evidence_id_prefix"], r["verdict"], r["status"], r["at"]))
            for r in rows
        ]

    # --- decisions -----------------------------------------------------------
    def add_decision(self, d: Decision) -> int:
        with self._lock, self._conn:
            cur = self._conn.execute(
                f"INSERT INTO decisions ({_DECISION_COLUMNS}) VALUES ({','.join('?' * 20)})", _decision_values(d)
            )
            d.decision_id = int(cur.lastrowid)
            return d.decision_id

    def save_decision(self, d: Decision) -> None:
        """Write back the fields that change after a decision is first logged."""
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE decisions SET explanation = ?, driver_result = ?, reversed_at = ?, reversed_reason = ? "
                "WHERE decision_id = ?",
                (d.explanation, d.driver_result, d.reversed_at, d.reversed_reason, d.decision_id),
            )

    def get_decision(self, decision_id: int) -> Decision | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM decisions WHERE decision_id = ?", (decision_id,)).fetchone()
        return _decision_from_row(row) if row else None

    def decisions(self, ip: str | None = None, limit: int | None = None, newest_first: bool = False) -> list[Decision]:
        sql, params = "SELECT * FROM decisions", []
        if ip is not None:
            sql += " WHERE ip = ?"
            params.append(ip)
        sql += " ORDER BY decision_id" + (" DESC" if newest_first else "")
        if limit is not None:
            sql += " LIMIT ?"
            params.append(int(limit))
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [_decision_from_row(r) for r in rows]

    def active_decisions(self, now: float) -> list[Decision]:
        """Decisions still in force: applied (or alert-only), not expired, not reversed."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM decisions WHERE expires_at > ? AND reversed_at IS NULL AND ttl > 0 "
                "AND kind != ? AND (driver_result LIKE 'ok%' OR driver_result = 'not_enforced') ORDER BY decision_id",
                (now, ActionKind.OBSERVE.value),
            ).fetchall()
        return [_decision_from_row(r) for r in rows]

    def block_history(self, since: float) -> list[Decision]:
        """Blocks and quarantines that took effect since `since` and were not undone by triage.

        A block superseded by a stronger one still counts: it did happen.
        """
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM decisions WHERE created_at >= ? AND kind IN (?, ?) AND driver_result LIKE 'ok%' "
                "AND (reversed_at IS NULL OR reversed_reason LIKE 'superseded%') ORDER BY decision_id",
                (since, ActionKind.BLOCK.value, ActionKind.QUARANTINE.value),
            ).fetchall()
        return [_decision_from_row(r) for r in rows]

    # --- retention -----------------------------------------------------------
    def prune(self, before: float, now: float) -> dict[str, int]:
        """Delete rows older than `before`; return how many went from each table.

        Kept regardless of age: a decision that has not expired yet, and
        evidence last seen after the cutoff. Adapter bookmarks are never
        touched, because losing one would make old alerts look new.
        """
        with self._lock, self._conn:
            evidence = self._conn.execute(
                "DELETE FROM evidence WHERE received_at < ? AND last_seen < ?", (before, before)
            ).rowcount
            triage = self._conn.execute("DELETE FROM triage_events WHERE received_at < ?", (before,)).rowcount
            decisions = self._conn.execute(
                "DELETE FROM decisions WHERE created_at < ? AND expires_at <= ?", (before, now)
            ).rowcount
        return {"evidence": evidence, "triage_events": triage, "decisions": decisions}

    # --- adapter state -------------------------------------------------------
    def get_state(self, key: str) -> Any | None:
        with self._lock:
            row = self._conn.execute("SELECT value FROM adapter_state WHERE key = ?", (key,)).fetchone()
        return json.loads(row["value"]) if row else None

    def set_states(self, items: dict[str, Any]) -> None:
        with self._lock, self._conn:
            self._conn.executemany(
                "INSERT INTO adapter_state (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                [(k, json.dumps(v)) for k, v in items.items()],
            )

    def delete_states(self, prefix: str) -> None:
        with self._lock, self._conn:
            self._conn.execute("DELETE FROM adapter_state WHERE substr(key, 1, ?) = ?", (len(prefix), prefix))
