"""The engine: holds live state and turns policy assessments into actions.

It keeps, per source IP, the evidence inside the sliding window and whatever
action is currently in force. On every new evidence record and on a periodic
tick it asks the policy what should be true, and acts only when the answer is
a higher rung than what is already active. Actions run for their full duration
and are lifted early only by triage feedback or a manual unblock.

The engine never imports an adapter or a concrete driver.
"""
from __future__ import annotations

import logging
import threading
import time
from collections import Counter
from dataclasses import dataclass, replace
from typing import Callable

from .config import Config
from .enforcers.base import Enforcer
from .enrichment import Enricher
from .explain import explain
from .models import (
    ENFORCED_KINDS,
    ISOLATING_KINDS,
    Action,
    ActionKind,
    Decision,
    Evidence,
    Target,
    TriageEvent,
    normalize_ip,
)
from .policy import Assessment, Policy

logger = logging.getLogger(__name__)

_ISOLATING_VALUES = frozenset(k.value for k in ISOLATING_KINDS)
_ENFORCED_VALUES = frozenset(k.value for k in ENFORCED_KINDS)
FALSE_POSITIVE = "false_positive"
SUPERSEDED_PREFIX = "superseded"


@dataclass
class ActiveAction:
    """An action currently in force, mirrored from the decision log."""

    decision_id: int
    ip: str
    kind: str
    rung: int
    target: str
    created_at: float
    expires_at: float
    evidence_ids: frozenset[str]
    parent_id: int | None = None


class Engine:
    def __init__(
        self,
        cfg: Config,
        store,
        policy: Policy,
        enricher: Enricher,
        enforcer: Enforcer,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.cfg = cfg
        self.store = store
        self.policy = policy
        self.enricher = enricher
        self.enforcer = enforcer
        self.clock = clock
        self.stats: Counter = Counter()

        self._lock = threading.RLock()
        self._window = cfg.scoring.window_seconds
        self._repeat_window = cfg.policy.long_block.repeat_window_seconds
        self._evidence: dict[str, list[Evidence]] = {}
        self._active: dict[str, dict[str, ActiveAction]] = {}
        self._block_times: dict[str, list[tuple[float, int]]] = {}    # ip -> (time, decision id)
        self._observed: set[str] = set()                              # rung-0 already logged this episode
        self._alerted: dict[tuple[str, str], float] = {}              # (ip, rule) -> last alert-only time
        self._retry_after: dict[str, float] = {}                      # ip -> earliest retry after a driver failure

    # ------------------------------------------------------------------ startup
    def restore(self) -> None:
        """Rebuild live state from ips.db after a restart and re-assert active actions."""
        with self._lock:
            now = self.clock()
            for ev in self.store.window_evidence(now - self._window):
                self._evidence.setdefault(ev.src_ip, []).append(ev)
            for d in self.store.block_history(now - self._repeat_window):
                self._block_times.setdefault(d.ip, []).append((d.created_at, d.decision_id))
            for d in self.store.active_decisions(now):
                self._register(d)
                if d.kind in _ENFORCED_VALUES:
                    # Idempotent: puts the entry back if the firewall table was lost (e.g. reboot).
                    remaining = max(1, int(d.expires_at - now))
                    try:
                        self.enforcer.apply(Action(ActionKind(d.kind), d.ip, remaining, str(d.decision_id)))
                    except Exception as exc:  # noqa: BLE001 - a driver failure must not stop startup
                        logger.error("could not re-assert decision #%s on %s: %s", d.decision_id, d.ip, exc)
            logger.info("restored %d tracked IP(s) and %d active action(s)",
                        len(self._evidence), sum(len(k) for k in self._active.values()))

    # ------------------------------------------------------------------ inputs
    def ingest(self, ev: Evidence) -> bool:
        """Take one evidence record: store it, then re-evaluate its source IP."""
        with self._lock:
            now = self.clock()
            ev = replace(ev, received_at=now, while_blocked=self._is_isolated(ev.src_ip, now))
            if not self.store.add_evidence(ev):
                self.stats["duplicate_evidence"] += 1
                return False
            self.stats["evidence"] += 1
            self._evidence.setdefault(ev.src_ip, []).append(ev)
            self._evaluate(ev.src_ip, now)
            return True

    def triage(self, event: TriageEvent) -> None:
        """Apply an analyst verdict. A false positive removes its evidence and
        lifts any action the remaining evidence no longer supports."""
        with self._lock:
            now = self.clock()
            if not self.store.add_triage(event, now):
                return
            self.stats["triage_events"] += 1
            if event.verdict != FALSE_POSITIVE:
                return
            alert_ref = event.evidence_id_prefix.rstrip(":")
            reason = f"triage: {alert_ref} marked false positive"
            removed = self.store.invalidate_by_prefix(event.evidence_id_prefix, now, reason)
            if removed:
                self._after_invalidation(removed, now, reason)

    def manual_unblock(self, ip: str, who: str = "operator") -> list[int]:
        """Lift everything active on an IP and discard its current evidence.

        The evidence is discarded on purpose: otherwise the next tick would see
        the same score and put the block straight back.
        """
        with self._lock:
            now = self.clock()
            ip = normalize_ip(ip)
            reason = f"manual unblock by {who}"
            lifted = []
            for act in list(self._active.get(ip, {}).values()):
                lifted.append(act.decision_id)
                self._reverse(act, now, reason)
            evidence = self._evidence.pop(ip, [])
            self.store.invalidate_ids([e.evidence_id for e in evidence], now, reason)
            self._forget(ip)
            return lifted

    # ------------------------------------------------------------------ clock-driven
    def expire_due(self) -> None:
        """Drop actions whose time is up and re-evaluate their IPs (rungs step down)."""
        with self._lock:
            self._expire(self.clock())

    def tick(self) -> None:
        """Periodic re-evaluation, so rungs fall as evidence ages out of the window."""
        with self._lock:
            now = self.clock()
            self._expire(now)
            for ip in list(self._evidence):
                self._evaluate(ip, now)
            self._alerted = {k: t for k, t in self._alerted.items() if now - t < self._window}
            for ip in list(self._block_times):
                kept = [(t, i) for t, i in self._block_times[ip] if now - t < self._repeat_window]
                if kept:
                    self._block_times[ip] = kept
                else:
                    del self._block_times[ip]

    def idle(self) -> bool:
        with self._lock:
            return not self._evidence and not self._active

    # ------------------------------------------------------------------ read side
    def active_actions(self) -> list[dict]:
        with self._lock:
            now = self.clock()
            return [
                {"decision_id": a.decision_id, "ip": a.ip, "kind": a.kind, "rung": a.rung, "target": a.target,
                 "remaining_seconds": round(a.expires_at - now, 1), "parent_id": a.parent_id}
                for kinds in self._active.values() for a in kinds.values() if a.expires_at > now
            ]

    def snapshot(self, ip: str) -> dict:
        """What the policy currently thinks of one IP, without acting on it."""
        with self._lock:
            now = self.clock()
            ip = normalize_ip(ip)
            self._prune(ip, now)
            evidence = self._evidence.get(ip, [])
            out: dict = {
                "ip": ip,
                "allowlisted_by": self.policy.allowlisted_by(ip),
                "evidence_in_window": len(evidence),
                "active": [a for a in self.active_actions() if a["ip"] == ip],
            }
            if evidence:
                main = self._main_action(ip, now)
                prior = self._prior_blocks(ip, now, exclude=main.decision_id if main else None)
                a = self.policy.assess(ip, evidence, prior)
                out.update({
                    "score": a.score.total, "families": list(a.score.families),
                    "handshake_confirmed": a.score.handshake_confirmed, "target": a.target.value,
                    "rung": a.rung, "kind": a.kind.value, "why_not_higher": a.why_not_higher,
                    "notes": list(a.notes),
                })
            return out

    def status(self) -> dict:
        with self._lock:
            return {
                "tracked_ips": len(self._evidence),
                "active_actions": sum(len(k) for k in self._active.values()),
                "driver": self.enforcer.name,
                "stats": dict(self.stats),
            }

    # ------------------------------------------------------------------ internals
    def _prune(self, ip: str, now: float) -> None:
        evidence = self._evidence.get(ip)
        if evidence is None:
            return
        # Strictly inside the window: an action lasting exactly one window must not
        # be renewed by the very evidence that caused it.
        kept = [e for e in evidence if now - e.last_seen < self._window]
        if kept:
            self._evidence[ip] = kept
        else:
            del self._evidence[ip]

    def _forget(self, ip: str) -> None:
        self._observed.discard(ip)
        self._retry_after.pop(ip, None)

    def _main_action(self, ip: str, now: float) -> ActiveAction | None:
        """The strongest action in force against this IP as a source."""
        candidates = [
            a for a in self._active.get(ip, {}).values()
            if a.kind != ActionKind.BLOCK_DST.value and a.expires_at > now
        ]
        return max(candidates, key=lambda a: a.rung, default=None)

    def _is_isolated(self, ip: str, now: float) -> bool:
        return any(a.kind in _ISOLATING_VALUES and a.expires_at > now for a in self._active.get(ip, {}).values())

    def _prior_blocks(self, ip: str, now: float, exclude: int | None = None) -> int:
        return sum(1 for t, i in self._block_times.get(ip, []) if now - self._repeat_window < t <= now and i != exclude)

    def _expire(self, now: float) -> None:
        affected = []
        for ip in list(self._active):
            kinds = self._active[ip]
            for kind in [k for k, a in kinds.items() if a.expires_at <= now]:
                del kinds[kind]
                self.stats["expired"] += 1
                if kind != ActionKind.BLOCK_DST.value:
                    affected.append(ip)
            if not kinds:
                del self._active[ip]
        for ip in affected:
            self._evaluate(ip, now)

    def _evaluate(self, ip: str, now: float) -> None:
        """Run the four policy steps for one IP and act if the rung went up."""
        self._prune(ip, now)
        evidence = self._evidence.get(ip)
        main = self._main_action(ip, now)
        if not evidence:
            if main is None:
                self._forget(ip)
            return

        cidr = self.policy.allowlisted_by(ip)
        if cidr:
            if ip not in self._observed:
                self._observed.add(ip)
                self._commit(Decision(
                    ip=ip, target=Target.ALLOWLISTED.value, rung=0, kind=ActionKind.OBSERVE.value, ttl=0,
                    created_at=now, expires_at=now, evidence_ids=[e.evidence_id for e in evidence], score=0.0,
                    families=[], detail={"cidr": cidr},
                ))
            return

        # The block that is in force right now is not a *previous* block.
        prior = self._prior_blocks(ip, now, exclude=main.decision_id if main else None)
        a = self.policy.assess(ip, evidence, prior)
        self._raise_alert_only(a, now)

        if a.rung == 0:
            if main is None and ip not in self._observed and (a.has_scorable_evidence or a.while_blocked_count):
                self._observed.add(ip)
                self._commit(self._decision_from(a, now))
            return

        current = main.rung if main else 0
        if a.rung > current and now >= self._retry_after.get(ip, 0.0):
            self._act(a, main, now)
        self._block_destinations(a, now)

    def _detail(self, a: Assessment, kind: ActionKind) -> dict:
        counter = self.enricher.countermeasure(kind) if kind in ENFORCED_KINDS else None
        ml = self.cfg.scoring.ml
        detail = {
            "groups": [
                {"family": g.family.value, "rule_id": g.rule_id, "count": g.total_count, "points": g.points,
                 "kind": g.kind, "dst_ip": g.dst_ip, "max_probability": g.max_probability,
                 "ml_attack_type": g.ml_attack_type}
                for g in a.score.groups
            ],
            "ml_points": a.score.ml_points,
            "ml_capped": a.score.ml_capped,
            "ml_cap": ml.per_ip_cap if ml.per_ip_cap is not None else ml.cap,
            "ml_family_min_probability": ml.family_min_probability,
            "handshake_confirmed": a.score.handshake_confirmed,
            "technique_name": self.enricher.technique_name(a.technique),
            "tactic_name": self.enricher.tactic_name(a.tactic),
            "d3fend": {"id": counter.d3fend_id, "name": counter.name} if counter else None,
            "why_not_higher": a.why_not_higher,
            "notes": list(a.notes),
            "while_blocked_count": a.while_blocked_count,
            "prior_blocks": a.prior_blocks,
        }
        if kind is ActionKind.THROTTLE:
            detail["throttle_rate"] = self.cfg.nftables.throttle_rate_per_second
        return detail

    def _decision_from(self, a: Assessment, now: float) -> Decision:
        detail = self._detail(a, a.kind)
        counter = detail["d3fend"]
        return Decision(
            ip=a.ip, target=a.target.value, rung=a.rung, kind=a.kind.value, ttl=a.ttl, created_at=now,
            expires_at=now + a.ttl, evidence_ids=list(a.evidence_ids), score=a.score.total,
            families=list(a.score.families), technique=a.technique, tactic=a.tactic,
            d3fend=f"{counter['id']} {counter['name']}" if counter else None,
            driver=self.enforcer.name if a.kind in ENFORCED_KINDS else "none", detail=detail,
        )

    def _commit(self, d: Decision) -> bool:
        """Log a decision, enforce it if it is enforceable, and record the driver's answer."""
        self.store.add_decision(d)
        kind = ActionKind(d.kind)
        if kind in ENFORCED_KINDS:
            try:
                result = self.enforcer.apply(Action(kind, d.ip, d.ttl, str(d.decision_id)))
                d.driver_result = f"ok: {result}" if result else "ok"
            except Exception as exc:  # noqa: BLE001 - every driver failure belongs in the decision log
                d.driver_result = f"error: {exc}"
                self.stats["driver_errors"] += 1
                logger.error("driver %s failed for decision #%s on %s: %s", d.driver, d.decision_id, d.ip, exc)
        else:
            d.driver_result = "not_enforced"
        d.explanation = explain(d)
        self.store.save_decision(d)
        self.stats["decisions"] += 1
        level = logging.WARNING if kind is ActionKind.ALERT else logging.INFO
        logger.log(level, "decision #%s: %s", d.decision_id, d.explanation.splitlines()[0])
        return not d.driver_result.startswith("error")

    def _register(self, d: Decision) -> ActiveAction:
        act = ActiveAction(
            decision_id=d.decision_id, ip=d.ip, kind=d.kind, rung=d.rung, target=d.target, created_at=d.created_at,
            expires_at=d.expires_at, evidence_ids=frozenset(d.evidence_ids), parent_id=d.parent_id,
        )
        self._active.setdefault(d.ip, {})[d.kind] = act
        return act

    def _act(self, a: Assessment, main: ActiveAction | None, now: float) -> None:
        d = self._decision_from(a, now)
        if not self._commit(d):
            # Do not hammer a failing driver on every new alert; try again next tick.
            self._retry_after[a.ip] = now + self.cfg.engine.tick_seconds
            return
        self._retry_after.pop(a.ip, None)
        if main is not None:
            self._supersede(main, d, now)
        self._register(d)
        if d.kind in _ISOLATING_VALUES:
            self._block_times.setdefault(a.ip, []).append((now, d.decision_id))

    def _supersede(self, old: ActiveAction, new: Decision, now: float) -> None:
        """A stronger action replaced a weaker one. The new one is already in place."""
        note = ""
        if old.kind != new.kind and old.kind in _ENFORCED_VALUES:
            try:
                self.enforcer.remove(old.ip, ActionKind(old.kind))
            except Exception as exc:  # noqa: BLE001
                note = f"; driver could not remove the old entry: {exc}"
        self._mark_reversed(old.decision_id, now, f"{SUPERSEDED_PREFIX} by decision #{new.decision_id}{note}")
        kinds = self._active.get(old.ip, {})
        if kinds.get(old.kind) is old:
            del kinds[old.kind]

    def _mark_reversed(self, decision_id: int, now: float, reason: str) -> None:
        d = self.store.get_decision(decision_id)
        if d is None:
            return
        d.reversed_at, d.reversed_reason = now, reason
        d.explanation = explain(d)
        self.store.save_decision(d)

    def _reverse(self, act: ActiveAction, now: float, reason: str) -> None:
        """Lift one action early and log why. Companion actions go with it."""
        note = ""
        if act.kind in _ENFORCED_VALUES:
            try:
                self.enforcer.remove(act.ip, ActionKind(act.kind))
            except Exception as exc:  # noqa: BLE001
                note = f"; driver could not remove the entry: {exc}"
                self.stats["driver_errors"] += 1
        self._mark_reversed(act.decision_id, now, reason + note)
        kinds = self._active.get(act.ip, {})
        if kinds.get(act.kind) is act:
            del kinds[act.kind]
            if not kinds:
                del self._active[act.ip]
        if act.kind in _ISOLATING_VALUES:
            # A block that was a mistake must not count towards a long block later.
            self._block_times[act.ip] = [(t, i) for t, i in self._block_times.get(act.ip, []) if i != act.decision_id]
        self.stats["reversals"] += 1
        logger.warning("decision #%s on %s reversed: %s", act.decision_id, act.ip, reason + note)
        children = [c for kinds in self._active.values() for c in kinds.values() if c.parent_id == act.decision_id]
        for child in children:
            self._reverse(child, now, f"parent decision #{act.decision_id} was reversed ({reason})")

    def _raise_alert_only(self, a: Assessment, now: float) -> None:
        """Log one alert-only decision per (IP, rule) per window. Nothing is enforced."""
        by_rule: dict[str, list[Evidence]] = {}
        for ev in a.alert_only:
            by_rule.setdefault(ev.rule_id, []).append(ev)
        for rule_id, items in by_rule.items():
            last = self._alerted.get((a.ip, rule_id))
            if last is not None and now - last < self._window:
                continue
            self._alerted[(a.ip, rule_id)] = now
            technique = next((e.technique for e in items if e.technique), None)
            self._commit(Decision(
                ip=a.ip, target=Target.ALERT_ONLY.value, rung=0, kind=ActionKind.ALERT.value, ttl=0,
                created_at=now, expires_at=now, evidence_ids=[e.evidence_id for e in items], score=0.0,
                families=sorted({e.family.value for e in items}), technique=technique,
                tactic=self.enricher.tactic_for(technique),
                detail={"alert_only": {
                    "rule_id": rule_id, "technique": technique,
                    "technique_name": self.enricher.technique_name(technique),
                    "count": sum(e.count_delta for e in items),
                }},
            ))

    def _block_destinations(self, a: Assessment, now: float) -> None:
        """Companion block_dst actions for a quarantined or reset internal host."""
        main = self._main_action(a.ip, now)
        if not a.block_dst or main is None or main.target != Target.QUARANTINE_SRC.value:
            return
        if main.rung < self.cfg.policy.block_dst_min_rung:
            return
        ttl = int(main.expires_at - now)
        if ttl < 1:
            return
        kind = ActionKind.BLOCK_DST
        for dst, evidence_ids in a.block_dst.items():
            existing = self._active.get(dst, {}).get(kind.value)
            if (existing and existing.expires_at > now) or now < self._retry_after.get(dst, 0.0):
                continue
            detail = self._detail(a, kind)
            detail["companion_of"] = {"decision_id": main.decision_id, "src_ip": a.ip}
            counter = detail["d3fend"]
            d = Decision(
                ip=dst, target=Target.BLOCK_DST.value, rung=main.rung, kind=kind.value, ttl=ttl, created_at=now,
                expires_at=now + ttl, evidence_ids=list(evidence_ids), score=a.score.total,
                families=list(a.score.families), technique=a.technique, tactic=a.tactic,
                d3fend=f"{counter['id']} {counter['name']}" if counter else None,
                driver=self.enforcer.name, parent_id=main.decision_id, detail=detail,
            )
            if self._commit(d):
                self._register(d)
            else:
                self._retry_after[dst] = now + self.cfg.engine.tick_seconds

    def _after_invalidation(self, removed: list[Evidence], now: float, reason: str) -> None:
        """Evidence was withdrawn: re-check every action that relied on it."""
        gone = {e.evidence_id for e in removed}
        for ip in sorted({e.src_ip for e in removed}):
            if ip in self._evidence:
                kept = [e for e in self._evidence[ip] if e.evidence_id not in gone]
                if kept:
                    self._evidence[ip] = kept
                else:
                    del self._evidence[ip]
            for act in list(self._active.get(ip, {}).values()):
                if act.kind == ActionKind.BLOCK_DST.value or not act.evidence_ids & gone:
                    continue
                # Would this decision still have been made without the withdrawn
                # evidence? Judge it on the evidence it was made from, as it was then.
                remaining = [replace(e, while_blocked=False) for e in self.store.evidence_by_ids(act.evidence_ids)]
                prior = self._prior_blocks(ip, act.created_at, exclude=act.decision_id)
                supported = self.policy.assess(ip, remaining, prior).rung
                if supported < act.rung:
                    self._reverse(act, now, f"{reason}; the remaining evidence supports rung {supported}, not {act.rung}")
            self._evaluate(ip, now)

        # A destination block whose own evidence is all gone has nothing left to stand on.
        for kinds in list(self._active.values()):
            act = kinds.get(ActionKind.BLOCK_DST.value)
            if act and act.evidence_ids & gone and not self.store.evidence_by_ids(act.evidence_ids):
                self._reverse(act, now, reason)
