"""The policy: allowlist, response target, rung, action.

`Policy.assess` is a pure function of (evidence, history count, config). It
never applies anything; the engine compares its answer with what is already
active and decides whether to act.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Iterable

from .config import Config
from .enrichment import Enricher, normalize_tactic
from .models import ActionKind, Evidence, Family, Target
from .scoring import Score, score_evidence

MAX_RUNG = 4
BLOCK_RUNG = 3
SPOOF_GUARD_MAX_RUNG = 1
_SECONDS_PER_HOUR = 3600

_LADDERS: dict[Target, dict[int, ActionKind]] = {
    Target.BLOCK_SRC: {
        0: ActionKind.OBSERVE, 1: ActionKind.THROTTLE, 2: ActionKind.RESET, 3: ActionKind.BLOCK, 4: ActionKind.BLOCK,
    },
    # Internal hosts: rung 1 only alerts, rung 3 isolates instead of dropping everything.
    Target.QUARANTINE_SRC: {
        0: ActionKind.OBSERVE, 1: ActionKind.ALERT, 2: ActionKind.RESET, 3: ActionKind.QUARANTINE, 4: ActionKind.QUARANTINE,
    },
}


@dataclass(frozen=True)
class Assessment:
    """What the policy thinks should be true for one IP right now."""

    ip: str
    score: Score
    target: Target
    rung: int
    kind: ActionKind
    ttl: int
    technique: str | None            # of the highest-scoring group
    tactic: str | None
    prior_blocks: int
    why_not_higher: str
    notes: tuple[str, ...]
    evidence_ids: tuple[str, ...]    # the evidence that was scored
    alert_only: tuple[Evidence, ...]
    while_blocked_count: int
    block_dst: dict[str, tuple[str, ...]]   # external destination -> evidence ids
    has_scorable_evidence: bool


def _fmt(value: float) -> str:
    return f"{value:.1f}".rstrip("0").rstrip(".")


class Policy:
    def __init__(self, cfg: Config, enricher: Enricher) -> None:
        self._p = cfg.policy
        self._scoring = cfg.scoring
        self._enricher = enricher
        self._allow = [ipaddress.ip_network(c) for c in cfg.network.allowlist]
        self._internal = [ipaddress.ip_network(c) for c in cfg.network.internal_networks]
        self._stage_index = {normalize_tactic(s): i for i, s in enumerate(self._p.kill_chain_order)}
        self._ttl = {
            1: self._p.throttle.ttl_seconds,
            2: self._p.reset.ttl_seconds,
            3: self._p.block.ttl_seconds,
            4: self._p.long_block.ttl_seconds,
        }

    # --- step 1: allowlist -------------------------------------------------
    def allowlisted_by(self, ip: str) -> str | None:
        """The allowlist CIDR covering this IP, or None."""
        addr = ipaddress.ip_address(ip)
        return next((str(net) for net in self._allow if addr in net), None)

    def is_internal(self, ip: str) -> bool:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in self._internal)

    def is_alert_only(self, ev: Evidence) -> bool:
        """Problems an IP block cannot solve (ARP spoofing, rogue hardware, impossible travel)."""
        return ev.rule_id in self._p.alert_only_rules or (
            ev.technique is not None and ev.technique in self._p.alert_only_techniques
        )

    def ttl_for(self, rung: int) -> int:
        return self._ttl.get(rung, 0)

    # --- steps 2-4 ---------------------------------------------------------
    def assess(self, ip: str, evidence: Iterable[Evidence], prior_blocks: int) -> Assessment:
        """Assess one IP from the evidence the caller considers current.

        prior_blocks is how many times this IP reached rung 3 or higher inside
        the repeat window, not counting anything being assessed now.
        """
        evidence = list(evidence)
        alert_only = [e for e in evidence if self.is_alert_only(e)]
        rest = [e for e in evidence if not self.is_alert_only(e)]
        # Evidence recorded while the source was already blocked is shown but never scored.
        scorable = [e for e in rest if not e.while_blocked]
        score = score_evidence(scorable, self._scoring)

        target = self._target(ip, score)
        rung, notes = self._rung(ip, scorable, score, prior_blocks)
        top = score.groups[0] if score.groups else None
        technique = top.technique if top else None

        block_dst: dict[str, tuple[str, ...]] = {}
        if target is Target.QUARANTINE_SRC and rung >= self._p.block_dst_min_rung:
            block_dst = self._external_destinations(scorable)

        return Assessment(
            ip=ip,
            score=score,
            target=target,
            rung=rung,
            kind=_LADDERS[target][rung],
            ttl=self.ttl_for(rung),
            technique=technique,
            tactic=self._enricher.tactic_for(technique),
            prior_blocks=prior_blocks,
            why_not_higher=self._why_not_higher(ip, rung, score, prior_blocks),
            notes=tuple(notes),
            evidence_ids=tuple(e.evidence_id for e in sorted(scorable, key=lambda e: (e.last_seen, e.evidence_id))),
            alert_only=tuple(alert_only),
            while_blocked_count=sum(e.count_delta for e in rest if e.while_blocked),
            block_dst=block_dst,
            has_scorable_evidence=bool(scorable),
        )

    def _target(self, ip: str, score: Score) -> Target:
        """Step 2: pick the response target from tactic and traffic direction."""
        has_tactic = any(self._enricher.tactic_for(g.technique) for g in score.groups)
        if not has_tactic:
            return Target.BLOCK_SRC          # no technique (ML-only evidence): by score only
        if self.is_internal(ip):
            return Target.QUARANTINE_SRC     # a compromised internal host is isolated, not just dropped
        return Target.BLOCK_SRC

    def _external_destinations(self, scorable: list[Evidence]) -> dict[str, tuple[str, ...]]:
        """External destinations of C2 / exfiltration / lateral movement / collection evidence."""
        found: dict[str, list[str]] = {}
        for ev in scorable:
            if not ev.dst_ip or self._enricher.tactic_for(ev.technique) not in self._p.quarantine_tactics:
                continue
            if ipaddress.ip_address(ev.dst_ip).version != 4:
                continue
            if self.is_internal(ev.dst_ip) or self.allowlisted_by(ev.dst_ip):
                continue
            found.setdefault(ev.dst_ip, []).append(ev.evidence_id)
        return {dst: tuple(ids) for dst, ids in sorted(found.items())}

    def _forward_progression(self, scorable: list[Evidence]) -> tuple[str, ...] | None:
        """Stages of the first correlated incident that moves forward along the kill chain."""
        for ev in scorable:
            if ev.family is not Family.CORRELATION or not ev.stages:
                continue
            earliest = None
            for stage in ev.stages:
                idx = self._stage_index.get(normalize_tactic(stage))
                if idx is None:
                    continue
                if earliest is not None and idx > earliest:
                    return ev.stages
                earliest = idx if earliest is None else min(earliest, idx)
        return None

    def _own_progression(self, scorable: list[Evidence]) -> tuple[str, ...] | None:
        """Stages this source's own alerts went through, if a later alert reached a later stage.

        The alert that advances must be handshake-confirmed, so forged packets
        cannot fake an advance; earlier stages (a SYN scan) need not be.
        """
        staged = []
        for ev in scorable:
            idx = self._stage_index.get(normalize_tactic(ev.stage)) if ev.stage else None
            if idx is not None:
                staged.append((ev.first_seen, idx, ev))
        staged.sort(key=lambda item: (item[0], item[1]))
        earliest = None
        seen: list[str] = []
        for _, idx, ev in staged:
            if ev.stage not in seen:
                seen.append(ev.stage)
            if earliest is not None and idx > earliest and ev.handshake_confirmed:
                return tuple(seen)
            earliest = idx if earliest is None else min(earliest, idx)
        return None

    def _has_instant_block(self, scorable: list[Evidence]) -> bool:
        return any(e.family.value in self._p.instant_block_families for e in scorable)

    def _rung(self, ip: str, scorable: list[Evidence], score: Score, prior_blocks: int) -> tuple[int, list[str]]:
        """Step 3: the highest rung whose conditions are all met, then the adjustments."""
        p, s = self._p, score.total
        families, handshake = len(score.families), score.handshake_confirmed
        instant = self._has_instant_block(scorable)
        notes: list[str] = []

        rung = 0
        if s >= p.throttle.score:
            rung = 1
        if s >= p.reset.score and handshake:
            rung = 2
        if s >= p.block.score and families >= p.block.families and handshake:
            rung = BLOCK_RUNG
        if instant and rung < BLOCK_RUNG:
            rung = BLOCK_RUNG
            notes.append("Honeypot contact: reaches rung 3 on contact alone.")

        stages = self._forward_progression(scorable)
        what = "Correlated incident shows"
        if not stages and self._p.progression_from_alerts:
            stages = self._own_progression(scorable)
            what = "This source's own alerts show"
        if stages:
            raised = min(rung + 1, MAX_RUNG)
            # Correlation may stand in for the second family up to rung 3, never beyond it.
            if raised > BLOCK_RUNG and families < p.block.families:
                raised = BLOCK_RUNG
            if raised != rung:
                notes.append(
                    f"{what} forward progression ({' -> '.join(stages)}): "
                    f"rung raised from {rung} to {raised}."
                )
                rung = raised

        if rung == BLOCK_RUNG and prior_blocks >= 1 and (families >= p.block.families or instant):
            rung = MAX_RUNG
            notes.append(
                f"Repeat offender: already blocked {prior_blocks} time(s) in the last "
                f"{_fmt(p.long_block.repeat_window_seconds / _SECONDS_PER_HOUR)} h."
            )

        if not handshake and rung > SPOOF_GUARD_MAX_RUNG:
            notes.append(
                f"Spoof guard: no handshake-confirmed evidence, so the source address may be forged; "
                f"capped at rung {SPOOF_GUARD_MAX_RUNG} instead of {rung}."
            )
            rung = SPOOF_GUARD_MAX_RUNG

        if ipaddress.ip_address(ip).version == 6 and rung > 0:
            notes.append("IPv6 source: version 1 enforces IPv4 only, so this is observed, not acted on.")
            rung = 0
        return rung, notes

    def _why_not_higher(self, ip: str, rung: int, score: Score, prior_blocks: int) -> str:
        """One sentence on what the next rung would have needed."""
        if rung >= MAX_RUNG:
            return f"Rung {MAX_RUNG} is the top rung; its duration is a hard cap."
        p, s = self._p, score.total
        families, handshake = len(score.families), score.handshake_confirmed
        nxt = rung + 1
        reasons: list[str] = []
        no_handshake = "no handshake-confirmed evidence, so the source address may be forged"
        if ipaddress.ip_address(ip).version == 6:
            reasons.append("IPv6 enforcement is not part of version 1")
        elif nxt == 1:
            reasons.append(f"score {_fmt(s)} is below {_fmt(p.throttle.score)}")
        elif nxt == 2:
            if s < p.reset.score:
                reasons.append(f"score {_fmt(s)} is below {_fmt(p.reset.score)}")
            if not handshake:
                reasons.append(no_handshake)
        elif nxt == BLOCK_RUNG:
            if s < p.block.score:
                reasons.append(f"score {_fmt(s)} is below {_fmt(p.block.score)}")
            if families < p.block.families:
                noun = "family" if families == 1 else "families"
                reason = f"only {families} independent {noun}, {p.block.families} needed"
                cut_off = self._scoring.ml.family_min_probability
                if cut_off is not None and score.ml_points > 0 and "anomaly_ml" not in score.families:
                    reason += f" (ML evidence below probability {cut_off:g} does not count as one)"
                reasons.append(reason)
            if not handshake:
                reasons.append(no_handshake)
        elif nxt == MAX_RUNG:
            window_h = _fmt(p.long_block.repeat_window_seconds / _SECONDS_PER_HOUR)
            if prior_blocks < 1:
                reasons.append(f"first block for this IP in {window_h} h")
            else:
                reasons.append("a repeat block needs a second independent family")
        if not reasons:
            reasons.append("its conditions are not all met")
        return f"Not rung {nxt}: {'; '.join(reasons)}."
