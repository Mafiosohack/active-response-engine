"""Turns the evidence in one source IP's window into a score.

Pure functions only: no clock, no database, no policy. The caller decides which
evidence is in the window and passes exactly that.
"""
from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass
from typing import Iterable

from .config import ScoringConfig
from .models import Evidence, Family

_SCORE_DECIMALS = 2


@dataclass(frozen=True)
class Group:
    """One scored bucket: a rule, or all ML evidence towards one destination."""

    kind: str                      # "rule" or "ml"
    family: Family
    rule_id: str
    total_count: int
    points: float
    technique: str | None
    evidence_ids: tuple[str, ...]
    dst_ip: str | None = None
    max_probability: float | None = None
    ml_attack_type: str | None = None


@dataclass(frozen=True)
class Score:
    total: float
    groups: tuple[Group, ...]          # highest points first
    families: tuple[str, ...]          # independent families that scored above zero
    handshake_confirmed: bool
    ml_points: float                   # ML contribution after the per-source cap
    ml_capped: bool


def rescale_probability(p: float, floor: float) -> float:
    """Map [floor, 1] onto [0, 1].

    The source only raises an ML alert at p >= floor, so floor means "barely an
    alert" and must score nothing.
    """
    return min(1.0, max(0.0, (p - floor) / (1.0 - floor)))


def _rule_group(rule_id: str, items: list[Evidence], cfg: ScoringConfig) -> Group:
    base = max(cfg.severity_points[e.severity.value] for e in items)
    total = sum(e.count_delta for e in items)
    # Repeats add logarithmically: forty hits of one rule are one sustained event, not forty votes.
    points = min(base * cfg.repeat_cap_multiplier, base * (1.0 + math.log2(total)))
    return Group(
        kind="rule",
        family=items[0].family,
        rule_id=rule_id,
        total_count=total,
        points=round(points, _SCORE_DECIMALS),
        technique=next((e.technique for e in items if e.technique), None),
        evidence_ids=tuple(e.evidence_id for e in items),
    )


def _ml_group(dst_ip: str | None, items: list[Evidence], cfg: ScoringConfig) -> Group:
    ml = cfg.ml
    best = max(items, key=lambda e: e.ml_probability if e.ml_probability is not None else ml.floor)
    best_p = best.ml_probability if best.ml_probability is not None else ml.floor
    total = sum(e.count_delta for e in items)
    points = min(ml.cap, ml.cap * rescale_probability(best_p, ml.floor) * (1.0 + ml.repeat_weight * math.log2(total)))
    return Group(
        kind="ml",
        family=Family.ANOMALY_ML,
        rule_id=", ".join(sorted({e.rule_id for e in items})),
        total_count=total,
        points=round(points, _SCORE_DECIMALS),
        technique=None,
        evidence_ids=tuple(e.evidence_id for e in items),
        dst_ip=dst_ip,
        max_probability=best_p,
        ml_attack_type=best.ml_attack_type,
    )


def _counts_as_family(group: Group, cfg: ScoringConfig) -> bool:
    cut_off = cfg.ml.family_min_probability
    if group.kind != "ml" or cut_off is None:
        return True
    return group.max_probability is not None and group.max_probability >= cut_off


def score_evidence(evidence: Iterable[Evidence], cfg: ScoringConfig) -> Score:
    """Score one source IP's in-window evidence."""
    by_rule: dict[str, list[Evidence]] = defaultdict(list)
    by_dst: dict[str | None, list[Evidence]] = defaultdict(list)
    handshake = False
    for ev in evidence:
        handshake = handshake or ev.handshake_confirmed
        if ev.family is Family.CORRELATION:
            continue      # scores nothing; the policy uses it to raise a rung
        if ev.family is Family.ANOMALY_ML:
            by_dst[ev.dst_ip].append(ev)      # high and medium rows merge here
        else:
            by_rule[ev.rule_id].append(ev)

    rule_groups = [_rule_group(rule, items, cfg) for rule, items in by_rule.items()]
    ml_groups = [_ml_group(dst, items, cfg) for dst, items in by_dst.items()]

    ml_raw = sum(g.points for g in ml_groups)
    ml_points = ml_raw if cfg.ml.per_ip_cap is None else min(ml_raw, cfg.ml.per_ip_cap)
    total = sum(g.points for g in rule_groups) + ml_points

    groups = sorted(rule_groups + ml_groups, key=lambda g: (-g.points, g.kind, g.rule_id, g.dst_ip or ""))
    # A family is independent corroboration only if it actually contributed points,
    # and ML only if the model was confident about at least one destination.
    families = sorted({g.family.value for g in groups if g.points > 0 and _counts_as_family(g, cfg)})
    return Score(
        total=round(total, _SCORE_DECIMALS),
        groups=tuple(groups),
        families=tuple(families),
        handshake_confirmed=handshake,
        ml_points=round(ml_points, _SCORE_DECIMALS),
        ml_capped=ml_points < ml_raw,
    )
