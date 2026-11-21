"""Replay mode: run recorded evidence through the current policy, offline.

A fresh engine is built with an in-memory decision log, a simulated clock and
the dry_run driver, then fed the recorded events in time order with the same
30 s tick the live engine uses. Nothing is enforced and ips.db is not touched.
"""
from __future__ import annotations

import ipaddress
import json
import statistics
import time
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

import yaml

from .config import Config
from .enforcers.dry_run import DryRunEnforcer
from .engine import SUPERSEDED_PREFIX, Engine
from .enrichment import Enricher
from .models import ENFORCED_KINDS, ActionKind, Decision, Evidence, Family, TriageEvent
from .policy import Policy
from .scoring import rescale_probability
from .store import Store

NIDS_DB_NOTE = (
    "APPROXIMATE: the NIDS database keeps only the final count and the time of the last repeat for each "
    "alert row, so the timing of individual repeats is lost. Each row is replayed as one evidence record "
    "carrying its whole count at its last-seen time. Real-time scoring would have built up more gradually."
)
_ENFORCED_VALUES = frozenset(k.value for k in ENFORCED_KINDS)
_LABELS = ("attacker", "benign")


class SimClock:
    def __init__(self, now: float = 0.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


@dataclass(frozen=True)
class Label:
    network: ipaddress.IPv4Network | ipaddress.IPv6Network
    label: str
    start: float
    end: float

    def covers(self, ip: str, t: float) -> bool:
        return ipaddress.ip_address(ip) in self.network and self.start <= t <= self.end


def load_labels(path: str | Path) -> list[Label]:
    """Read a labels file: a list of {ip, label: attacker|benign, from, to} (YAML or JSON)."""
    with Path(path).open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if isinstance(data, dict):
        data = data.get("labels")
    if not isinstance(data, list):
        raise ValueError(f"{path}: expected a list of labels")
    labels = []
    for i, item in enumerate(data):
        if item.get("label") not in _LABELS:
            raise ValueError(f"{path}: entry {i}: label must be one of {_LABELS}")
        labels.append(Label(
            network=ipaddress.ip_network(str(item["ip"]), strict=False),
            label=item["label"],
            start=float(item.get("from", float("-inf"))),
            end=float(item.get("to", float("inf"))),
        ))
    return labels


def _event_time(ev: Evidence) -> float:
    return ev.received_at if ev.received_at > 0 else ev.last_seen


def run_replay(
    cfg: Config,
    enricher: Enricher,
    evidence: Iterable[Evidence],
    triage: Iterable[tuple[float, TriageEvent]] = (),
    *,
    source: str,
    approximate: bool = False,
    start: float | None = None,
    end: float | None = None,
    labels: list[Label] | None = None,
) -> dict:
    """Replay events through the current policy and return the report as a dict."""
    lo = start if start is not None else float("-inf")
    hi = end if end is not None else float("inf")
    # (time, order, kind, payload): evidence sorts before a triage event at the same instant.
    events: list[tuple[float, int, str, object]] = []
    for ev in evidence:
        t = _event_time(ev)
        if lo <= t <= hi:
            events.append((t, 0, ev.evidence_id, ev))
    for t, tr in triage:
        if lo <= t <= hi:
            events.append((t, 1, tr.evidence_id_prefix, tr))
    events.sort(key=lambda e: e[:3])

    clock = SimClock(events[0][0] if events else 0.0)
    store = Store(":memory:")
    enforcer = DryRunEnforcer(cfg.nftables, cfg.network.management_hosts, clock)
    engine = Engine(cfg, store, Policy(cfg, enricher), enricher, enforcer, clock)
    tick = cfg.engine.tick_seconds

    def advance(to: float) -> None:
        """Move the simulated clock forward, ticking like the live engine does."""
        while clock.now + tick <= to:
            if engine.idle():
                break                   # nothing can change until the next event
            clock.now += tick
            engine.tick()
        clock.now = to
        engine.expire_due()

    n_evidence = n_triage = 0
    for t, _, _, payload in events:
        advance(t)
        if isinstance(payload, Evidence):
            engine.ingest(replace(payload, received_at=0.0, while_blocked=False))
            n_evidence += 1
        else:
            engine.triage(payload)      # type: ignore[arg-type]
            n_triage += 1

    # Let everything play out: actions expire, evidence ages out of the window.
    if events:
        deadline = events[-1][0] + cfg.scoring.window_seconds + cfg.policy.long_block.ttl_seconds + tick
        while not engine.idle() and clock.now < deadline:
            clock.now += tick
            engine.tick()

    decisions = store.decisions()
    recorded = store.evidence_between(None, None)
    report = {
        "meta": {
            "source": source,
            "approximate": approximate,
            "note": NIDS_DB_NOTE if approximate else None,
            "from": events[0][0] if events else None,
            "to": events[-1][0] if events else None,
            "evidence_records": n_evidence,
            "triage_events": n_triage,
            "driver": enforcer.name,
            "generated_at": time.time(),
            "policy": {
                "window_seconds": cfg.scoring.window_seconds,
                "throttle_score": cfg.policy.throttle.score,
                "reset_score": cfg.policy.reset.score,
                "block_score": cfg.policy.block.score,
                "block_families": cfg.policy.block.families,
            },
        },
        "summary": _summary(decisions),
        "labels": _label_metrics(cfg, labels, decisions, recorded) if labels else None,
        "timelines": _timelines(decisions, recorded),
        "decisions": [_decision_dict(d) for d in decisions],
    }
    store.close()
    return report


def _decision_dict(d: Decision) -> dict:
    return {
        "decision_id": d.decision_id, "ip": d.ip, "created_at": d.created_at, "expires_at": d.expires_at,
        "target": d.target, "rung": d.rung, "kind": d.kind, "ttl": d.ttl, "score": d.score, "families": d.families,
        "technique": d.technique, "tactic": d.tactic, "d3fend": d.d3fend, "driver": d.driver,
        "driver_result": d.driver_result, "evidence_ids": d.evidence_ids, "reversed_at": d.reversed_at,
        "reversed_reason": d.reversed_reason, "parent_id": d.parent_id, "explanation": d.explanation,
    }


def _is_superseded(d: Decision) -> bool:
    return bool(d.reversed_reason and d.reversed_reason.startswith(SUPERSEDED_PREFIX))


def _summary(decisions: list[Decision]) -> dict:
    by_rung = {
        str(rung): {
            "decisions": sum(1 for d in decisions if d.rung == rung),
            "distinct_ips": len({d.ip for d in decisions if d.rung == rung}),
        }
        for rung in range(5)
    }
    by_kind: dict[str, int] = {}
    for d in decisions:
        by_kind[d.kind] = by_kind.get(d.kind, 0) + 1
    return {
        "decisions": len(decisions),
        "by_rung": by_rung,
        "by_kind": dict(sorted(by_kind.items())),
        "reversed_early": sum(1 for d in decisions if d.reversed_at is not None and not _is_superseded(d)),
        "superseded_by_stronger": sum(1 for d in decisions if _is_superseded(d)),
    }


def _timelines(decisions: list[Decision], recorded: list[Evidence]) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for ev in recorded:
        out.setdefault(ev.src_ip, []).append({
            "t": ev.received_at, "event": "evidence", "rule_id": ev.rule_id, "family": ev.family.value,
            "severity": ev.severity.value, "count": ev.count_delta, "while_blocked": ev.while_blocked,
        })
    for d in decisions:
        line = out.setdefault(d.ip, [])
        line.append({
            "t": d.created_at, "event": "decision", "decision_id": d.decision_id, "rung": d.rung, "kind": d.kind,
            "text": d.explanation.splitlines()[0] if d.explanation else "",
        })
        if d.reversed_at is not None:
            line.append({
                "t": d.reversed_at, "event": "superseded" if _is_superseded(d) else "reversed",
                "decision_id": d.decision_id, "text": d.reversed_reason,
            })
        elif d.ttl > 0 and d.kind in _ENFORCED_VALUES:
            line.append({"t": d.expires_at, "event": "expired", "decision_id": d.decision_id, "text": f"{d.kind} ended"})
    for line in out.values():
        line.sort(key=lambda e: e["t"])
    return dict(sorted(out.items()))


def _label_of(labels: list[Label], ip: str, t: float) -> str | None:
    return next((lab.label for lab in labels if lab.covers(ip, t)), None)


def _label_metrics(cfg: Config, labels: list[Label], decisions: list[Decision], recorded: list[Evidence]) -> dict:
    acted = [d for d in decisions if d.rung >= 1 and d.kind != ActionKind.OBSERVE.value]

    false_positives = [
        {"decision_id": d.decision_id, "ip": d.ip, "t": d.created_at, "rung": d.rung, "kind": d.kind,
         "text": d.explanation.splitlines()[0]}
        for d in acted if _label_of(labels, d.ip, d.created_at) == "benign"
    ]

    first_evidence: dict[str, float] = {}
    for ev in recorded:
        if _label_of(labels, ev.src_ip, ev.received_at) == "attacker":
            first_evidence[ev.src_ip] = min(first_evidence.get(ev.src_ip, ev.received_at), ev.received_at)
    time_to_action = []
    for ip, t0 in sorted(first_evidence.items()):
        first = min((d.created_at for d in acted if d.ip == ip and d.created_at >= t0), default=None)
        time_to_action.append({
            "ip": ip, "first_evidence_at": t0, "first_action_at": first,
            "seconds_to_first_action": round(first - t0, 2) if first is not None else None,
        })

    ml: dict[str, dict] = {}
    floor = cfg.scoring.ml.floor
    for label in _LABELS:
        records = [e for e in recorded if e.family is Family.ANOMALY_ML and _label_of(labels, e.src_ip, e.received_at) == label]
        probs = [e.ml_probability for e in records if e.ml_probability is not None]
        ips = {e.src_ip for e in records}
        peak = max((d.detail.get("ml_points", 0.0) for d in decisions if d.ip in ips), default=0.0)
        ml[label] = {
            "ml_evidence_records": len(records),
            "ml_alert_count": sum(e.count_delta for e in records),
            "distinct_ips": len(ips),
            "mean_probability": round(statistics.fmean(probs), 4) if probs else None,
            "mean_rescaled": round(statistics.fmean(rescale_probability(p, floor) for p in probs), 4) if probs else None,
            "max_probability": max(probs) if probs else None,
            "peak_ml_points_in_a_decision": peak,
        }

    return {"false_positive_actions": false_positives, "time_to_first_action": time_to_action, "ml_by_label": ml}


# ---------------------------------------------------------------------- text report
def _ts(t: float | None) -> str:
    if t is None:
        return "-"
    return f"{datetime.fromtimestamp(t, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}Z"


def render_text(report: dict) -> str:
    meta, summary = report["meta"], report["summary"]
    out = [
        "ACTIVE RESPONSE ENGINE - REPLAY REPORT",
        "=" * 38,
        f"Source:   {meta['source']}",
        f"Range:    {_ts(meta['from'])} to {_ts(meta['to'])}",
        f"Input:    {meta['evidence_records']} evidence record(s), {meta['triage_events']} triage event(s)",
        f"Driver:   {meta['driver']} (nothing was enforced)",
    ]
    if meta["approximate"]:
        out += ["", meta["note"]]

    out += ["", "SUMMARY PER RUNG", "-" * 16]
    names = {"0": "observe / log only", "1": "throttle or alert", "2": "reset", "3": "block or quarantine", "4": "long block"}
    for rung, row in summary["by_rung"].items():
        out.append(f"  rung {rung} ({names[rung]:<19}) {row['decisions']:>5} decision(s) on {row['distinct_ips']} IP(s)")
    out.append(f"  by action: " + (", ".join(f"{k}={v}" for k, v in summary["by_kind"].items()) or "none"))
    out.append(f"  lifted early (triage/manual): {summary['reversed_early']};  "
               f"replaced by a stronger action: {summary['superseded_by_stronger']}")

    labels = report.get("labels")
    if labels:
        out += ["", "AGAINST YOUR LABELS", "-" * 19]
        fps = labels["false_positive_actions"]
        out.append(f"  Actions against benign IPs (false positives): {len(fps)}")
        out += [f"    {_ts(f['t'])}  #{f['decision_id']}  {f['text']}" for f in fps]
        out.append("  Time from an attacker's first evidence to the first action:")
        for row in labels["time_to_first_action"]:
            took = f"{row['seconds_to_first_action']} s" if row["seconds_to_first_action"] is not None else "never acted on"
            out.append(f"    {row['ip']:<15} {took}")
        if not labels["time_to_first_action"]:
            out.append("    (no evidence from attacker-labelled IPs)")
        out.append("  How ML evidence scored:")
        for label, row in labels["ml_by_label"].items():
            out.append(
                f"    {label:<8} {row['ml_alert_count']} alert(s) from {row['distinct_ips']} IP(s), "
                f"mean probability {row['mean_probability']}, mean rescaled {row['mean_rescaled']}, "
                f"most ML points in any decision {row['peak_ml_points_in_a_decision']}"
            )

    out += ["", "TIMELINE PER IP", "-" * 15]
    for ip, line in report["timelines"].items():
        out.append(f"  {ip}")
        for e in line:
            if e["event"] == "evidence":
                flag = "  [while blocked]" if e["while_blocked"] else ""
                out.append(f"    {_ts(e['t'])}  evidence   {e['rule_id']} x{e['count']} ({e['family']}, {e['severity']}){flag}")
            else:
                out.append(f"    {_ts(e['t'])}  {e['event']:<10} #{e['decision_id']}  {e['text']}")
    if not report["timelines"]:
        out.append("  (no events in range)")

    out += ["", "EVERY EXPLANATION", "-" * 17]
    for d in report["decisions"]:
        out.append(f"#{d['decision_id']}  {_ts(d['created_at'])}  {d['ip']}")
        out += [f"    {line}" for line in d["explanation"].splitlines()]
        out.append("")
    return "\n".join(out).rstrip() + "\n"


def write_report(report: dict, out_dir: str | Path) -> tuple[Path, Path]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path, text_path = out_dir / "replay_report.json", out_dir / "replay_report.txt"
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    text_path.write_text(render_text(report), encoding="utf-8")
    return json_path, text_path
