"""Plain-English explanations, generated from the decision record and nothing else.

There is no free text here: the same Decision always produces the same words,
so an explanation can be regenerated from the decision log at any time.
"""
from __future__ import annotations

from .models import ActionKind, Decision, Target

FAMILY_LABELS = {
    "net_signature": "network signature",
    "net_behavior": "network behavior",
    "anomaly_ml": "ML anomaly",
    "host_sensor": "host sensor",
    "cloud_sensor": "cloud sensor",
    "honeypot": "honeypot",
}

_SECONDS_PER_MINUTE = 60
_SECONDS_PER_HOUR = 3600
_ERROR_PREFIX = "error: "


def fmt_number(value: float) -> str:
    return f"{value:.1f}".rstrip("0").rstrip(".")


def fmt_duration(seconds: float) -> str:
    seconds = int(round(seconds))
    if seconds >= _SECONDS_PER_HOUR and seconds % _SECONDS_PER_HOUR == 0:
        return f"{seconds // _SECONDS_PER_HOUR} h"
    if seconds >= _SECONDS_PER_MINUTE and seconds % _SECONDS_PER_MINUTE == 0:
        return f"{seconds // _SECONDS_PER_MINUTE} min"
    return f"{seconds} s"


def _headline(d: Decision) -> str:
    """What was done."""
    dur = fmt_duration(d.ttl)
    detail = d.detail
    if d.target == Target.ALLOWLISTED.value:
        return f"{d.ip} is allowlisted ({detail.get('cidr', 'allowlist')}): evidence logged, no action taken."
    if d.target == Target.ALERT_ONLY.value:
        info = detail.get("alert_only", {})
        what = info.get("rule_id", "this alert")
        if info.get("technique"):
            what += f" ({' '.join(x for x in (info['technique'], info.get('technique_name')) if x)})"
        return (f"Alert only for {d.ip}: {what} x{info.get('count', 1)} cannot be solved by blocking an IP address. "
                f"High-priority alert raised, nothing enforced.")
    kind = d.kind
    if kind == ActionKind.OBSERVE.value:
        return f"Observing {d.ip} (rung {d.rung}): logged, no action."
    if kind == ActionKind.ALERT.value:
        return f"High-priority alert for internal host {d.ip} (rung {d.rung}): logged, nothing enforced yet."
    if kind == ActionKind.THROTTLE.value:
        return f"Throttled {d.ip} to {detail.get('throttle_rate', '?')} packets/s for {dur} (rung {d.rung})."
    if kind == ActionKind.RESET.value:
        return f"Resetting TCP connections of {d.ip} for {dur} (rung {d.rung}); its other traffic is dropped."
    if kind == ActionKind.BLOCK.value:
        return f"Blocked {d.ip} for {dur} (rung {d.rung})."
    if kind == ActionKind.QUARANTINE.value:
        return (f"Quarantined internal host {d.ip} for {dur} (rung {d.rung}): "
                f"its forwarded traffic is dropped except to the management host.")
    if kind == ActionKind.BLOCK_DST.value:
        parent = detail.get("companion_of", {})
        return (f"Blocked traffic to external destination {d.ip} for {dur}, "
                f"alongside decision #{parent.get('decision_id', '?')} on {parent.get('src_ip', '?')}.")
    return f"{kind} on {d.ip} (rung {d.rung})."


def _group_text(group: dict) -> str:
    text = f"{group['rule_id']} x{group['count']}"
    if group.get("kind") != "ml":
        return text
    if group.get("dst_ip"):
        text += f" to {group['dst_ip']}"
    if group.get("max_probability") is not None:
        text += f", max probability {group['max_probability']:.2f}"
    if group.get("ml_attack_type"):
        text += f", model says {group['ml_attack_type']}"
    return text


def _score_line(d: Decision) -> str:
    groups = d.detail.get("groups", [])
    if not groups:
        return f"Score {fmt_number(d.score)}: no scoring evidence in the window."
    # ML that scored but stayed below the family cut-off is listed apart, so the
    # families named match the count.
    ml_aside = [g for g in groups if g.get("kind") == "ml" and g["family"] not in d.families and g["points"] > 0]
    by_family: dict[str, list[str]] = {}
    for g in groups:
        if g not in ml_aside:
            by_family.setdefault(g["family"], []).append(_group_text(g))
    listed = ", ".join(f"{FAMILY_LABELS.get(fam, fam)} ({'; '.join(items)})" for fam, items in by_family.items())
    n = len(d.families)
    noun = "independent family" if n == 1 else "independent families"
    line = f"Score {fmt_number(d.score)} from {n} {noun}: {listed}."
    if ml_aside:
        cut_off = d.detail.get("ml_family_min_probability")
        why = f"because it is below probability {cut_off:g}" if cut_off is not None else "by the policy"
        items = "; ".join(_group_text(g) for g in ml_aside)
        line += f" Also scored: {FAMILY_LABELS['anomaly_ml']} ({items}), not counted as a family {why}."
    if any(g.get("kind") == "ml" for g in groups):
        line += f" ML evidence is a ranking signal only and adds at most {fmt_number(d.detail.get('ml_cap', 0))} points"
        line += " (cap reached)." if d.detail.get("ml_capped") else "."
    return line


def _tactic_line(d: Decision) -> str:
    if d.tactic:
        tactic = d.detail.get("tactic_name") or d.tactic
        technique = " ".join(x for x in (d.technique, d.detail.get("technique_name")) if x)
        line = f"Tactic: {tactic} ({technique})."
    else:
        line = "Tactic: none (no ATT&CK technique for the strongest evidence; decided by score only)."
    counter = d.detail.get("d3fend")
    if counter:
        line += f" Countermeasure: {counter['name'].lower()} (D3FEND {counter['id']}, a suggestion)."
    return line


def explain(d: Decision) -> str:
    """Build the explanation: what was done, score and families, tactic and
    countermeasure, and why not one rung higher."""
    lines = []
    if d.driver_result.startswith(_ERROR_PREFIX):
        lines.append(
            f"NOT ENFORCED: the {d.driver} driver failed ({d.driver_result[len(_ERROR_PREFIX):]}). "
            f"The intended action was:"
        )
    lines.append(_headline(d))

    if d.target not in (Target.ALLOWLISTED.value, Target.ALERT_ONLY.value):
        lines.append(_score_line(d))
        lines.append(_tactic_line(d))
        lines.extend(d.detail.get("notes", []))
        blocked = d.detail.get("while_blocked_count", 0)
        if blocked:
            lines.append(
                f"While blocked: {blocked} further alert(s) were recorded; "
                f"they do not count towards a new or longer block."
            )
        if d.detail.get("why_not_higher"):
            lines.append(d.detail["why_not_higher"])

    if d.reversed_at is not None:
        lines.append(f"Reversed: {d.reversed_reason or 'no reason recorded'}.")
    return "\n".join(lines)
