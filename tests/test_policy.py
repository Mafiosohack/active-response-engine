from __future__ import annotations

from are.models import ActionKind, Target

from .conftest import ALLOWLISTED, ATTACKER, C2_SERVER, INTERNAL_HOST, make_ev

TWO_FAMILIES = [
    make_ev("TCP_CONNECT_SCAN", count=2),                                             # 12 points
    make_ev("Host Brute Force", family="host_sensor", technique="T1110"),             # 6 points
]


def assess(policy, evidence, ip=ATTACKER, prior=0):
    return policy.assess(ip, evidence, prior)


# ---- rung thresholds ---------------------------------------------------------
def test_rung_0_observe_below_throttle_score(policy):
    a = assess(policy, [make_ev(severity="medium")])
    assert (a.rung, a.kind) == (0, ActionKind.OBSERVE)
    assert a.why_not_higher == "Not rung 1: score 3 is below 4."


def test_rung_1_throttle(policy):
    a = assess(policy, [make_ev()])
    assert (a.rung, a.kind, a.ttl) == (1, ActionKind.THROTTLE, 600)
    assert a.why_not_higher == "Not rung 2: score 6 is below 8."


def test_rung_2_reset_needs_score_and_handshake(policy):
    a = assess(policy, [make_ev(count=2)])
    assert (a.rung, a.kind, a.ttl) == (2, ActionKind.RESET, 600)
    assert a.why_not_higher == "Not rung 3: only 1 independent family, 2 needed."


def test_rung_3_block_needs_two_families(policy):
    a = assess(policy, TWO_FAMILIES)
    assert (a.rung, a.kind, a.ttl) == (3, ActionKind.BLOCK, 900)
    assert a.why_not_higher == "Not rung 4: first block for this IP in 24 h."


def test_many_alerts_from_one_family_never_block(policy):
    evidence = [make_ev(f"EXPLOIT_{i}", severity="critical", technique="T1190") for i in range(6)]
    a = assess(policy, evidence)
    assert a.score.total == 60 and a.rung == 2


def test_rung_4_on_second_block_within_24h_is_capped_at_two_hours(policy):
    a = assess(policy, TWO_FAMILIES, prior=1)
    assert (a.rung, a.kind, a.ttl) == (4, ActionKind.BLOCK, 7200)


# ---- spoof guard -------------------------------------------------------------
def test_spoof_guard_caps_unconfirmed_sources_at_rung_1(policy):
    evidence = [
        make_ev("TCP_SYN_SCAN", count=4, handshake=False),
        make_ev("FLOOD_SYN", family="net_behavior", severity="critical", count=4, handshake=False, technique="T1498"),
    ]
    a = assess(policy, evidence)
    assert a.score.total >= 12 and len(a.score.families) == 2
    assert a.rung == 1
    assert "may be forged" in a.why_not_higher


# ---- ML ----------------------------------------------------------------------
def test_ml_alone_never_goes_past_throttle(policy):
    evidence = [make_ev("ML_FLOW_ANOMALY", family="anomaly_ml", prob=1.0, count=500, handshake=False,
                        technique=None, dst=f"10.0.0.{i}") for i in range(2, 10)]
    a = assess(policy, evidence)
    assert a.rung == 1 and a.target is Target.BLOCK_SRC and a.tactic is None


def test_internal_source_with_ml_only_uses_the_block_ladder_by_score(policy):
    a = assess(policy, [make_ev("ML_FLOW_ANOMALY", family="anomaly_ml", prob=1.0, handshake=False, technique=None)],
               ip=INTERNAL_HOST)
    assert a.target is Target.BLOCK_SRC and a.kind is ActionKind.THROTTLE


# ---- correlation -------------------------------------------------------------
def corr(stages, handshake=True):
    return make_ev("CORRELATED_INCIDENT", family="correlation", stages=stages, technique=None, handshake=handshake)


def test_forward_progression_raises_the_rung_by_one(policy):
    a = assess(policy, [make_ev(count=2), corr(("reconnaissance", "privilege_escalation"))])
    assert a.rung == 3 and a.kind is ActionKind.BLOCK       # 2 -> 3 with a single family
    assert any("rung raised from 2 to 3" in n for n in a.notes)


def test_progression_uses_the_nids_stage_order(policy):
    # credential_access precedes initial_access in the NIDS kill chain (it is the reverse in ATT&CK's matrix).
    assert assess(policy, [make_ev(), corr(("credential_access", "initial_access"))]).rung == 2


def test_backward_or_single_stage_incident_does_not_raise(policy):
    assert assess(policy, [make_ev(), corr(("exfiltration", "reconnaissance"))]).rung == 1
    assert assess(policy, [make_ev(), corr(("reconnaissance",))]).rung == 1


def test_correlation_never_lifts_a_single_family_above_rung_3(policy):
    # One family reached rung 3 only because of the incident; even a repeat offender stays at 3.
    a = assess(policy, [make_ev(count=2), corr(("reconnaissance", "initial_access"))], prior=1)
    assert a.rung == 3


def test_correlation_raises_a_two_family_block_to_rung_4(policy):
    assert assess(policy, TWO_FAMILIES + [corr(("reconnaissance", "initial_access"))]).rung == 4


def test_correlation_cannot_beat_the_spoof_guard(policy):
    a = assess(policy, [make_ev(count=2, handshake=False), corr(("reconnaissance", "initial_access"), handshake=False)])
    assert a.rung == 1


# ---- response target ---------------------------------------------------------
def test_external_source_gets_the_block_ladder(policy):
    assert assess(policy, TWO_FAMILIES).target is Target.BLOCK_SRC


def test_internal_source_gets_the_quarantine_ladder(policy):
    low = assess(policy, [make_ev(src=INTERNAL_HOST)], ip=INTERNAL_HOST)
    assert (low.target, low.rung, low.kind) == (Target.QUARANTINE_SRC, 1, ActionKind.ALERT)
    high = assess(policy, [make_ev(src=INTERNAL_HOST, count=2),
                           make_ev("Root Access", INTERNAL_HOST, family="host_sensor", technique="T1548")],
                  ip=INTERNAL_HOST)
    assert (high.rung, high.kind) == (3, ActionKind.QUARANTINE)


def test_internal_c2_also_blocks_the_external_destination(policy):
    ev = make_ev("BEHAVIOR_C2_BEACON", INTERNAL_HOST, family="net_behavior", technique="T1071", dst=C2_SERVER, count=2)
    a = assess(policy, [ev], ip=INTERNAL_HOST)
    assert (a.target, a.rung, a.kind) == (Target.QUARANTINE_SRC, 2, ActionKind.RESET)
    assert a.block_dst == {C2_SERVER: (ev.evidence_id,)}


def test_block_dst_skips_internal_and_allowlisted_destinations_and_low_rungs(policy):
    def beacon(dst, count=2):
        return make_ev("BEHAVIOR_C2_BEACON", INTERNAL_HOST, family="net_behavior", technique="T1071", dst=dst, count=count)

    assert assess(policy, [beacon("10.0.0.9")], ip=INTERNAL_HOST).block_dst == {}
    assert assess(policy, [beacon("198.51.100.53")], ip=INTERNAL_HOST).block_dst == {}      # allowlisted DNS
    assert assess(policy, [beacon(C2_SERVER, count=1)], ip=INTERNAL_HOST).block_dst == {}   # rung 1 only alerts


def test_non_quarantine_tactic_from_internal_host_does_not_block_destination(policy):
    a = assess(policy, [make_ev(src=INTERNAL_HOST, count=2, dst=C2_SERVER)], ip=INTERNAL_HOST)   # discovery
    assert a.target is Target.QUARANTINE_SRC and a.block_dst == {}


def test_multi_tactic_technique_uses_the_configured_primary_tactic(policy):
    a = assess(policy, [make_ev("SSH Login", family="host_sensor", technique="T1078")])
    assert a.tactic == "initial-access"


# ---- alert-only and allowlist ------------------------------------------------
def test_alert_only_evidence_is_split_off_and_never_scored(policy):
    arp = make_ev("MITM_ARP_SPOOF", severity="critical", technique="T1557.002", handshake=False)
    travel = make_ev("Impossible Travel", family="host_sensor", technique="T1078")
    a = assess(policy, [arp, travel])
    assert {e.rule_id for e in a.alert_only} == {"MITM_ARP_SPOOF", "Impossible Travel"}
    assert a.score.total == 0 and a.rung == 0 and not a.has_scorable_evidence


def test_allowlist_and_internal_lookup(policy):
    assert policy.allowlisted_by(ALLOWLISTED) == "10.0.0.1/32"
    assert policy.allowlisted_by(ATTACKER) is None
    assert policy.is_internal(INTERNAL_HOST) and not policy.is_internal(ATTACKER)


# ---- other guards ------------------------------------------------------------
def test_while_blocked_evidence_is_counted_but_not_scored(policy):
    a = assess(policy, [make_ev(count=2, while_blocked=True),
                        make_ev("Host Brute Force", family="host_sensor", count=3, while_blocked=True)])
    assert a.score.total == 0 and a.rung == 0 and a.while_blocked_count == 5


def test_ipv6_source_is_observed_only(policy):
    ip = "2001:db8::9"
    a = assess(policy, [make_ev(src=ip, count=2), make_ev("Host Brute Force", ip, family="host_sensor")], ip=ip)
    assert a.rung == 0 and "IPv6" in a.why_not_higher


def test_honeypot_contact_alone_reaches_rung_3(policy):
    a = assess(policy, [make_ev("HONEYPOT_CONTACT", family="honeypot", severity="low", technique=None)])
    assert a.rung == 3 and a.kind is ActionKind.BLOCK


# ---- ML family cut-off -------------------------------------------------------
EXPLOIT_X4 = make_ev("EXPLOIT_SAMBA_USERMAP", technique="T1190", count=4)            # 18 points, one family


def test_faint_ml_does_not_turn_a_reset_into_a_block(policy):
    a = assess(policy, [EXPLOIT_X4, make_ev("ML_FLOW_ANOMALY", family="anomaly_ml", prob=0.51, handshake=False,
                                            technique=None)])
    assert (a.rung, a.kind) == (2, ActionKind.RESET)
    assert a.why_not_higher == ("Not rung 3: only 1 independent family, 2 needed "
                                "(ML evidence below probability 0.8 does not count as one).")


def test_confident_ml_is_a_second_family_and_blocks(policy):
    a = assess(policy, [EXPLOIT_X4, make_ev("ML_FLOW_ANOMALY", family="anomaly_ml", prob=0.95, severity="high",
                                            handshake=False, technique=None)])
    assert (a.rung, a.kind) == (3, ActionKind.BLOCK)


def test_traffic_anomaly_without_a_probability_is_not_a_family(policy):
    # The adapter gives a medium row with no probability 0.65 (ml_severity_fallback).
    a = assess(policy, [EXPLOIT_X4, make_ev("ANOMALY_TRAFFIC_BASELINE", family="anomaly_ml", severity="medium",
                                            prob=0.65, handshake=False, technique=None, dst=None)])
    assert a.rung == 2 and a.score.families == ("net_signature",)


# ---- progression from the source's own alerts ---------------------------------
# The NIDS announces a correlated incident once, when it opens, so later stages
# never reach the engine that way. The engine also reads the stage of each alert.
def staged(rule, stage, at, technique="T1046", handshake=True, **kw):
    return make_ev(rule, stage=stage, at=at, technique=technique, handshake=handshake, **kw)


SCAN = dict(rule="TCP_CONNECT_SCAN", stage="reconnaissance")
EXPLOIT = dict(rule="EXPLOIT_SAMBA_USERMAP", stage="initial_access", technique="T1190")


def test_own_alerts_moving_forward_raise_the_rung_by_one(policy):
    a = assess(policy, [staged(at=1000.0, **SCAN), staged(at=1010.0, **EXPLOIT)])     # 12 points, one family
    assert a.rung == 3 and a.kind is ActionKind.BLOCK
    assert any("own alerts" in n and "reconnaissance -> initial_access" in n and "rung raised from 2 to 3" in n
               for n in a.notes)


def test_own_alerts_in_reverse_order_do_not_raise(policy):
    assert assess(policy, [staged(at=1010.0, **SCAN), staged(at=1000.0, **EXPLOIT)]).rung == 2


def test_own_alerts_at_one_stage_do_not_raise(policy):
    assert assess(policy, [staged(at=1000.0, **SCAN), staged("TCP_SYN_SCAN", "reconnaissance", 1010.0)]).rung == 2


def test_an_unconfirmed_advance_does_not_raise(policy):
    # Forged exploit packets naming the scanner must not fake an advance.
    a = assess(policy, [staged(at=1000.0, **SCAN), staged(at=1010.0, handshake=False, **EXPLOIT)])
    assert a.rung == 2


def test_own_progression_and_a_correlated_incident_raise_only_once(policy):
    a = assess(policy, [staged(at=1000.0, **SCAN), staged(at=1010.0, **EXPLOIT),
                        corr(("reconnaissance", "initial_access"))], prior=1)
    assert a.rung == 3        # one family: progression may stand in for the second up to rung 3, once


def test_progression_from_alerts_can_be_switched_off(cfg_dict, enricher):
    from are.config import Config
    from are.policy import Policy

    cfg_dict["policy"]["progression_from_alerts"] = False
    off = Policy(Config.model_validate(cfg_dict), enricher)
    assert assess(off, [staged(at=1000.0, **SCAN), staged(at=1010.0, **EXPLOIT)]).rung == 2
