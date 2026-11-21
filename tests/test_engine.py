from __future__ import annotations

from are.enforcers.base import EnforcerError
from are.enforcers.dry_run import DryRunEnforcer
from are.models import TriageEvent

from .conftest import ALLOWLISTED, ATTACKER, C2_SERVER, INTERNAL_HOST, Harness


def block_attacker(h: Harness) -> None:
    """Two families, handshake-confirmed, score 18: rung 3."""
    h.feed("TCP_CONNECT_SCAN", count=2, eid="nids:1:2")
    h.feed("Host Brute Force", family="host_sensor", technique="T1110", eid="nids:2:1")


def fp(prefix: str, at: float) -> TriageEvent:
    return TriageEvent("nids", prefix, "false_positive", "false_positive", at)


# ---- the ladder --------------------------------------------------------------
def test_ladder_climbs_one_action_at_a_time(harness):
    h = harness
    h.feed("TCP_SYN_SCAN", handshake=False)                                  # 6: throttle
    assert h.enforced() == {("throttle", ATTACKER)}
    h.feed("TCP_CONNECT_SCAN")                                               # 12, one family: reset
    assert h.enforced() == {("reset", ATTACKER)}
    h.feed("Host Brute Force", family="host_sensor", technique="T1110")      # 18, two families: block
    assert h.enforced() == {("block", ATTACKER)}

    throttle, reset, block = h.decisions(ATTACKER)
    assert [d.kind for d in (throttle, reset, block)] == ["throttle", "reset", "block"]
    assert [d.rung for d in (throttle, reset, block)] == [1, 2, 3]
    assert throttle.reversed_reason == f"superseded by decision #{reset.decision_id}"
    assert reset.reversed_reason == f"superseded by decision #{block.decision_id}"
    assert block.reversed_at is None and block.ttl == 900 and block.driver_result.startswith("ok")
    assert block.d3fend == "D3-ITF Inbound Traffic Filtering"


def test_low_score_is_observed_once_and_nothing_is_enforced(harness):
    harness.feed(severity="medium")
    harness.feed(severity="info", rule="OTHER")
    assert harness.kinds() == ["observe"] and harness.enforced() == set()


def test_more_evidence_at_the_same_rung_does_not_create_new_decisions(harness):
    harness.feed()
    harness.feed(rule="TCP_SYN_SCAN", severity="low", handshake=False)
    assert harness.kinds() == ["throttle"]


def test_duplicate_evidence_id_is_ignored(harness):
    ev = harness.feed(eid="nids:7:1")
    assert harness.engine.ingest(ev) is False
    assert harness.engine.stats["duplicate_evidence"] == 1


# ---- time --------------------------------------------------------------------
def test_block_runs_its_full_15_minutes_then_everything_decays(harness):
    block_attacker(harness)
    harness.advance(899)
    assert harness.enforced() == {("block", ATTACKER)}        # evidence left the 10 min window, block still holds
    harness.advance(2)
    assert harness.enforced() == set() and harness.engine.idle()
    assert harness.kinds(ATTACKER) == ["reset", "block"]      # no re-block, no extra decisions


def test_throttle_is_reapplied_at_expiry_only_while_evidence_supports_it(harness):
    harness.feed("TCP_SYN_SCAN", handshake=False)             # throttle at t0, 10 min
    harness.advance(300)
    harness.feed("TCP_FIN_SCAN", handshake=False)             # unconfirmed source: still rung 1, nothing new
    harness.advance(301)                                      # first throttle expired; newer evidence still in window
    assert harness.kinds() == ["throttle", "throttle"]
    harness.advance(700)
    assert harness.kinds() == ["throttle", "throttle"] and harness.engine.idle()


def test_rung_steps_down_when_a_stronger_action_expires(harness):
    h = harness
    h.feed(count=2)                                           # 12, one family: reset for 10 min
    h.advance(400)
    h.feed(rule="TCP_SYN_SCAN", handshake=False)              # 6 more; still rung 2, nothing new
    h.advance(201)                                            # reset expired; only the later 6 points remain
    assert h.kinds() == ["reset", "throttle"]


# ---- while_blocked and the long block ---------------------------------------
def test_evidence_while_blocked_is_recorded_but_cannot_extend_or_renew_the_block(harness):
    h = harness
    block_attacker(h)
    h.advance(800)
    during = [h.feed(count=4), h.feed("Host Brute Force", family="host_sensor", count=4)]
    stored = h.store.evidence_by_ids([e.evidence_id for e in during])
    assert all(e.while_blocked for e in stored)
    assert h.kinds(ATTACKER) == ["reset", "block"]

    h.advance(101)                                            # block over; that evidence is still in the window
    assert h.enforced() == set()
    last = h.decisions(ATTACKER)[-1]
    assert last.kind == "observe" and last.score == 0
    assert "While blocked: 8 further alert(s)" in last.explanation


def test_second_block_within_24h_is_a_two_hour_long_block(harness):
    h = harness
    block_attacker(h)
    h.advance(3600)
    h.feed("TCP_CONNECT_SCAN", count=2)
    h.feed("Host Brute Force", family="host_sensor", technique="T1110")
    long_block = h.decisions(ATTACKER)[-1]
    assert (long_block.rung, long_block.kind, long_block.ttl) == (4, "block", 7200)
    assert "Repeat offender" in long_block.explanation

    h.advance(7199)
    h.feed(count=4)                                           # still blocked: cannot extend the hard cap
    assert h.enforced() == {("block", ATTACKER)}
    h.advance(2)
    assert h.enforced() == set()


def test_first_block_is_forgotten_after_24h(harness):
    block_attacker(harness)
    harness.advance(86400 + 60)
    harness.feed("TCP_CONNECT_SCAN", count=2)
    harness.feed("Host Brute Force", family="host_sensor", technique="T1110")
    assert harness.decisions(ATTACKER)[-1].rung == 3


# ---- triage feedback ---------------------------------------------------------
def test_false_positive_lifts_the_block_and_falls_back_to_what_remains(harness):
    h = harness
    block_attacker(h)
    h.advance(60)
    h.engine.triage(fp("nids:2:", h.clock.now))               # the host-sensor alert was wrong

    block = next(d for d in h.decisions(ATTACKER) if d.kind == "block")
    assert block.reversed_at == h.clock.now
    assert "nids:2 marked false positive" in block.reversed_reason
    assert "supports rung 2, not 3" in block.reversed_reason
    assert block.explanation.splitlines()[-1].startswith("Reversed: triage")
    assert h.enforced() == {("reset", ATTACKER)}              # the scan evidence alone still supports rung 2
    assert h.store.evidence_by_ids(["nids:2:1"]) == []        # withdrawn, but still in the table
    assert len(h.store.evidence_by_ids(["nids:2:1"], valid_only=False)) == 1


def test_false_positive_on_minor_evidence_leaves_a_still_justified_block(harness):
    h = harness
    h.feed("TCP_FIN_SCAN", severity="low", handshake=False, eid="nids:9:1")
    block_attacker(h)
    h.engine.triage(fp("nids:9:", h.clock.now))
    assert h.enforced() == {("block", ATTACKER)}
    assert all(d.reversed_at is None for d in h.decisions(ATTACKER) if d.kind == "block")


def test_block_lifted_by_triage_does_not_count_towards_a_long_block(harness):
    h = harness
    block_attacker(h)
    h.engine.triage(fp("nids:1:", h.clock.now))
    h.engine.triage(fp("nids:2:", h.clock.now))
    assert h.enforced() == set()
    h.advance(1200)
    h.feed("TCP_CONNECT_SCAN", count=2)
    h.feed("Host Brute Force", family="host_sensor", technique="T1110")
    assert h.decisions(ATTACKER)[-1].rung == 3


def test_non_false_positive_verdicts_and_repeated_events_change_nothing(harness):
    h = harness
    block_attacker(h)
    h.engine.triage(TriageEvent("nids", "nids:2:", "other", "confirmed", h.clock.now))
    event = fp("nids:404:", h.clock.now)
    h.engine.triage(event)
    h.engine.triage(event)
    assert h.enforced() == {("block", ATTACKER)} and h.engine.stats["triage_events"] == 2


def test_manual_unblock_lifts_and_does_not_snap_back(harness):
    h = harness
    block_attacker(h)
    lifted = h.engine.manual_unblock(ATTACKER, who="tester")
    assert len(lifted) == 1 and h.enforced() == set()
    h.advance(60)                                             # ticks must not re-block from the same evidence
    assert h.enforced() == set()
    assert "manual unblock by tester" in h.decisions(ATTACKER)[-1].reversed_reason


# ---- targets -----------------------------------------------------------------
def test_allowlisted_ip_is_logged_once_and_never_acted_on(harness):
    for _ in range(3):
        harness.feed(src=ALLOWLISTED, severity="critical", count=8)
    (d,) = harness.decisions(ALLOWLISTED)
    assert d.target == "allowlisted" and harness.enforced() == set()
    assert d.explanation == f"{ALLOWLISTED} is allowlisted (10.0.0.1/32): evidence logged, no action taken."


def test_alert_only_evidence_raises_one_alert_and_enforces_nothing(harness):
    h = harness
    for _ in range(3):
        h.feed("MITM_ARP_SPOOF", severity="critical", technique="T1557.002", handshake=False, count=5)
    (d,) = h.decisions(ATTACKER)
    assert (d.target, d.kind, d.driver_result) == ("alert_only", "alert", "not_enforced")
    assert "cannot be solved by blocking an IP address" in d.explanation and h.enforced() == set()


def test_internal_host_rung_1_alerts_without_enforcing(harness):
    harness.feed(src=INTERNAL_HOST)
    (d,) = harness.decisions(INTERNAL_HOST)
    assert (d.target, d.kind, d.rung, d.driver) == ("quarantine_src", "alert", 1, "none")
    assert harness.enforced() == set()


def test_compromised_internal_host_is_quarantined_and_its_c2_destination_blocked(harness):
    h = harness
    h.feed("BEHAVIOR_C2_BEACON", INTERNAL_HOST, family="net_behavior", technique="T1071", dst=C2_SERVER, count=2,
           eid="nids:20:2")
    assert h.enforced() == {("reset", INTERNAL_HOST), ("block_dst", C2_SERVER)}
    h.feed("Root Access", INTERNAL_HOST, family="host_sensor", severity="critical", technique="T1548", eid="nids:21:1")
    assert h.enforced() == {("quarantine", INTERNAL_HOST), ("block_dst", C2_SERVER)}

    dst = h.decisions(C2_SERVER)[0]
    assert dst.kind == "block_dst" and dst.parent_id == h.decisions(INTERNAL_HOST)[0].decision_id
    assert dst.d3fend == "D3-OTF Outbound Traffic Filtering"
    quarantine = h.decisions(INTERNAL_HOST)[-1]
    assert "except to the management host" in quarantine.explanation
    assert "Tactic: Command and Control (T1071 Application Layer Protocol)" in quarantine.explanation

    h.engine.triage(fp("nids:20:", h.clock.now))              # the beacon alert was a false positive
    assert ("block_dst", C2_SERVER) not in h.enforced()
    assert ("quarantine", INTERNAL_HOST) not in h.enforced()


# ---- driver failures and restart --------------------------------------------
class FlakyEnforcer(DryRunEnforcer):
    def __init__(self, *args, failures: int, **kw):
        super().__init__(*args, **kw)
        self.failures = failures

    def apply(self, action):
        if self.failures > 0:
            self.failures -= 1
            raise EnforcerError("nft: Operation not permitted")
        return super().apply(action)


def test_driver_failure_goes_into_the_decision_log_and_is_retried_on_the_next_tick(cfg, enricher):
    h = Harness(cfg, enricher)
    h.enforcer = FlakyEnforcer(cfg.nftables, cfg.network.management_hosts, h.clock, failures=1)
    h.engine.enforcer = h.enforcer
    h.feed()
    h.feed(rule="TCP_FIN_SCAN", severity="low", handshake=False)      # new evidence must not hammer the driver
    (failed,) = h.decisions(ATTACKER)
    assert failed.driver_result == "error: nft: Operation not permitted"
    assert failed.explanation.startswith("NOT ENFORCED: the dry_run driver failed (nft: Operation not permitted)")
    assert h.enforced() == set()

    h.advance(30)
    assert h.kinds(ATTACKER) == ["throttle", "throttle"]
    assert h.decisions(ATTACKER)[-1].driver_result.startswith("ok") and h.enforced() == {("throttle", ATTACKER)}


def test_restart_restores_state_and_reasserts_active_actions(cfg, enricher):
    first = Harness(cfg, enricher)
    block_attacker(first)
    first.advance(100)

    second = Harness(cfg, enricher, store=first.store, start=first.clock.now)     # new process, same ips.db
    assert second.enforced() == set()
    second.engine.restore()
    assert second.enforced() == {("block", ATTACKER)}
    (entry,) = second.enforcer.list_active()
    assert 795 <= entry.remaining_seconds <= 800                                    # the remaining time, not a fresh 15 min

    second.advance(801)                                                             # block expired
    second.feed("TCP_CONNECT_SCAN", count=2)
    second.feed("Host Brute Force", family="host_sensor", technique="T1110")
    assert second.decisions(ATTACKER)[-1].rung == 4                                 # block history survived the restart


def test_snapshot_and_status_are_read_only(harness):
    harness.feed(count=2)
    snap = harness.engine.snapshot(ATTACKER)
    assert snap["rung"] == 2 and snap["score"] == 12 and snap["active"][0]["kind"] == "reset"
    assert harness.engine.status()["active_actions"] == 1
    assert harness.kinds() == ["reset"]
