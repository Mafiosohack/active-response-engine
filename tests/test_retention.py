"""ips.db retention: old rows are deleted, anything the engine still needs is kept."""
from __future__ import annotations

import json
from dataclasses import replace

import pytest
from pydantic import ValidationError

from are.app import PRUNE_INTERVAL_SECONDS, Runtime, Service
from are.config import Config
from are.models import Decision, TriageEvent
from are.store import Store

from .conftest import ATTACKER, Harness, make_ev

DAY = 86400.0
NOW = 100 * DAY
CUTOFF = NOW - 30 * DAY


def _decision(created_at: float, expires_at: float) -> Decision:
    return Decision(ip=ATTACKER, target="external", rung=3, kind="block", ttl=int(expires_at - created_at),
                    created_at=created_at, expires_at=expires_at, evidence_ids=[], score=12.0, families=["net_signature"],
                    driver="dry_run", driver_result="ok")


def _add_evidence(store: Store, eid: str, at: float) -> None:
    store.add_evidence(replace(make_ev(at=at, eid=eid), received_at=at))


def _evidence_ids(store: Store) -> list[str]:
    return [e.evidence_id for e in store.evidence_between(None, None)]


# ---- Store.prune ---------------------------------------------------------------
def test_prune_deletes_rows_older_than_the_cutoff_and_keeps_newer_ones():
    store = Store(":memory:")
    _add_evidence(store, "old", CUTOFF - 1)
    _add_evidence(store, "recent", CUTOFF + 1)
    store.add_triage(TriageEvent("nids", "nids:1:", "false_positive", "false_positive", CUTOFF - 5), CUTOFF - 1)
    store.add_triage(TriageEvent("nids", "nids:2:", "false_positive", "false_positive", CUTOFF + 5), CUTOFF + 1)
    old_id = store.add_decision(_decision(CUTOFF - 1000, CUTOFF - 100))
    recent_id = store.add_decision(_decision(CUTOFF + 100, CUTOFF + 1000))

    removed = store.prune(before=CUTOFF, now=NOW)

    assert removed == {"evidence": 1, "triage_events": 1, "decisions": 1}
    assert _evidence_ids(store) == ["recent"]
    assert [e.evidence_id_prefix for _, e in store.triage_between(None, None)] == ["nids:2:"]
    assert store.get_decision(old_id) is None and store.get_decision(recent_id) is not None


def test_prune_keeps_a_decision_that_is_still_in_force():
    store = Store(":memory:")
    active_id = store.add_decision(_decision(CUTOFF - 10, NOW + 60))      # older than the cutoff, not yet expired

    removed = store.prune(before=CUTOFF, now=NOW)

    assert removed["decisions"] == 0
    assert [d.decision_id for d in store.active_decisions(NOW)] == [active_id]


def test_prune_keeps_old_evidence_that_was_seen_again_recently():
    store = Store(":memory:")
    # last_seen is after the cutoff even though the record arrived before it
    store.add_evidence(replace(make_ev(at=CUTOFF + 1, eid="seen-again"), received_at=CUTOFF - 1))

    assert store.prune(before=CUTOFF, now=NOW)["evidence"] == 0


def test_prune_never_touches_the_adapter_bookmarks():
    store = Store(":memory:")
    store.set_states({"nids:cursor": 123.0, "nids:row:0:7": {"c": 4}})

    store.prune(before=CUTOFF, now=NOW)

    assert store.get_state("nids:cursor") == 123.0 and store.get_state("nids:row:0:7") == {"c": 4}


# ---- config --------------------------------------------------------------------
def test_shipped_config_keeps_thirty_days(cfg):
    assert cfg.engine.retention_days == 30


def test_retention_can_be_switched_off_with_null(cfg_dict):
    cfg_dict["engine"]["retention_days"] = None
    assert Config.model_validate(cfg_dict).engine.retention_days is None


@pytest.mark.parametrize("days", [0, -1, 0.5])
def test_config_rejects_retention_shorter_than_what_the_engine_still_reads(cfg_dict, days):
    # 0.5 days is shorter than the 24 h repeat-offender memory: a long block would never be reached.
    bad = json.loads(json.dumps(cfg_dict))
    bad["engine"]["retention_days"] = days
    with pytest.raises(ValidationError):
        Config.model_validate(bad)


def test_config_rejects_retention_shorter_than_the_longest_action(cfg_dict):
    bad = json.loads(json.dumps(cfg_dict))
    bad["engine"]["retention_days"] = 1
    bad["policy"]["long_block"]["ttl_seconds"] = 2 * 86400       # evidence of a live block would be deleted
    with pytest.raises(ValidationError):
        Config.model_validate(bad)


# ---- the live loop --------------------------------------------------------------
def _service(cfg, enricher, start: float = NOW) -> tuple[Service, Harness]:
    h = Harness(cfg, enricher, start=start)
    return Service(Runtime(cfg, h.store, enricher, h.enforcer, h.engine, adapters=[])), h


def test_service_prunes_on_its_first_step_and_then_once_an_hour(cfg, enricher):
    service, h = _service(cfg, enricher)
    _add_evidence(h.store, "old-1", NOW - 31 * DAY)

    service.step()
    assert _evidence_ids(h.store) == []

    _add_evidence(h.store, "old-2", NOW - 31 * DAY)
    service.step()                                               # same hour: not yet
    assert _evidence_ids(h.store) == ["old-2"]

    h.clock.now += PRUNE_INTERVAL_SECONDS
    service.step()
    assert _evidence_ids(h.store) == []


def test_service_keeps_everything_when_retention_is_off(cfg_dict, enricher):
    cfg_dict["engine"]["retention_days"] = None
    service, h = _service(Config.model_validate(cfg_dict), enricher)
    _add_evidence(h.store, "ancient", NOW - 400 * DAY)

    service.step()

    assert _evidence_ids(h.store) == ["ancient"]
