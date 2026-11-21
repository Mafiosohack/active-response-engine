from __future__ import annotations

import sqlite3

from are.store import Store

from .conftest import make_ev


def test_evidence_stage_round_trips_through_ips_db():
    store = Store(":memory:")
    ev = make_ev(stage="initial_access", eid="t:1:1")
    store.add_evidence(ev)
    (back,) = store.evidence_by_ids(["t:1:1"])
    assert back.stage == "initial_access"


def test_an_ips_db_from_before_stages_is_upgraded_in_place(tmp_path):
    path = str(tmp_path / "ips.db")
    old = make_ev(eid="old:1:1")
    store = Store(path)
    store.add_evidence(old)
    store.close()
    with sqlite3.connect(path) as conn:          # the evidence table as version 1 created it
        conn.execute("ALTER TABLE evidence DROP COLUMN stage")

    store = Store(path)
    store.add_evidence(make_ev(stage="reconnaissance", eid="new:1:1"))
    stages = {e.evidence_id: e.stage for e in store.evidence_by_ids(["old:1:1", "new:1:1"])}
    assert stages == {"old:1:1": None, "new:1:1": "reconnaissance"}
