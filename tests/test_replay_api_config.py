from __future__ import annotations

import ast
import json
from dataclasses import replace
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient
from pydantic import ValidationError

from are.__main__ import main
from are.adapters import MemoryState, build_nids_adapter
from are.api import create_app
from are.config import Config, load_config
from are.models import TriageEvent
from are.replay import NIDS_DB_NOTE, load_labels, render_text, run_replay, write_report
from are.store import Store

from .conftest import ATTACKER, PROJECT_ROOT, Harness, make_ev

BENIGN = "203.0.113.50"
TOKEN = "t" * 40


def scenario():
    """An attacker who escalates to a block, and a benign host with one ML alert."""
    return [
        make_ev("TCP_SYN_SCAN", at=1000.0, handshake=False, eid="nids:1:1"),
        make_ev("ML_FLOW_ANOMALY", family="anomaly_ml", prob=0.95, at=1010.0, handshake=False, technique=None, eid="nids:2:1"),
        make_ev("TCP_CONNECT_SCAN", at=1020.0, count=2, eid="nids:3:2"),
        make_ev("Host Brute Force", family="host_sensor", technique="T1110", at=1040.0, eid="nids:4:1"),
        make_ev("TCP_CONNECT_SCAN", at=1500.0, count=3, eid="nids:3:5"),                       # while blocked
        make_ev("ML_FLOW_ANOMALY", BENIGN, family="anomaly_ml", prob=0.62, at=1100.0, handshake=False,
                technique=None, eid="nids:5:1"),
        make_ev("BRUTEFORCE_STANDARD_RATE", BENIGN, family="net_behavior", technique="T1110", at=1200.0, eid="nids:6:1"),
    ]


# ---- replay ------------------------------------------------------------------
def test_replay_report_structure_and_determinism(cfg, enricher):
    report = run_replay(cfg, enricher, scenario(), source="test")
    again = run_replay(cfg, enricher, list(reversed(scenario())), source="test")
    for r in (report, again):
        r["meta"].pop("generated_at")
    assert report == again                                              # same input, any order: same result

    assert report["meta"]["driver"] == "dry_run" and report["meta"]["evidence_records"] == 7
    # The scan plus one ML alert are two families, so the connect scan takes it straight to a block.
    assert [d["kind"] for d in report["decisions"] if d["ip"] == ATTACKER] == ["throttle", "block", "observe"]
    assert report["summary"]["by_rung"]["3"] == {"decisions": 1, "distinct_ips": 1}
    assert report["summary"]["superseded_by_stronger"] == 1

    timeline = report["timelines"][ATTACKER]
    assert [e["event"] for e in timeline][-3:] == ["evidence", "expired", "decision"]
    assert timeline[-3]["while_blocked"] is True
    assert timeline[-2]["t"] == 1020.0 + 900                            # the block ended on the simulated clock

    text = render_text(report)
    assert "SUMMARY PER RUNG" in text and "TIMELINE PER IP" in text and "EVERY EXPLANATION" in text
    assert "Blocked 203.0.113.9 for 15 min (rung 3)." in text and "[while blocked]" in text


def test_replay_applies_recorded_triage_and_a_time_range(cfg, enricher):
    triage = [(1100.0, TriageEvent("nids", "nids:2:", "false_positive", "false_positive", 1100.0))]
    report = run_replay(cfg, enricher, scenario(), triage, source="test")
    block = next(d for d in report["decisions"] if d["kind"] == "block")
    assert block["reversed_at"] == 1100.0 and report["summary"]["reversed_early"] == 1
    # Without the ML alert there is one family left: the block is lifted and a reset takes its place.
    assert [d["kind"] for d in report["decisions"] if d["ip"] == ATTACKER][:3] == ["throttle", "block", "reset"]

    early = run_replay(cfg, enricher, scenario(), source="test", start=1000.0, end=1015.0)
    assert early["meta"]["evidence_records"] == 2 and [d["kind"] for d in early["decisions"]] == ["throttle"]


def test_replay_label_metrics(cfg, enricher, tmp_path):
    labels_file = tmp_path / "labels.yaml"
    labels_file.write_text(yaml.safe_dump([
        {"ip": ATTACKER, "label": "attacker", "from": 900, "to": 5000},
        {"ip": BENIGN, "label": "benign", "from": 900, "to": 5000},
    ]), encoding="utf-8")
    report = run_replay(cfg, enricher, scenario(), source="test", labels=load_labels(labels_file))
    labels = report["labels"]

    # The benign host: ML 0.96 points + one high rule 6 = throttle. That is a false positive, and it is reported.
    (fp,) = labels["false_positive_actions"]
    assert fp["ip"] == BENIGN and fp["kind"] == "throttle"
    assert labels["time_to_first_action"] == [
        {"ip": ATTACKER, "first_evidence_at": 1000.0, "first_action_at": 1000.0, "seconds_to_first_action": 0.0}]
    assert labels["ml_by_label"]["attacker"]["mean_probability"] == 0.95
    assert labels["ml_by_label"]["attacker"]["mean_rescaled"] == 0.9
    assert labels["ml_by_label"]["benign"]["ml_alert_count"] == 1
    assert "Actions against benign IPs (false positives): 1" in render_text(report)

    with pytest.raises(ValueError):
        bad = tmp_path / "bad.yaml"
        bad.write_text("- {ip: 1.2.3.4, label: maybe}", encoding="utf-8")
        load_labels(bad)


def test_replay_of_a_nids_database_copy_is_marked_approximate(cfg, enricher, nids_db, tmp_path):
    nids_db.insert(1, "TCP_CONNECT_SCAN", count=12, created_at=1000.0)
    nids_db.insert(2, "Host Brute Force", count=5, created_at=1030.0)
    snap = build_nids_adapter(cfg, MemoryState(), db_path=str(nids_db.path)).snapshot()
    report = run_replay(cfg, enricher, snap.evidence, [(t.at, t) for t in snap.triage], source="nids copy", approximate=True)
    assert report["meta"]["note"] == NIDS_DB_NOTE and "APPROXIMATE" in render_text(report)
    assert [d["kind"] for d in report["decisions"]] == ["reset", "block"]

    json_path, text_path = write_report(report, tmp_path / "out")
    assert json.loads(json_path.read_text(encoding="utf-8"))["summary"] == report["summary"]
    assert text_path.read_text(encoding="utf-8").startswith("ACTIVE RESPONSE ENGINE - REPLAY REPORT")


def test_replay_cli_from_the_decision_log_and_from_a_nids_copy(cfg_dict, nids_db, tmp_path, capsys):
    cfg_path = tmp_path / "config.yaml"
    cfg_dict.pop("base_dir")
    cfg_path.write_text(yaml.safe_dump(cfg_dict), encoding="utf-8")

    live = Store(str(tmp_path / "ips.db"))                              # what a live run would have recorded
    for ev in scenario():
        live.add_evidence(replace(ev, received_at=ev.last_seen + 1))   # the engine saw it a moment after the NIDS did
    live.close()

    out = tmp_path / "out"
    assert main(["-c", str(cfg_path), "replay", "--source", "evidence", "--from", "0", "--to", "9999", "--out", str(out)]) == 0
    assert "Blocked 203.0.113.9 for 15 min (rung 3)." in capsys.readouterr().out
    assert (out / "replay_report.json").is_file() and (out / "replay_report.txt").is_file()

    nids_db.insert(1, "TCP_CONNECT_SCAN", count=12, created_at=1000.0)
    assert main(["-c", str(cfg_path), "replay", "--source", "nids-db", str(nids_db.path), "--out", str(out)]) == 0
    assert "APPROXIMATE" in capsys.readouterr().out
    assert main(["-c", str(cfg_path), "replay", "--source", "nids-db", "--out", str(out)]) == 2


# ---- API ---------------------------------------------------------------------
@pytest.fixture
def client(cfg, enricher):
    h = Harness(cfg, enricher)
    h.feed("TCP_CONNECT_SCAN", count=2)
    h.feed("Host Brute Force", family="host_sensor", technique="T1110")
    api = TestClient(create_app(h.engine, h.store, [], TOKEN))
    api.harness = h
    return api


AUTH = {"Authorization": f"Bearer {TOKEN}"}


def test_api_needs_the_token_everywhere_except_health(client):
    assert client.get("/health").json() == {"status": "ok", "driver": "dry_run", "driver_healthy": True}
    for method, path in [("get", "/status"), ("get", "/decisions"), ("get", "/decisions/1"), ("get", "/active"),
                         ("get", f"/ips/{ATTACKER}"), ("post", "/unblock")]:
        assert getattr(client, method)(path).status_code == 401
        assert getattr(client, method)(path, headers={"Authorization": "Bearer " + "x" * 40}).status_code == 401
        assert getattr(client, method)(path, headers={"Authorization": TOKEN}).status_code == 401    # not a bearer header
    assert ("block", ATTACKER) in client.harness.enforced()                 # the unauthenticated unblock did nothing


def test_api_reads_and_unblocks(client):
    assert client.get("/status", headers=AUTH).json()["active_actions"] == 1
    decisions = client.get("/decisions", headers=AUTH, params={"ip": ATTACKER}).json()
    assert decisions[0]["kind"] == "block" and decisions[0]["explanation"].startswith("Blocked")
    assert client.get(f"/decisions/{decisions[0]['decision_id']}", headers=AUTH).json()["rung"] == 3
    assert client.get("/decisions/999", headers=AUTH).status_code == 404
    assert client.get("/active", headers=AUTH).json()["driver"][0]["ip"] == ATTACKER
    assert client.get(f"/ips/{ATTACKER}", headers=AUTH).json()["rung"] == 3

    assert client.post("/unblock", headers=AUTH, json={"ip": "not-an-ip"}).status_code == 400
    assert client.get("/ips/1.2.3.4;rm", headers=AUTH).status_code == 400
    done = client.post("/unblock", headers=AUTH, json={"ip": ATTACKER}).json()
    assert len(done["reversed_decisions"]) == 1 and client.harness.enforced() == set()


def test_api_refuses_a_short_token(harness):
    with pytest.raises(ValueError):
        create_app(harness.engine, harness.store, [], "short")


# ---- config and architecture -------------------------------------------------
def test_shipped_config_loads_and_defaults_to_dry_run():
    cfg = load_config(PROJECT_ROOT / "config.yaml")
    assert cfg.engine.driver == "dry_run" and cfg.api.host == "127.0.0.1"
    assert cfg.scoring.window_seconds == 600 and cfg.policy.long_block.ttl_seconds == 7200


def test_config_rejects_typos_and_nonsense(cfg_dict):
    for mutate in (
        lambda d: d["policy"].update(blok={"score": 1}),
        lambda d: d["policy"]["block"].update(score=1),                     # thresholds must ascend
        lambda d: d["network"].update(allowlist=["not-a-cidr"]),
        lambda d: d["enrichment"]["d3fend_by_action"].pop("reset"),
        lambda d: d["enrichment"]["attack"].update(url="http://example.org/attack.json"),
        lambda d: d["engine"].update(driver="iptables"),
    ):
        bad = json.loads(json.dumps(cfg_dict))
        mutate(bad)
        with pytest.raises(ValidationError):
            Config.model_validate(bad)


CORE = ["models", "config", "scoring", "policy", "explain", "enrichment", "store", "engine", "replay", "api"]


@pytest.mark.parametrize("module", CORE)
def test_core_never_imports_an_adapter_or_a_concrete_firewall_driver(module):
    tree = ast.parse((PROJECT_ROOT / "are" / f"{module}.py").read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
        elif isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
    assert not any("adapters" in name or name.endswith("nftables") or name == "subprocess" for name in imported), imported
