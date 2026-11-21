from __future__ import annotations

import json

import pytest

from are.config import Config
from are.enrichment import Enricher, EnrichmentError, file_sha256, load_attack, load_d3fend
from are.explain import explain, fmt_duration
from are.models import ActionKind

from .conftest import ATTACKER, PROJECT_ROOT, write_d3fend


# ---- explanations ------------------------------------------------------------
def test_block_explanation_has_the_four_required_parts(harness):
    harness.feed("TCP_CONNECT_SCAN", count=12)
    harness.feed("Host Brute Force", family="host_sensor", technique="T1110", count=5)
    block = harness.decisions(ATTACKER)[-1]
    assert block.explanation.splitlines() == [
        "Blocked 203.0.113.9 for 15 min (rung 3).",
        "Score 36 from 2 independent families: host sensor (Host Brute Force x5), "
        "network signature (TCP_CONNECT_SCAN x12).",
        "Tactic: Credential Access (T1110 Brute Force). "
        "Countermeasure: inbound traffic filtering (D3FEND D3-ITF, a suggestion).",
        "Not rung 4: first block for this IP in 24 h.",
    ]


def test_explanation_is_generated_from_the_record_alone(harness):
    harness.feed(count=2)
    stored = harness.decisions(ATTACKER)[-1]
    assert explain(harness.store.get_decision(stored.decision_id)) == stored.explanation


def test_ml_and_throttle_wording(harness):
    harness.feed("ML_FLOW_ANOMALY", family="anomaly_ml", prob=1.0, attack_type="PortScan", handshake=False,
                 technique=None, count=50)
    text = harness.decisions(ATTACKER)[-1].explanation
    assert text.startswith("Throttled 203.0.113.9 to 20 packets/s for 10 min (rung 1).")
    assert "ML anomaly (ML_FLOW_ANOMALY x50 to 10.0.0.5, max probability 1.00, model says PortScan)" in text
    assert "ML evidence is a ranking signal only and adds at most 4 points" in text
    assert "Tactic: none" in text
    assert "Countermeasure: network traffic filtering (D3FEND D3-NTF, a suggestion)." in text
    assert text.splitlines()[-1] == "Not rung 2: score 4 is below 8; no handshake-confirmed evidence, " \
                                    "so the source address may be forged."


def test_faint_ml_is_listed_apart_from_the_families_it_did_not_join(harness):
    harness.feed("ML_FLOW_ANOMALY", family="anomaly_ml", prob=0.51, handshake=False, technique=None)
    harness.feed("EXPLOIT_SAMBA_USERMAP", technique="T1190", count=4)
    lines = harness.decisions(ATTACKER)[-1].explanation.splitlines()
    assert lines[1] == (
        "Score 18.1 from 1 independent family: network signature (EXPLOIT_SAMBA_USERMAP x4). "
        "Also scored: ML anomaly (ML_FLOW_ANOMALY x1 to 10.0.0.5, max probability 0.51), "
        "not counted as a family because it is below probability 0.8. "
        "ML evidence is a ranking signal only and adds at most 4 points."
    )


def test_durations():
    assert [fmt_duration(s) for s in (600, 900, 7200, 45, 5400)] == ["10 min", "15 min", "2 h", "45 s", "90 min"]


# ---- enrichment --------------------------------------------------------------
def test_tactic_derivation(enricher):
    assert enricher.tactic_for("T1110") == "credential-access"
    assert enricher.tactic_for("T1078") == "initial-access"            # config's primary tactic
    assert enricher.tactic_for("T1557.002") == "credential-access"     # earliest in matrix order when not configured
    assert enricher.tactic_for("T1110.001") == "credential-access"     # unknown sub-technique falls back to its parent
    assert enricher.tactic_for("T9999") is None                        # revoked entries are ignored
    assert enricher.tactic_for(None) is None
    assert enricher.tactic_name("command-and-control") == "Command and Control"
    assert enricher.technique_name("T1046") == "Network Service Discovery"
    assert enricher.countermeasure(ActionKind.RESET).d3fend_id == "D3-ST"


def test_startup_fails_when_a_mapped_d3fend_name_is_missing(cfg_dict):
    cfg_dict["enrichment"]["d3fend_by_action"]["block"] = "Wishful Thinking"
    with pytest.raises(EnrichmentError, match="Wishful Thinking"):
        Enricher.from_config(Config.model_validate(cfg_dict))


def test_startup_fails_on_wrong_sha256_wrong_version_or_missing_file(cfg_dict, tmp_path):
    bad = json.loads(json.dumps(cfg_dict))
    bad["enrichment"]["attack"]["sha256"] = "0" * 64
    with pytest.raises(EnrichmentError, match="sha256"):
        Enricher.from_config(Config.model_validate(bad))

    other = tmp_path / "d3fend-old.json"
    write_d3fend(other, version="0.9.0")
    bad = json.loads(json.dumps(cfg_dict))
    bad["enrichment"]["d3fend"]["path"] = str(other)
    with pytest.raises(EnrichmentError, match="version 0.9.0"):
        Enricher.from_config(Config.model_validate(bad))

    bad = json.loads(json.dumps(cfg_dict))
    bad["enrichment"]["attack"]["path"] = str(tmp_path / "nope.json")
    with pytest.raises(EnrichmentError, match="fetch-data"):
        Enricher.from_config(Config.model_validate(bad))


def test_startup_fails_on_config_that_contradicts_attack(cfg_dict):
    bad = json.loads(json.dumps(cfg_dict))
    bad["policy"]["primary_tactic"] = {"T1110": "impact"}
    with pytest.raises(EnrichmentError, match="T1110"):
        Enricher.from_config(Config.model_validate(bad))
    bad = json.loads(json.dumps(cfg_dict))
    bad["policy"]["quarantine_tactics"] = ["command_and_control"]
    with pytest.raises(EnrichmentError, match="command_and_control"):
        Enricher.from_config(Config.model_validate(bad))


def test_pinned_hash_is_checked_when_set(cfg_dict):
    path = cfg_dict["enrichment"]["attack"]["path"]
    cfg_dict["enrichment"]["attack"]["sha256"] = file_sha256(__import__("pathlib").Path(path))
    Enricher.from_config(Config.model_validate(cfg_dict))


REAL = Config.model_validate({**__import__("yaml").safe_load((PROJECT_ROOT / "config.yaml").read_text(encoding="utf-8")),
                              "base_dir": str(PROJECT_ROOT)})
_real_files = REAL.resolve(REAL.enrichment.attack.path).is_file() and REAL.resolve(REAL.enrichment.d3fend.path).is_file()


@pytest.mark.skipif(not _real_files, reason="pinned MITRE data not downloaded (run `are fetch-data`)")
def test_shipped_config_works_with_the_real_pinned_data():
    enricher = Enricher.from_config(REAL)                               # verifies both sha256 pins
    attack = load_attack(REAL.resolve(REAL.enrichment.attack.path))
    assert load_d3fend(REAL.resolve(REAL.enrichment.d3fend.path)).version == "1.6.0"
    assert len(attack.techniques) > 600 and attack.tactic_order[0] == "reconnaissance"
    missing = [t for t in REAL.adapters["nids"]["techniques"].values() if enricher.technique(t) is None]
    assert missing == []                                                # every technique copied from the NIDS exists
    assert enricher.tactic_for("T1078") == "initial-access"
    assert enricher.tactic_for("T1071") == "command-and-control"
