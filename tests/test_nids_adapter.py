from __future__ import annotations

import hashlib
import sqlite3

import pytest

from are.adapters import AdapterError, MemoryState, build_nids_adapter
from are.models import Family

from .conftest import ATTACKER, NidsDb


def adapter(cfg, state=None, start_from="beginning", clock=lambda: 5000.0):
    cfg.adapters["nids"]["start_from"] = start_from
    return build_nids_adapter(cfg, state if state is not None else MemoryState(), clock)


def test_new_row_delta_is_its_count_and_fields_are_mapped(cfg, nids_db):
    nids_db.insert(1, "TCP_CONNECT_SCAN", count=3, created_at=1000.0, details={"distinct_ports": 9})
    (ev,) = adapter(cfg).poll().evidence
    assert ev.evidence_id == "nids:1:3" and ev.source == "nids"
    assert (ev.family, ev.rule_id, ev.src_ip, ev.dst_ip) == (Family.NET_SIGNATURE, "TCP_CONNECT_SCAN", ATTACKER, "10.0.0.5")
    assert (ev.count_delta, ev.last_seen, ev.handshake_confirmed, ev.technique) == (3, 1000.0, True, "T1046")
    assert ev.raw["details"] == {"distinct_ports": 9} and ev.raw["id"] == 1


def test_repeat_updates_emit_only_the_delta(cfg, nids_db):
    a = adapter(cfg)
    nids_db.insert(1, "TCP_SYN_SCAN", count=1, created_at=1000.0)
    assert [e.count_delta for e in a.poll().evidence] == [1]
    assert a.poll().evidence == []                                    # nothing changed
    nids_db.repeat(1, count=12, created_at=1010.0)
    (ev,) = a.poll().evidence
    assert (ev.evidence_id, ev.count_delta, ev.first_seen, ev.last_seen) == ("nids:1:12", 11, 1000.0, 1010.0)
    assert a.poll().evidence == []


def test_late_written_repeat_with_an_older_timestamp_is_not_missed(cfg, nids_db):
    """The NIDS batches repeat counts and stamps them with when the repeat was seen."""
    a = adapter(cfg)
    nids_db.insert(1, "TCP_SYN_SCAN", created_at=1000.0)
    nids_db.insert(2, "BRUTEFORCE_STANDARD_RATE", created_at=1200.0)
    a.poll()                                                           # cursor is now 1200
    nids_db.repeat(1, count=5, created_at=1100.0)                      # flushed late, stamped before the cursor
    (ev,) = a.poll().evidence
    assert (ev.evidence_id, ev.count_delta, ev.last_seen) == ("nids:1:5", 4, 1100.0)


def test_family_and_handshake_lookup(cfg, nids_db):
    rows = [
        ("TCP_SYN_SCAN", Family.NET_SIGNATURE, False), ("TCP_CONNECT_SCAN", Family.NET_SIGNATURE, True),
        ("EXPLOIT_SAMBA_USERMAP", Family.NET_SIGNATURE, True), ("FLOOD_SYN", Family.NET_BEHAVIOR, False),
        ("FLOOD_PACKET_RATE", Family.NET_BEHAVIOR, False), ("SCAN_SLOW_RATE", Family.NET_BEHAVIOR, False),
        ("BRUTEFORCE_LOW_RATE", Family.NET_BEHAVIOR, False), ("EXFIL_DNS_TUNNEL", Family.NET_BEHAVIOR, True),
        ("ML_FLOW_ANOMALY", Family.ANOMALY_ML, False), ("ANOMALY_TRAFFIC_BASELINE", Family.ANOMALY_ML, False),
        ("Root Access", Family.HOST_SENSOR, True), ("Cloud Brute Force", Family.CLOUD_SENSOR, True),
        ("MITM_ARP_SPOOF", Family.NET_SIGNATURE, False),
    ]
    for i, (rule, _, _) in enumerate(rows, start=1):
        nids_db.insert(i, rule, created_at=1000.0 + i)
    got = {e.rule_id: (e.family, e.handshake_confirmed) for e in adapter(cfg).poll().evidence}
    assert got == {rule: (family, hs) for rule, family, hs in rows}


def test_rows_that_cannot_become_evidence_are_skipped_and_counted(cfg, nids_db):
    nids_db.insert(1, None, created_at=1001.0)                                    # no rule id (pre-catalogue row)
    nids_db.insert(2, "SOMETHING_NEW", created_at=1002.0)                         # not in the family table
    nids_db.insert(3, "SCAN_DISTRIBUTED", src=None, created_at=1003.0)            # the NIDS files this with no source
    nids_db.insert(4, "Root Access", src="local", dst="web-prod-01", created_at=1004.0)
    nids_db.insert(5, "SSH Login", dst="web-prod-01", created_at=1005.0)          # hostname destination becomes null
    a = adapter(cfg)
    (ev,) = a.poll().evidence
    assert ev.rule_id == "SSH Login" and ev.dst_ip is None
    assert a.stats["skipped_null_rule"] == 1 and a.stats["skipped_unmapped_rule"] == 1
    assert a.stats["skipped_no_source_ip"] == 2
    a.poll()
    assert a.stats["skipped_null_rule"] == 1                                       # counted once, not every poll


def test_ml_probability_sources_in_order(cfg, nids_db):
    nids_db.insert(1, "ML_FLOW_ANOMALY", created_at=1001.0,
                   details={"max_attack_probability": 0.97, "attack_probability": 0.6, "attack_type": "PortScan"})
    nids_db.insert(2, "ML_FLOW_ANOMALY", created_at=1002.0, details={"attack_probability": 0.71,
                                                                    "predicted_label": "attack"})
    nids_db.insert(3, "ML_FLOW_ANOMALY", severity="high", created_at=1003.0, details={"attack_probability": None})
    nids_db.insert(4, "ANOMALY_TRAFFIC_BASELINE", severity="medium", created_at=1004.0, details={"sigma": 4})
    nids_db.insert(5, "ML_FLOW_ANOMALY", severity="low", created_at=1005.0)
    got = [(e.ml_probability, e.ml_attack_type) for e in adapter(cfg).poll().evidence]
    assert got == [(0.97, "PortScan"), (0.71, "attack"), (0.85, None), (0.65, None), (0.5, None)]


def test_correlation_rows_carry_stages_and_inherit_handshake_from_members(cfg, nids_db):
    nids_db.insert(1, "CORRELATED_INCIDENT", created_at=1001.0, details={
        "incident_id": "INC-00001", "stages": ["reconnaissance", "initial_access"],
        "rule_ids": {"TCP_SYN_SCAN": 3, "EXPLOIT_SAMBA_USERMAP": 1}})
    nids_db.insert(2, "CORRELATED_INCIDENT", src="203.0.113.10", created_at=1002.0, details={
        "stages": ["reconnaissance", "credential_access"], "rule_ids": {"TCP_SYN_SCAN": 3, "SCAN_SLOW_RATE": 1}})
    nids_db.insert(3, "ACTIVE_INTRUSION", severity="critical", created_at=1003.0, details={
        "kill_chain": ["initial_access", "privilege_escalation"], "stage_count": 2})
    first, second, intrusion = adapter(cfg).poll().evidence
    assert first.family is Family.CORRELATION and first.stages == ("reconnaissance", "initial_access")
    assert first.handshake_confirmed and not second.handshake_confirmed
    assert intrusion.family is Family.CORRELATION and intrusion.stages == ("initial_access", "privilege_escalation")
    assert first.technique is None


def test_exploit_alert_uses_the_nids_own_source_verification(cfg, nids_db):
    nids_db.insert(1, "EXPLOIT_VSFTPD_BACKDOOR", created_at=1001.0, details={"source_verified": False})
    nids_db.insert(2, "EXPLOIT_VSFTPD_BACKDOOR", src="203.0.113.10", created_at=1002.0, details={"source_verified": True})
    forged, real = adapter(cfg).poll().evidence
    assert not forged.handshake_confirmed and real.handshake_confirmed


def test_triage_changes_become_events(cfg, nids_db):
    a = adapter(cfg)
    nids_db.insert(1, "TCP_CONNECT_SCAN", created_at=1000.0)
    assert a.poll().triage == []
    nids_db.set_triage(1, "false_positive", 1050.0)
    (event,) = a.poll().triage
    assert (event.evidence_id_prefix, event.verdict, event.status, event.at) == ("nids:1:", "false_positive", "false_positive", 1050.0)
    assert a.poll().triage == []                                       # same status: no new event
    nids_db.set_triage(1, "new", 1060.0)                               # analyst undid the verdict
    (undo,) = a.poll().triage
    assert undo.verdict == "other" and undo.status == "new"


def test_suppressed_and_dismissed_alerts_do_not_become_evidence(cfg, nids_db):
    a = adapter(cfg)
    nids_db.insert(1, "TCP_SYN_SCAN", created_at=1000.0, triage_status="false_positive", triage_at=1000.0)  # suppression
    assert a.poll().evidence == []
    nids_db.insert(2, "TCP_SYN_SCAN", src="203.0.113.10", created_at=1001.0)
    a.poll()
    nids_db.set_triage(2, "false_positive", 1002.0)
    a.poll()
    nids_db.repeat(2, count=9, created_at=1003.0)                      # repeats of a dismissed alert
    assert a.poll().evidence == []
    assert a.stats["skipped_false_positive"] == 2


def test_cleared_alert_table_with_restarted_ids_is_detected(cfg, nids_db):
    a = adapter(cfg)
    nids_db.insert(1, "TCP_SYN_SCAN", count=7, created_at=1000.0, timestamp="2026-11-12 10:00:00")
    assert a.poll().evidence[0].evidence_id == "nids:1:7"
    nids_db.clear()                                                    # dashboard "Clear Alerts": ids restart at 1
    nids_db.insert(1, "EXPLOIT_SAMBA_USERMAP", count=1, created_at=1100.0, timestamp="2026-11-12 10:01:40")
    (ev,) = a.poll().evidence
    assert ev.evidence_id == "nids:g1-1:1" and ev.count_delta == 1 and ev.rule_id == "EXPLOIT_SAMBA_USERMAP"
    assert a.stats["id_resets_detected"] == 1
    nids_db.set_triage(1, "false_positive", 1150.0)
    assert a.poll().triage[0].evidence_id_prefix == "nids:g1-1:"


def test_state_survives_an_engine_restart(cfg, nids_db):
    state = MemoryState()
    nids_db.insert(1, "TCP_SYN_SCAN", count=4, created_at=1000.0)
    assert len(adapter(cfg, state).poll().evidence) == 1
    restarted = adapter(cfg, state)
    assert restarted.poll().evidence == []
    nids_db.repeat(1, count=6, created_at=1020.0)
    assert [e.count_delta for e in restarted.poll().evidence] == [2]


def test_start_from_now_ignores_history_but_sees_what_comes_next(cfg, nids_db):
    nids_db.insert(1, "TCP_SYN_SCAN", count=50, created_at=1000.0)
    a = adapter(cfg, start_from="now")
    assert a.poll().evidence == []
    nids_db.repeat(1, count=53, created_at=1030.0)
    nids_db.insert(2, "TCP_CONNECT_SCAN", created_at=1031.0)
    assert [(e.evidence_id, e.count_delta) for e in a.poll().evidence] == [("nids:1:53", 3), ("nids:2:1", 1)]


def test_database_is_opened_read_only_and_never_modified(cfg, nids_db):
    nids_db.insert(1, "TCP_SYN_SCAN", created_at=1000.0)
    before = hashlib.sha256(nids_db.path.read_bytes()).hexdigest()
    a = adapter(cfg)
    a.poll()
    a.snapshot()
    conn = a._connect()
    with pytest.raises(sqlite3.OperationalError):
        conn.execute("DELETE FROM alerts")
    conn.close()
    assert hashlib.sha256(nids_db.path.read_bytes()).hexdigest() == before


def test_older_nids_schema_without_triage_columns_still_works(cfg, tmp_path):
    db = NidsDb(tmp_path / "nids_users.db", with_triage=False)
    db.insert(1, "TCP_SYN_SCAN", created_at=1000.0)
    result = adapter(cfg).poll()
    assert len(result.evidence) == 1 and result.triage == []


def test_missing_database_or_wrong_schema_is_a_clear_error(cfg, tmp_path):
    with pytest.raises(AdapterError, match="not found"):
        adapter(cfg).poll()
    with sqlite3.connect(tmp_path / "nids_users.db") as conn:
        conn.execute("CREATE TABLE alerts (id INTEGER PRIMARY KEY, severity TEXT)")
    with pytest.raises(AdapterError, match="missing column"):
        adapter(cfg).poll()


def test_snapshot_replays_final_counts_and_dismissals(cfg, nids_db):
    nids_db.insert(1, "TCP_CONNECT_SCAN", count=12, created_at=1000.0)
    nids_db.insert(2, "Host Brute Force", count=5, created_at=1005.0, triage_status="false_positive", triage_at=1100.0)
    nids_db.insert(3, None, created_at=1006.0)
    snap = adapter(cfg).snapshot()
    assert [(e.evidence_id, e.count_delta, e.last_seen) for e in snap.evidence] == [
        ("nids:1:12", 12, 1000.0), ("nids:2:5", 5, 1005.0)]
    assert [(t.evidence_id_prefix, t.at) for t in snap.triage] == [("nids:2:", 1100.0)]


def test_rows_carry_the_nids_kill_chain_stage(cfg, nids_db):
    nids_db.insert(1, "TCP_SYN_SCAN", created_at=1000.0)
    nids_db.insert(2, "EXPLOIT_SAMBA_USERMAP", created_at=1001.0)
    nids_db.insert(3, "Root Access", created_at=1002.0)
    nids_db.insert(4, "FLOOD_SYN", created_at=1003.0)
    stages = [e.stage for e in adapter(cfg).poll().evidence]
    assert stages == ["reconnaissance", "initial_access", "privilege_escalation", None]
