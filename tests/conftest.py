"""Shared fixtures: tiny ATT&CK / D3FEND files, a test config, and an engine harness.

Tests never need the real 49 MB ATT&CK bundle and never touch a firewall.
"""
from __future__ import annotations

import itertools
import json
import sqlite3
from pathlib import Path

import pytest
import yaml

from are.config import Config
from are.enforcers.dry_run import DryRunEnforcer
from are.engine import Engine
from are.enrichment import Enricher
from are.models import Evidence
from are.policy import Policy
from are.replay import SimClock
from are.store import Store

PROJECT_ROOT = Path(__file__).resolve().parent.parent

ATTACKER = "203.0.113.9"          # external
INTERNAL_HOST = "10.0.0.50"       # inside internal_networks
TARGET = "10.0.0.5"
C2_SERVER = "198.51.100.77"       # external destination
ALLOWLISTED = "10.0.0.1"

_TACTICS = [
    ("reconnaissance", "Reconnaissance"), ("initial-access", "Initial Access"), ("execution", "Execution"),
    ("persistence", "Persistence"), ("privilege-escalation", "Privilege Escalation"), ("stealth", "Stealth"),
    ("credential-access", "Credential Access"), ("discovery", "Discovery"), ("lateral-movement", "Lateral Movement"),
    ("collection", "Collection"), ("command-and-control", "Command and Control"), ("exfiltration", "Exfiltration"),
    ("impact", "Impact"),
]
_TECHNIQUES = {
    "T1046": ("Network Service Discovery", ["discovery"]),
    "T1110": ("Brute Force", ["credential-access"]),
    "T1190": ("Exploit Public-Facing Application", ["initial-access"]),
    "T1078": ("Valid Accounts", ["stealth", "persistence", "privilege-escalation", "initial-access"]),
    "T1071": ("Application Layer Protocol", ["command-and-control"]),
    "T1041": ("Exfiltration Over C2 Channel", ["exfiltration"]),
    "T1021": ("Remote Services", ["lateral-movement"]),
    "T1548": ("Abuse Elevation Control Mechanism", ["privilege-escalation"]),
    "T1557.002": ("ARP Cache Poisoning", ["credential-access", "collection"]),
    "T1200": ("Hardware Additions", ["initial-access"]),
    "T1498": ("Network Denial of Service", ["impact"]),
}
_D3FEND = {
    "D3-NTF": "Network Traffic Filtering", "D3-ST": "Session Termination", "D3-ITF": "Inbound Traffic Filtering",
    "D3-NI": "Network Isolation", "D3-OTF": "Outbound Traffic Filtering",
}


def write_attack_bundle(path: Path) -> None:
    objects = []
    for short, name in _TACTICS:
        objects.append({"type": "x-mitre-tactic", "id": f"x-mitre-tactic--{short}", "name": name,
                        "x_mitre_shortname": short})
    objects.append({"type": "x-mitre-matrix", "id": "x-mitre-matrix--1", "name": "Enterprise ATT&CK",
                    "tactic_refs": [f"x-mitre-tactic--{short}" for short, _ in _TACTICS]})
    for tid, (name, tactics) in _TECHNIQUES.items():
        objects.append({
            "type": "attack-pattern", "id": f"attack-pattern--{tid}", "name": name,
            "external_references": [{"source_name": "mitre-attack", "external_id": tid}],
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": t} for t in tactics],
        })
    objects.append({"type": "attack-pattern", "id": "attack-pattern--old", "name": "Revoked", "revoked": True,
                    "external_references": [{"source_name": "mitre-attack", "external_id": "T9999"}]})
    path.write_text(json.dumps({"type": "bundle", "id": "bundle--test", "objects": objects}), encoding="utf-8")


def write_d3fend(path: Path, version: str = "1.6.0") -> None:
    graph = [{"@id": "http://d3fend.mitre.org/ontologies/d3fend.owl", "@type": "owl:Ontology", "owl:versionInfo": version}]
    graph += [{"@id": f"d3f:{name.replace(' ', '')}", "d3f:d3fend-id": did, "rdfs:label": name}
              for did, name in _D3FEND.items()]
    path.write_text(json.dumps({"@context": {}, "@graph": graph}), encoding="utf-8")


@pytest.fixture(scope="session")
def data_dir(tmp_path_factory) -> Path:
    d = tmp_path_factory.mktemp("mitre")
    write_attack_bundle(d / "attack.json")
    write_d3fend(d / "d3fend.json")
    return d


@pytest.fixture
def cfg_dict(data_dir, tmp_path) -> dict:
    """The project's real config.yaml, pointed at the test data and a test network."""
    data = yaml.safe_load((PROJECT_ROOT / "config.yaml").read_text(encoding="utf-8"))
    data["base_dir"] = str(tmp_path)
    data["network"] = {
        "internal_networks": ["10.0.0.0/24"],
        "allowlist": [f"{ALLOWLISTED}/32", "198.51.100.53/32"],
        "management_hosts": [ALLOWLISTED],
    }
    data["enrichment"]["attack"].update(path=str(data_dir / "attack.json"), sha256=None)
    data["enrichment"]["d3fend"].update(path=str(data_dir / "d3fend.json"), sha256=None)
    data["adapters"]["nids"]["db_path"] = str(tmp_path / "nids_users.db")
    return data


@pytest.fixture
def cfg(cfg_dict) -> Config:
    return Config.model_validate(cfg_dict)


@pytest.fixture
def enricher(cfg) -> Enricher:
    return Enricher.from_config(cfg)


@pytest.fixture
def policy(cfg, enricher) -> Policy:
    return Policy(cfg, enricher)


_ids = itertools.count(1)


def make_ev(rule="TCP_CONNECT_SCAN", src=ATTACKER, *, family="net_signature", severity="high", count=1, at=1000.0,
            handshake=True, technique="T1046", dst=TARGET, prob=None, attack_type=None, stages=None, eid=None,
            while_blocked=False, stage=None) -> Evidence:
    return Evidence(
        evidence_id=eid or f"test:{next(_ids)}:{count}", source="test", family=family, rule_id=rule, src_ip=src,
        dst_ip=dst, severity=severity, first_seen=at, last_seen=at, count_delta=count, handshake_confirmed=handshake,
        raw={}, ml_probability=prob, ml_attack_type=attack_type, technique=technique, stages=stages,
        while_blocked=while_blocked, stage=stage,
    )


class Harness:
    """An engine on a simulated clock with the dry_run driver."""

    def __init__(self, cfg: Config, enricher: Enricher, store: Store | None = None, enforcer=None, start: float = 1000.0):
        self.cfg = cfg
        self.clock = SimClock(start)
        self.store = store or Store(":memory:")
        self.enforcer = enforcer or DryRunEnforcer(cfg.nftables, cfg.network.management_hosts, self.clock)
        self.engine = Engine(cfg, self.store, Policy(cfg, enricher), enricher, self.enforcer, self.clock)

    def feed(self, rule="TCP_CONNECT_SCAN", src=ATTACKER, **kw) -> Evidence:
        ev = make_ev(rule, src, at=self.clock.now, **kw)
        self.engine.ingest(ev)
        return ev

    def advance(self, seconds: float) -> None:
        """Move time forward, ticking every 30 s like the live loop."""
        end = self.clock.now + seconds
        tick = self.cfg.engine.tick_seconds
        while self.clock.now + tick <= end:
            self.clock.now += tick
            self.engine.tick()
        self.clock.now = end
        self.engine.expire_due()

    def decisions(self, ip: str | None = None):
        return self.store.decisions(ip=ip)

    def kinds(self, ip: str | None = None) -> list[str]:
        return [d.kind for d in self.decisions(ip)]

    def enforced(self) -> set[tuple[str, str]]:
        return {(e.kind.value, e.ip) for e in self.enforcer.list_active()}


@pytest.fixture
def harness(cfg, enricher) -> Harness:
    return Harness(cfg, enricher)


# ------------------------------------------------------------------ a synthetic NIDS database
NIDS_SCHEMA = """
CREATE TABLE alerts (
    id INTEGER PRIMARY KEY, type TEXT NOT NULL, severity TEXT NOT NULL, src TEXT, dst TEXT, protocol TEXT,
    message TEXT, timestamp TEXT NOT NULL, details TEXT, created_at REAL NOT NULL, rule_id TEXT,
    count INTEGER DEFAULT 1{triage}
)"""
_TRIAGE_COLS = ", triage_status TEXT, triage_by TEXT, triage_at REAL, triage_note TEXT"


class NidsDb:
    """Writes alert rows the way the NIDS does (same table, same columns)."""

    def __init__(self, path: Path, with_triage: bool = True) -> None:
        self.path = path
        self.with_triage = with_triage
        with sqlite3.connect(path) as conn:
            conn.execute(NIDS_SCHEMA.format(triage=_TRIAGE_COLS if with_triage else ""))

    def insert(self, id, rule_id, src=ATTACKER, dst=TARGET, severity="high", count=1, created_at=1000.0,
               details=None, timestamp="2026-11-12 10:00:00", triage_status=None, triage_at=None) -> None:
        cols = "id, type, severity, src, dst, protocol, message, timestamp, details, created_at, rule_id, count"
        vals = [id, rule_id or "legacy", severity, src, dst, "TCP", "msg", timestamp, json.dumps(details or {}),
                created_at, rule_id, count]
        if self.with_triage:
            cols += ", triage_status, triage_at"
            vals += [triage_status, triage_at]
        with sqlite3.connect(self.path) as conn:
            conn.execute(f"INSERT INTO alerts ({cols}) VALUES ({','.join('?' * len(vals))})", vals)

    def repeat(self, id, count, created_at) -> None:
        with sqlite3.connect(self.path) as conn:
            conn.execute("UPDATE alerts SET count=MAX(COALESCE(count,1), ?), created_at=? WHERE id=?",
                         (count, created_at, id))

    def set_triage(self, id, status, at) -> None:
        with sqlite3.connect(self.path) as conn:
            conn.execute("UPDATE alerts SET triage_status=?, triage_at=? WHERE id=?", (status, at, id))

    def clear(self) -> None:
        with sqlite3.connect(self.path) as conn:
            conn.execute("DELETE FROM alerts")


@pytest.fixture
def nids_db(tmp_path) -> NidsDb:
    return NidsDb(tmp_path / "nids_users.db")
