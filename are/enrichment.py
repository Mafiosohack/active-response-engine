"""Local ATT&CK and D3FEND lookups.

Both data files are pinned (version plus optional sha256) and loaded once at
startup. Nothing here touches the network, so a decision never waits on, or
leaks to, an outside service.
"""
from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from pathlib import Path

from .config import Config
from .models import ActionKind

logger = logging.getLogger(__name__)

_HASH_CHUNK_BYTES = 1 << 20


class EnrichmentError(RuntimeError):
    """Pinned data is missing, altered, or does not contain what config refers to."""


@dataclass(frozen=True)
class Technique:
    technique_id: str
    name: str
    tactics: tuple[str, ...]      # ATT&CK tactic short names, e.g. "credential-access"


@dataclass(frozen=True)
class D3fendTechnique:
    d3fend_id: str
    name: str


@dataclass(frozen=True)
class AttackData:
    techniques: dict[str, Technique]
    tactic_names: dict[str, str]          # short name -> display name
    tactic_order: tuple[str, ...]         # matrix order, used for stage progression


@dataclass(frozen=True)
class D3fendData:
    version: str | None
    by_name: dict[str, D3fendTechnique]   # lower-cased label -> technique


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(_HASH_CHUNK_BYTES):
            digest.update(chunk)
    return digest.hexdigest()


def _read_pinned(path: Path, sha256: str | None, label: str) -> dict:
    if not path.is_file():
        raise EnrichmentError(f"{label} data file not found: {path}. Run `are fetch-data` once to download it.")
    if sha256:
        actual = file_sha256(path)
        if actual.lower() != sha256.lower():
            raise EnrichmentError(f"{label} data file {path} does not match the pinned sha256 (got {actual}).")
    else:
        logger.warning("%s data file %s has no pinned sha256 in config", label, path)
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def load_attack(path: Path, sha256: str | None = None) -> AttackData:
    """Read technique names and tactics from an ATT&CK Enterprise STIX bundle."""
    bundle = _read_pinned(path, sha256, "ATT&CK")
    if bundle.get("type") != "bundle" or not isinstance(bundle.get("objects"), list):
        raise EnrichmentError(f"{path} is not a STIX bundle")

    techniques: dict[str, Technique] = {}
    tactic_names: dict[str, str] = {}
    tactic_by_stix_id: dict[str, str] = {}
    matrix_refs: list[str] = []
    for obj in bundle["objects"]:
        kind = obj.get("type")
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        if kind == "x-mitre-tactic":
            short = obj["x_mitre_shortname"]
            tactic_names[short] = obj["name"]
            tactic_by_stix_id[obj["id"]] = short
        elif kind == "x-mitre-matrix":
            matrix_refs = list(obj.get("tactic_refs", []))
        elif kind == "attack-pattern":
            ext_id = next(
                (r.get("external_id") for r in obj.get("external_references", []) if r.get("source_name") == "mitre-attack"),
                None,
            )
            if not ext_id:
                continue
            tactics = tuple(
                p["phase_name"] for p in obj.get("kill_chain_phases", []) if p.get("kill_chain_name") == "mitre-attack"
            )
            techniques[ext_id] = Technique(ext_id, obj["name"], tactics)

    if not techniques or not tactic_names:
        raise EnrichmentError(f"{path} contains no ATT&CK techniques or tactics")
    ordered = [tactic_by_stix_id[r] for r in matrix_refs if r in tactic_by_stix_id]
    ordered += sorted(t for t in tactic_names if t not in ordered)
    return AttackData(techniques, tactic_names, tuple(ordered))


def load_d3fend(path: Path, sha256: str | None = None) -> D3fendData:
    """Read defensive technique names and ids from the D3FEND JSON-LD ontology."""
    doc = _read_pinned(path, sha256, "D3FEND")
    graph = doc.get("@graph")
    if not isinstance(graph, list):
        raise EnrichmentError(f"{path} is not a D3FEND JSON-LD ontology (no @graph)")
    version = None
    by_name: dict[str, D3fendTechnique] = {}
    for node in graph:
        if node.get("@type") == "owl:Ontology" and isinstance(node.get("owl:versionInfo"), str):
            version = node["owl:versionInfo"]
        d3_id, label = node.get("d3f:d3fend-id"), node.get("rdfs:label")
        if isinstance(d3_id, str) and isinstance(label, str):
            by_name[label.lower()] = D3fendTechnique(d3_id, label)
    if not by_name:
        raise EnrichmentError(f"{path} contains no D3FEND techniques")
    return D3fendData(version, by_name)


def normalize_tactic(name: str) -> str:
    """'Privilege Escalation' / 'privilege_escalation' -> 'privilege-escalation'.

    Also used for correlation stage names, so sources may spell them either way.
    """
    return "-".join(str(name).strip().lower().replace("_", " ").replace("-", " ").split())


class Enricher:
    """Answers the three questions the core asks: tactic, names, countermeasure."""

    def __init__(self, attack: AttackData, d3fend: D3fendData, cfg: Config) -> None:
        self._attack = attack
        self._primary = dict(cfg.policy.primary_tactic)
        self._order = {t: i for i, t in enumerate(attack.tactic_order)}

        for tech_id, tactic in self._primary.items():
            tech = self.technique(tech_id)
            if tech is None:
                raise EnrichmentError(f"primary_tactic refers to {tech_id}, which is not in the pinned ATT&CK data")
            if tactic not in tech.tactics:
                raise EnrichmentError(
                    f"primary_tactic maps {tech_id} to '{tactic}', but its ATT&CK tactics are {list(tech.tactics)}"
                )
        for tactic in cfg.policy.quarantine_tactics:
            if tactic not in attack.tactic_names:
                raise EnrichmentError(f"quarantine_tactics entry '{tactic}' is not a tactic in the pinned ATT&CK data")
        for tech_id in cfg.policy.alert_only_techniques:
            if self.technique(tech_id) is None:
                raise EnrichmentError(f"alert_only_techniques entry {tech_id} is not in the pinned ATT&CK data")

        # Startup fails if a mapped countermeasure name is missing from the pinned file.
        self._countermeasures: dict[ActionKind, D3fendTechnique] = {}
        for kind, name in cfg.enrichment.d3fend_by_action.items():
            found = d3fend.by_name.get(name.lower())
            if found is None:
                raise EnrichmentError(f"d3fend_by_action maps '{kind}' to '{name}', which is not in the pinned D3FEND data")
            self._countermeasures[ActionKind(kind)] = found

    @classmethod
    def from_config(cls, cfg: Config) -> "Enricher":
        e = cfg.enrichment
        attack = load_attack(cfg.resolve(e.attack.path), e.attack.sha256)
        d3fend = load_d3fend(cfg.resolve(e.d3fend.path), e.d3fend.sha256)
        if d3fend.version and d3fend.version != e.d3fend.version:
            raise EnrichmentError(f"D3FEND file is version {d3fend.version}, config pins {e.d3fend.version}")
        return cls(attack, d3fend, cfg)

    def technique(self, technique_id: str | None) -> Technique | None:
        """Look a technique up; an unknown sub-technique falls back to its parent."""
        if not technique_id:
            return None
        found = self._attack.techniques.get(technique_id)
        if found is None and "." in technique_id:
            found = self._attack.techniques.get(technique_id.split(".", 1)[0])
        return found

    def tactic_for(self, technique_id: str | None) -> str | None:
        """The one tactic the policy uses for a technique.

        Config wins for multi-tactic techniques; otherwise the earliest tactic
        in matrix order is used so the result is deterministic.
        """
        tech = self.technique(technique_id)
        if tech is None or not tech.tactics:
            return None
        for key in (technique_id, tech.technique_id):
            if key in self._primary:
                return self._primary[key]
        return min(tech.tactics, key=lambda t: self._order.get(t, len(self._order)))

    def technique_name(self, technique_id: str | None) -> str | None:
        tech = self.technique(technique_id)
        return tech.name if tech else None

    def tactic_name(self, tactic: str | None) -> str | None:
        return self._attack.tactic_names.get(tactic) if tactic else None

    def countermeasure(self, kind: ActionKind) -> D3fendTechnique | None:
        return self._countermeasures.get(kind)
