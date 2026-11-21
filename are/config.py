"""Typed, validated view of config.yaml.

Every tunable number in the engine lives here. Unknown keys are rejected so a
typo in the config fails at startup instead of silently using a default.
"""
from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .models import ENFORCED_KINDS, Severity

_SECONDS_PER_DAY = 86400.0


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EngineConfig(_Strict):
    db_path: str = "ips.db"
    poll_interval_seconds: float = Field(2.0, gt=0)
    tick_seconds: float = Field(30.0, gt=0)
    # dry_run is the default so a fresh install never touches the firewall.
    driver: Literal["dry_run", "nftables"] = "dry_run"
    # Rows in ips.db older than this are deleted. null keeps everything forever.
    retention_days: float | None = Field(30.0, gt=0)


class NetworkConfig(_Strict):
    internal_networks: list[str] = Field(default_factory=list)
    allowlist: list[str] = Field(default_factory=list)
    management_hosts: list[str] = Field(default_factory=list)

    @field_validator("internal_networks", "allowlist")
    @classmethod
    def _valid_cidrs(cls, value: list[str]) -> list[str]:
        return [str(ipaddress.ip_network(v, strict=False)) for v in value]

    @field_validator("management_hosts")
    @classmethod
    def _valid_hosts(cls, value: list[str]) -> list[str]:
        return [str(ipaddress.IPv4Address(v)) for v in value]


class MLConfig(_Strict):
    floor: float = Field(0.5, ge=0, lt=1)       # alerts only exist at p >= floor
    cap: float = Field(4.0, ge=0)               # per (src, dst) group
    repeat_weight: float = Field(0.25, ge=0)
    # Total ML points one source can earn across all its destinations.
    # null disables the per-source cap and leaves only the per-group cap.
    per_ip_cap: float | None = Field(4.0, ge=0)
    # ML counts as an independent family only if some ML group's best probability
    # reaches this; below it, ML still adds its points. null = any scoring ML counts.
    family_min_probability: float | None = Field(0.8, ge=0, le=1)


class ScoringConfig(_Strict):
    window_seconds: float = Field(600.0, gt=0)
    severity_points: dict[str, float] = Field(
        default_factory=lambda: {"critical": 10, "high": 6, "medium": 3, "low": 1, "info": 0}
    )
    repeat_cap_multiplier: float = Field(3.0, ge=1)
    ml: MLConfig = Field(default_factory=MLConfig)

    @field_validator("severity_points")
    @classmethod
    def _all_severities(cls, value: dict[str, float]) -> dict[str, float]:
        expected = {s.value for s in Severity}
        if set(value) != expected:
            raise ValueError(f"severity_points must define exactly {sorted(expected)}")
        return value


class RungConfig(_Strict):
    score: float = Field(ge=0)
    ttl_seconds: int = Field(gt=0)


class BlockRungConfig(RungConfig):
    families: int = Field(2, ge=1)


class LongBlockConfig(_Strict):
    repeat_window_seconds: float = Field(86400.0, gt=0)
    ttl_seconds: int = Field(7200, gt=0)


class PolicyConfig(_Strict):
    throttle: RungConfig = Field(default_factory=lambda: RungConfig(score=4, ttl_seconds=600))
    reset: RungConfig = Field(default_factory=lambda: RungConfig(score=8, ttl_seconds=600))
    block: BlockRungConfig = Field(default_factory=lambda: BlockRungConfig(score=12, ttl_seconds=900))
    long_block: LongBlockConfig = Field(default_factory=LongBlockConfig)
    alert_only_techniques: list[str] = Field(default_factory=lambda: ["T1557.002", "T1200"])
    alert_only_rules: list[str] = Field(default_factory=lambda: ["Impossible Travel"])
    quarantine_tactics: list[str] = Field(
        default_factory=lambda: ["command-and-control", "exfiltration", "lateral-movement", "collection"]
    )
    primary_tactic: dict[str, str] = Field(default_factory=lambda: {"T1078": "initial-access"})
    # Lowest quarantine-ladder rung at which the external destination is also blocked.
    block_dst_min_rung: int = Field(2, ge=1, le=4)
    instant_block_families: list[str] = Field(default_factory=lambda: ["honeypot"])
    # Also raise a rung when the source's own alerts move forward along the kill
    # chain (each alert's stage comes from its adapter), not only when a
    # correlated incident says so.
    progression_from_alerts: bool = True
    # Stage order used to decide whether a correlated incident moved forward.
    # It must use the stage names the adapters emit, in the order they advance.
    kill_chain_order: list[str] = Field(
        default_factory=lambda: [
            "reconnaissance", "credential_access", "initial_access", "privilege_escalation", "persistence",
            "command_and_control", "lateral_movement", "collection", "exfiltration",
        ]
    )


class DataFileConfig(_Strict):
    path: str
    version: str
    url: str
    sha256: str | None = None

    @field_validator("url")
    @classmethod
    def _https_only(cls, value: str) -> str:
        if not value.startswith("https://"):
            raise ValueError("data file url must use https")
        return value


class EnrichmentConfig(_Strict):
    attack: DataFileConfig
    d3fend: DataFileConfig
    d3fend_by_action: dict[str, str]

    @field_validator("d3fend_by_action")
    @classmethod
    def _covers_every_action(cls, value: dict[str, str]) -> dict[str, str]:
        expected = {k.value for k in ENFORCED_KINDS}
        if set(value) != expected:
            raise ValueError(f"d3fend_by_action must map exactly {sorted(expected)}")
        return value


class NftablesConfig(_Strict):
    throttle_rate_per_second: int = Field(20, ge=1, le=1_000_000)
    # Lower than the standard filter priority (0) so this chain runs first.
    hook_priority: int = Field(-10, ge=-400, le=400)
    nft_binary: str = "/usr/sbin/nft"
    command_timeout_seconds: float = Field(10.0, gt=0)


class ApiConfig(_Strict):
    enabled: bool = True
    host: str = "127.0.0.1"
    port: int = Field(8088, ge=1, le=65535)


class Config(_Strict):
    engine: EngineConfig = Field(default_factory=EngineConfig)
    network: NetworkConfig = Field(default_factory=NetworkConfig)
    scoring: ScoringConfig = Field(default_factory=ScoringConfig)
    policy: PolicyConfig = Field(default_factory=PolicyConfig)
    enrichment: EnrichmentConfig
    nftables: NftablesConfig = Field(default_factory=NftablesConfig)
    api: ApiConfig = Field(default_factory=ApiConfig)
    # Each adapter validates its own section; the core never looks inside.
    adapters: dict[str, dict[str, Any]] = Field(default_factory=dict)
    base_dir: str = "."

    @model_validator(mode="after")
    def _rungs_ascend(self) -> "Config":
        p = self.policy
        if not p.throttle.score <= p.reset.score <= p.block.score:
            raise ValueError("policy score thresholds must ascend: throttle <= reset <= block")
        return self

    @model_validator(mode="after")
    def _retention_covers_what_the_engine_reads(self) -> "Config":
        """Pruning must never delete a row the engine still reads.

        The engine reads back the repeat-offender history (for the long block)
        and the evidence behind every action still in force (to re-judge it
        when an alert is marked false positive).
        """
        days = self.engine.retention_days
        if days is None:
            return self
        p = self.policy
        longest_ttl = max(p.throttle.ttl_seconds, p.reset.ttl_seconds, p.block.ttl_seconds, p.long_block.ttl_seconds)
        needed = max(p.long_block.repeat_window_seconds, self.scoring.window_seconds + longest_ttl)
        if days * _SECONDS_PER_DAY < needed:
            raise ValueError(
                f"engine.retention_days must be at least {needed / _SECONDS_PER_DAY:.2f} "
                "(the repeat-offender window, or the scoring window plus the longest action)"
            )
        return self

    def resolve(self, path: str) -> Path:
        """Resolve a config-relative path against the directory of config.yaml."""
        p = Path(path)
        return p if p.is_absolute() else Path(self.base_dir) / p


def load_config(path: str | Path) -> Config:
    path = Path(path)
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, dict):
        raise ValueError(f"{path}: top level must be a mapping")
    data["base_dir"] = str(path.resolve().parent)
    return Config.model_validate(data)
