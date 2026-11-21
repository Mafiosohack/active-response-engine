from __future__ import annotations

import json
import subprocess

import pytest

from are.enforcers import build_enforcer, nft_script
from are.enforcers.base import Enforcer, EnforcerError
from are.enforcers.dry_run import DryRunEnforcer
from are.enforcers.nftables import NftablesEnforcer
from are.models import Action, ActionKind
from are.replay import SimClock

BLOCK = Action(ActionKind.BLOCK, "203.0.113.9", 900, "42")


# ---- ruleset text ------------------------------------------------------------
def test_base_ruleset_owns_one_table_and_orders_rules_as_specified():
    text = nft_script.base_ruleset(["10.0.0.1"], 20, -10)
    lines = text.splitlines()
    assert lines[0] == "add table inet are"
    assert all(" inet are" in line for line in lines)                       # never touches another table
    assert "flush ruleset" not in text and "delete table" not in text       # reload keeps timed entries
    for name in ("throttle_v4", "reset_v4", "block_v4", "quarantine_v4", "block_dst_v4"):
        assert f"add set inet are {name} {{ type ipv4_addr; flags timeout; }}" in lines

    forward = [line for line in lines if line.startswith("add rule inet are forward")]
    order = ["@block_v4", "saddr @quarantine_v4", "daddr @quarantine_v4", "@block_dst_v4", "@reset_v4 meta l4proto tcp",
             "daddr @reset_v4", "saddr @reset_v4 counter drop", "@throttle_v4"]
    assert [next(i for i, line in enumerate(forward) if key in line) for key in order] == list(range(8))
    assert "ip saddr @quarantine_v4 ip daddr != { 10.0.0.1 } counter drop" in forward[1]
    assert "reject with tcp reset" in forward[4]
    assert "update @throttle_meter_v4 { ip saddr limit rate over 20/second } counter drop" in forward[7]
    assert "add rule inet are input ip saddr @block_v4 counter drop" in lines
    assert "hook forward priority -10" in text and "hook input priority -10" in text


def test_element_scripts():
    assert nft_script.add_element(BLOCK) == (
        'add element inet are block_v4 { 203.0.113.9 timeout 900s comment "decision-42" }\n')
    assert nft_script.delete_element("203.0.113.9", ActionKind.BLOCK) == (
        "delete element inet are block_v4 { 203.0.113.9 }\n")


@pytest.mark.parametrize("ip", [
    "203.0.113.9; flush ruleset", "203.0.113.9 }\nflush ruleset\n", "$(reboot)", "1.2.3.4/0", "2001:db8::1", "", "0x7f.1",
])
def test_anything_that_is_not_a_plain_ipv4_address_is_refused(ip):
    with pytest.raises(EnforcerError):
        nft_script.add_element(Action(ActionKind.BLOCK, ip, 900, "1"))
    with pytest.raises(EnforcerError):
        nft_script.delete_element(ip, ActionKind.BLOCK)
    with pytest.raises(EnforcerError):
        nft_script.base_ruleset([ip], 20, -10)


@pytest.mark.parametrize("action", [
    Action(ActionKind.BLOCK, "203.0.113.9", 900, '1" } ; flush ruleset ; #'),
    Action(ActionKind.BLOCK, "203.0.113.9", 0, "1"),
    Action(ActionKind.BLOCK, "203.0.113.9", 10**9, "1"),
    Action(ActionKind.OBSERVE, "203.0.113.9", 900, "1"),
    Action(ActionKind.ALERT, "203.0.113.9", 900, "1"),
])
def test_bad_decision_id_ttl_or_kind_is_refused(action):
    with pytest.raises(EnforcerError):
        nft_script.add_element(action)


# ---- dry_run -----------------------------------------------------------------
def test_dry_run_logs_exact_operations_changes_nothing_and_expires(cfg):
    clock = SimClock(100.0)
    d = DryRunEnforcer(cfg.nftables, ["10.0.0.1"], clock)
    assert isinstance(d, Enforcer) and d.health()
    assert d.operations[0][1] == nft_script.base_ruleset(["10.0.0.1"], 20, -10)

    d.apply(BLOCK)
    d.apply(BLOCK)                                                           # idempotent
    assert d.operations[-1][1] == nft_script.delete_element(BLOCK.ip, BLOCK.kind) + nft_script.add_element(BLOCK)
    (entry,) = d.list_active()
    assert (entry.kind, entry.ip, entry.remaining_seconds) == (ActionKind.BLOCK, "203.0.113.9", 900)

    clock.now += 901
    assert d.list_active() == []
    d.apply(BLOCK)
    d.remove(BLOCK.ip, BLOCK.kind)
    d.remove(BLOCK.ip, BLOCK.kind)                                           # removing twice is fine
    assert d.list_active() == []


def test_dry_run_is_the_default_driver(cfg):
    assert cfg.engine.driver == "dry_run"
    assert build_enforcer(cfg).name == "dry_run"


# ---- nftables (the nft binary is replaced by a recorder) ---------------------
class FakeNft:
    def __init__(self):
        self.calls: list[tuple[list[str], str | None]] = []
        self.fail_on: str | None = None
        self.stderr = "Error: Operation not permitted"
        self.stdout = ""

    def __call__(self, argv, input=None, capture_output=True, text=True, timeout=None, check=False, **kw):
        assert isinstance(argv, list) and "shell" not in kw, "nft must be run from an argument list, never a shell"
        self.calls.append((argv, input))
        failed = self.fail_on is not None and self.fail_on in (input or " ".join(argv))
        return subprocess.CompletedProcess(argv, 1 if failed else 0, self.stdout, self.stderr if failed else "")


@pytest.fixture
def nft(monkeypatch):
    fake = FakeNft()
    monkeypatch.setattr(subprocess, "run", fake)
    return fake


def test_nftables_loads_base_ruleset_through_nft_f_stdin(cfg, nft):
    NftablesEnforcer(cfg.nftables, ["10.0.0.1"])
    argv, script = nft.calls[0]
    assert argv == ["/usr/sbin/nft", "-f", "-"]
    assert script == nft_script.base_ruleset(["10.0.0.1"], 20, -10)


def test_nftables_apply_clears_then_adds_and_remove_tolerates_absence(cfg, nft):
    driver = NftablesEnforcer(cfg.nftables, ["10.0.0.1"])
    nft.calls.clear()
    driver.apply(BLOCK)
    assert [c[1] for c in nft.calls] == [nft_script.delete_element(BLOCK.ip, BLOCK.kind), nft_script.add_element(BLOCK)]

    nft.fail_on, nft.stderr = "delete element", "Error: Could not process rule: No such file or directory"
    driver.remove(BLOCK.ip, BLOCK.kind)                                      # already gone: not an error
    nft.stderr = "Error: Operation not permitted"
    with pytest.raises(EnforcerError, match="Operation not permitted"):
        driver.remove(BLOCK.ip, BLOCK.kind)


def test_nftables_failures_come_back_as_enforcer_errors(cfg, nft):
    driver = NftablesEnforcer(cfg.nftables, ["10.0.0.1"])
    nft.fail_on = "add element"
    with pytest.raises(EnforcerError, match="Operation not permitted"):
        driver.apply(BLOCK)
    calls_before = len(nft.calls)
    with pytest.raises(EnforcerError):
        driver.apply(Action(ActionKind.BLOCK, "203.0.113.9; flush ruleset", 900, "1"))
    assert len(nft.calls) == calls_before                                    # rejected before nft was ever run


def test_nftables_binary_missing_is_reported(cfg, monkeypatch):
    def boom(*a, **kw):
        raise FileNotFoundError("nft")

    monkeypatch.setattr(subprocess, "run", boom)
    with pytest.raises(EnforcerError, match="could not run"):
        NftablesEnforcer(cfg.nftables, ["10.0.0.1"])


def test_nftables_list_active_reads_set_elements_and_health(cfg, nft):
    driver = NftablesEnforcer(cfg.nftables, ["10.0.0.1"])
    nft.stdout = json.dumps({"nftables": [
        {"metainfo": {"version": "1.0.9"}},
        {"table": {"family": "inet", "name": "are"}},
        {"set": {"family": "inet", "name": "block_v4", "table": "are", "type": "ipv4_addr",
                 "elem": [{"elem": {"val": "203.0.113.9", "timeout": 900, "expires": 873, "comment": "decision-42"}}]}},
        {"set": {"family": "inet", "name": "throttle_meter_v4", "table": "are", "elem": [{"elem": {"val": "1.1.1.1"}}]}},
        {"set": {"family": "inet", "name": "reset_v4", "table": "are"}},
        {"chain": {"family": "inet", "table": "are", "name": "forward"}},
    ]})
    (entry,) = driver.list_active()
    assert (entry.kind, entry.ip, entry.remaining_seconds) == (ActionKind.BLOCK, "203.0.113.9", 873.0)
    assert driver.health()
    nft.fail_on = "list table"
    assert not driver.health()


def test_check_validates_without_loading(cfg, nft):
    driver = NftablesEnforcer(cfg.nftables, ["10.0.0.1"], load=False)
    assert nft.calls == []
    driver.check()
    assert nft.calls[0][0] == ["/usr/sbin/nft", "-c", "-f", "-"]
