"""nftables driver.

Owns exactly one table, `inet are`, and never touches any other. Blocks are
timed set elements, so the kernel expires them by itself: if the engine dies,
existing entries run out and new traffic flows (fail-open).

Every change goes to `nft -f -` as generated ruleset text on stdin, with the
command passed as an argument list. No shell is ever involved.
"""
from __future__ import annotations

import json
import logging
import subprocess

from ..config import NftablesConfig
from ..models import Action, ActionKind, ActiveEntry
from . import nft_script
from .base import EnforcerError

logger = logging.getLogger(__name__)

_NOT_FOUND_MARKERS = ("No such file or directory", "does not exist")


class NftablesEnforcer:
    name = "nftables"

    def __init__(self, cfg: NftablesConfig, management_hosts: list[str], load: bool = True) -> None:
        self._nft = cfg.nft_binary
        self._timeout = cfg.command_timeout_seconds
        self._base = nft_script.base_ruleset(management_hosts, cfg.throttle_rate_per_second, cfg.hook_priority)
        if load:
            self._run_script(self._base)
            logger.info("nftables table '%s %s' is in place", nft_script.FAMILY, nft_script.TABLE)

    def _exec(self, args: list[str], stdin: str | None = None) -> subprocess.CompletedProcess:
        try:
            return subprocess.run(
                [self._nft, *args], input=stdin, capture_output=True, text=True, timeout=self._timeout, check=False
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise EnforcerError(f"could not run {self._nft}: {exc}") from exc

    def _run_script(self, script: str, check: bool = True) -> subprocess.CompletedProcess:
        proc = self._exec(["-f", "-"], stdin=script)
        if check and proc.returncode != 0:
            raise EnforcerError(proc.stderr.strip() or f"nft exited with status {proc.returncode}")
        return proc

    def check(self) -> None:
        """Ask nft to validate the base ruleset without loading it (`nft -c`)."""
        proc = self._exec(["-c", "-f", "-"], stdin=self._base)
        if proc.returncode != 0:
            raise EnforcerError(proc.stderr.strip() or "nft rejected the ruleset")

    def apply(self, action: Action) -> str:
        add = nft_script.add_element(action)          # validates before anything runs
        # Adding an element that already exists keeps its old timeout, so clear
        # it first. A failed delete only means it was not there.
        self._run_script(nft_script.delete_element(action.ip, action.kind), check=False)
        self._run_script(add)
        return f"added to {nft_script.set_name(action.kind)}"

    def remove(self, ip: str, kind: ActionKind) -> None:
        proc = self._run_script(nft_script.delete_element(ip, kind), check=False)
        if proc.returncode != 0 and not any(m in proc.stderr for m in _NOT_FOUND_MARKERS):
            raise EnforcerError(proc.stderr.strip() or f"nft exited with status {proc.returncode}")

    def list_active(self) -> list[ActiveEntry]:
        proc = self._exec(["-j", "list", "table", nft_script.FAMILY, nft_script.TABLE])
        if proc.returncode != 0:
            raise EnforcerError(proc.stderr.strip() or "could not list the table")
        try:
            objects = json.loads(proc.stdout).get("nftables", [])
        except (ValueError, AttributeError) as exc:
            raise EnforcerError(f"unreadable nft JSON output: {exc}") from exc
        entries: list[ActiveEntry] = []
        for obj in objects:
            nft_set = obj.get("set") if isinstance(obj, dict) else None
            kind = nft_script.KIND_BY_SET.get(nft_set.get("name")) if nft_set else None
            if kind is None:
                continue
            for elem in nft_set.get("elem", []):
                inner = elem.get("elem") if isinstance(elem, dict) else None
                if inner is None:
                    continue      # an element without a timeout is not one of ours
                entries.append(ActiveEntry(kind, str(inner.get("val")), float(inner.get("expires", 0))))
        return entries

    def health(self) -> bool:
        try:
            return self._exec(["list", "table", nft_script.FAMILY, nft_script.TABLE]).returncode == 0
        except EnforcerError:
            return False
