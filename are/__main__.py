"""Command line: are run | replay | check | fetch-data | status | decisions | unblock."""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path

from .config import Config, load_config

logger = logging.getLogger("are")

TOKEN_ENV = "ARE_API_TOKEN"
_DOWNLOAD_CHUNK_BYTES = 1 << 20
_HTTP_TIMEOUT_SECONDS = 10


def _load_env() -> None:
    """Read a local .env file if python-dotenv is installed (the token lives there, never in config)."""
    try:
        from dotenv import load_dotenv
    except ImportError:
        return
    load_dotenv()


# ---------------------------------------------------------------------------- run
def cmd_run(cfg: Config, args: argparse.Namespace) -> int:
    from .app import Service, build_runtime

    runtime = build_runtime(cfg)
    service = Service(runtime)
    token = os.environ.get(TOKEN_ENV, "")
    if not cfg.api.enabled or args.no_api or not token:
        if cfg.api.enabled and not args.no_api:
            logger.warning("%s is not set: running without the HTTP API", TOKEN_ENV)
        try:
            service.run_forever()
        except KeyboardInterrupt:
            service.stop()
        return 0

    import uvicorn

    from .api import create_app

    app = create_app(runtime.engine, runtime.store, runtime.adapters, token)
    worker = threading.Thread(target=service.run_forever, name="are-engine", daemon=True)
    worker.start()
    try:
        uvicorn.run(app, host=cfg.api.host, port=cfg.api.port, log_level="warning")
    finally:
        service.stop()
        worker.join(timeout=cfg.engine.poll_interval_seconds * 2)
    return 0


# ---------------------------------------------------------------------------- replay
def cmd_replay(cfg: Config, args: argparse.Namespace) -> int:
    from .enrichment import Enricher
    from .replay import load_labels, render_text, run_replay, write_report
    from .store import Store

    kind = args.source[0]
    enricher = Enricher.from_config(cfg)
    labels = load_labels(args.labels) if args.labels else None

    if kind == "evidence":
        db = Path(args.source[1]) if len(args.source) > 1 else cfg.resolve(cfg.engine.db_path)
        if not db.is_file():
            print(f"error: decision log not found: {db}", file=sys.stderr)
            return 2
        store = Store(str(db))
        evidence = store.evidence_between(args.start, args.end)
        triage = store.triage_between(args.start, args.end)
        store.close()
        report = run_replay(cfg, enricher, evidence, triage, source=f"recorded evidence in {db}",
                            start=args.start, end=args.end, labels=labels)
    elif kind == "nids-db":
        if len(args.source) != 2:
            print("error: --source nids-db needs the path of a NIDS database copy", file=sys.stderr)
            return 2
        from .adapters import MemoryState, build_nids_adapter

        snapshot = build_nids_adapter(cfg, MemoryState(), db_path=args.source[1]).snapshot()
        triage = [(event.at, event) for event in snapshot.triage]
        report = run_replay(cfg, enricher, snapshot.evidence, triage, source=f"NIDS database copy {args.source[1]}",
                            approximate=True, start=args.start, end=args.end, labels=labels)
    else:
        print("error: --source must be 'evidence' or 'nids-db <path>'", file=sys.stderr)
        return 2

    json_path, text_path = write_report(report, args.out)
    print(render_text(report))
    print(f"Report written to {json_path} and {text_path}")
    return 0


# ---------------------------------------------------------------------------- check
def cmd_check(cfg: Config, args: argparse.Namespace) -> int:
    from .adapters import MemoryState, build_adapters
    from .enforcers import nft_script
    from .enrichment import Enricher

    enricher = Enricher.from_config(cfg)
    print("config: ok")
    print("pinned ATT&CK and D3FEND data: ok")
    for adapter in build_adapters(cfg, MemoryState()):
        table = getattr(adapter, "cfg", None)
        unknown = sorted({t for t in getattr(table, "techniques", {}).values() if enricher.technique(t) is None})
        print(f"adapter {adapter.name}: ok" + (f" (techniques not in pinned ATT&CK: {unknown})" if unknown else ""))
    ruleset = nft_script.base_ruleset(cfg.network.management_hosts, cfg.nftables.throttle_rate_per_second,
                                      cfg.nftables.hook_priority)
    print(f"driver: {cfg.engine.driver}\n\nnftables ruleset this engine owns:\n{ruleset}")
    if args.nft:
        from .enforcers.nftables import NftablesEnforcer

        NftablesEnforcer(cfg.nftables, cfg.network.management_hosts, load=False).check()
        print("nft -c accepted the ruleset (nothing was loaded)")
    return 0


# ---------------------------------------------------------------------------- fetch-data
def cmd_fetch_data(cfg: Config, args: argparse.Namespace) -> int:
    from .enrichment import file_sha256

    status = 0
    for label, item in (("ATT&CK", cfg.enrichment.attack), ("D3FEND", cfg.enrichment.d3fend)):
        target = cfg.resolve(item.path)
        if target.is_file() and not args.force:
            print(f"{label}: {target} already present (use --force to download again)")
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            partial = target.with_suffix(target.suffix + ".part")
            print(f"{label}: downloading version {item.version} ...")
            with urllib.request.urlopen(item.url, timeout=60) as resp, partial.open("wb") as fh:  # noqa: S310 - https enforced by config
                while chunk := resp.read(_DOWNLOAD_CHUNK_BYTES):
                    fh.write(chunk)
            partial.replace(target)
        actual = file_sha256(target)
        if item.sha256 and actual.lower() != item.sha256.lower():
            print(f"{label}: SHA-256 MISMATCH. expected {item.sha256}, got {actual}. Delete {target} and retry.",
                  file=sys.stderr)
            status = 1
        elif item.sha256:
            print(f"{label}: sha256 matches the pinned value")
        else:
            print(f"{label}: sha256 is {actual}; add it to config.yaml to pin this file")
    return status


# ---------------------------------------------------------------------------- API clients
def _api(cfg: Config, method: str, path: str, body: dict | None = None):
    token = os.environ.get(TOKEN_ENV, "")
    if not token:
        raise SystemExit(f"error: {TOKEN_ENV} is not set")
    request = urllib.request.Request(
        f"http://{cfg.api.host}:{cfg.api.port}{path}",
        method=method,
        data=json.dumps(body).encode("utf-8") if body is not None else None,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=_HTTP_TIMEOUT_SECONDS) as resp:  # noqa: S310 - local API only
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise SystemExit(f"error: API answered {exc.code}: {exc.read().decode('utf-8', 'replace')}") from None
    except urllib.error.URLError as exc:
        raise SystemExit(f"error: cannot reach the engine API at {cfg.api.host}:{cfg.api.port}: {exc.reason}") from None


def cmd_status(cfg: Config, args: argparse.Namespace) -> int:
    print(json.dumps({"status": _api(cfg, "GET", "/status"), "active": _api(cfg, "GET", "/active")}, indent=2))
    return 0


def cmd_decisions(cfg: Config, args: argparse.Namespace) -> int:
    query = f"?limit={int(args.limit)}" + (f"&ip={args.ip}" if args.ip else "")
    for d in reversed(_api(cfg, "GET", "/decisions" + query)):
        print(f"#{d['decision_id']}  {d['ip']}  rung {d['rung']}  {d['kind']}  [{d['driver']}: {d['driver_result']}]")
        for line in d["explanation"].splitlines():
            print(f"    {line}")
        print()
    return 0


def cmd_unblock(cfg: Config, args: argparse.Namespace) -> int:
    result = _api(cfg, "POST", "/unblock", {"ip": args.ip, "who": "cli"})
    print(f"{result['ip']}: reversed decisions {result['reversed_decisions'] or 'none (nothing was active)'}")
    return 0


# ---------------------------------------------------------------------------- entry point
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="are", description="Active Response Engine")
    parser.add_argument("-c", "--config", default="config.yaml", help="path to config.yaml")
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="run the engine (and the local API if ARE_API_TOKEN is set)")
    run.add_argument("--no-api", action="store_true")
    run.set_defaults(func=cmd_run)

    replay = sub.add_parser("replay", help="run recorded alerts through the current policy; enforces nothing")
    replay.add_argument("--source", nargs="+", required=True, metavar="SOURCE",
                        help="'evidence [ips.db]' or 'nids-db <path to a NIDS database copy>'")
    replay.add_argument("--from", dest="start", type=float, default=None, help="epoch seconds")
    replay.add_argument("--to", dest="end", type=float, default=None, help="epoch seconds")
    replay.add_argument("--labels", help="labels file (YAML/JSON): ip, label attacker|benign, from, to")
    replay.add_argument("--out", default="replay_out", help="directory for the JSON and text report")
    replay.set_defaults(func=cmd_replay)

    check = sub.add_parser("check", help="validate config and pinned data, print the nftables ruleset")
    check.add_argument("--nft", action="store_true", help="also ask nft to validate the ruleset (nft -c, loads nothing)")
    check.set_defaults(func=cmd_check)

    fetch = sub.add_parser("fetch-data", help="download the pinned ATT&CK and D3FEND files once")
    fetch.add_argument("--force", action="store_true")
    fetch.set_defaults(func=cmd_fetch_data)

    sub.add_parser("status", help="engine status and active actions (via the local API)").set_defaults(func=cmd_status)

    decisions = sub.add_parser("decisions", help="recent decisions with explanations (via the local API)")
    decisions.add_argument("--ip")
    decisions.add_argument("--limit", type=int, default=20)
    decisions.set_defaults(func=cmd_decisions)

    unblock = sub.add_parser("unblock", help="lift everything active on an IP (via the local API)")
    unblock.add_argument("ip")
    unblock.set_defaults(func=cmd_unblock)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    quiet = args.command == "replay" and not args.verbose      # replay prints a report, not a log
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.ERROR if quiet else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    _load_env()
    try:
        cfg = load_config(args.config)
        return args.func(cfg, args)
    except (OSError, ValueError, RuntimeError) as exc:
        # Config, pinned-data, adapter and driver errors are all operator-fixable: say what and stop.
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
