# Active Response Engine: where we stopped (2026-11-12)

Saved so the work can be picked up in a new session. `README.md` explains the
system itself; this file records the state of the build and what is still open.

## State

The engine is built and working in dry-run mode.

- 135 tests pass on Python 3.14 and 3.12 (`python -m pytest`).
- `python -m are check` passes against the real pinned ATT&CK v20.1 and
  D3FEND 1.6.0 files in `data/`.
- A live run with the dry-run driver went through the whole cycle: poll the
  NIDS database, throttle -> reset -> block, an alert-only decision for ARP
  spoofing, a false-positive mark lifting the block (falling back to reset),
  and a manual unblock through the token-protected API.
- A replay of a copy of the recorded `nids_users.db` (3 rows) produced a
  timeline and explanations, labelled approximate.

Not tested:

- The nftables driver against a real kernel. It was only run against a
  stand-in for the `nft` binary. Run `are check --nft` on the VM first.
- Python 3.10 (Ubuntu 22.04's default).

Nothing is committed; the folder is not a git repository.

## Added 2026-11-15

- Confirmed: the NIDS, the router and this engine all run on one VM, so no
  remote adapter is needed.
- `ips.db` retention (`engine.retention_days`, default 30). 147 tests pass on
  Python 3.14.
- `deploy/are.service` and `deploy/install.sh`. Written on Windows and only
  syntax-checked: neither has run on Linux yet. See "Run it as a service" in
  the README.
- Decided: alert-only decisions are to be sent to the NIDS dashboard. Not
  built yet.

## Added 2026-11-16

- Decided both open questions: internal hosts stay on the graded ladder, and
  ML counts as a family only at p >= 0.8 (decision 2 below). 156 tests pass on
  Python 3.14.

## Added 2026-11-21

- Module walk-through given in conversation.
- Pushed to a private GitHub repository (see "Where things are").
- NIDS fix (nids repo, branch `flush-repeat-counts`, not merged into main yet): `main.py`
  now writes deferred repeat counts every second from a background thread
  (`REPEAT_FLUSH_SEC`, env `NIDS_REPEAT_FLUSH_SEC`). Before, the end of a repeat
  burst stayed in memory until someone opened History. New test in
  `tests/test_alert_history.py`. The NIDS suite has 3 failures in
  `test_browser_hardening` that happen without this change too.
- Engine: each evidence record carries its NIDS kill-chain stage
  (`adapters.nids.stages`), and the policy raises the rung by one when a
  source's own alerts advance along the chain (`policy.progression_from_alerts`).
  Needed because the NIDS announces a correlated incident only once, when it
  opens. `ips.db` gains a `stage` column, added in place to an existing file.
  165 tests pass on Python 3.14.

Still to build: alert delivery to the NIDS dashboard, a liveness check, and
whatever the real-kernel nftables test turns up. One known driver gap: if
something flushes the nftables ruleset while the engine runs (other than a
restart of `nftables.service`, which the unit handles), the engine's table is
gone and every later action fails until the engine is restarted.

## Before running it on the VM

1. Fill in `network.internal_networks`, `allowlist` and `management_hosts` in
   `config.yaml`. They are empty because the lab addressing was not known.
2. Set `adapters.nids.db_path` to where `nids_users.db` lives on the VM.
3. Run `are fetch-data` on the VM, or copy the `data/` folder across.
4. Put a long random `ARE_API_TOKEN` in `.env` (see `.env.example`).
5. Leave `engine.driver: dry_run` until `are replay` looks right, then run
   `are check --nft` and switch to `nftables`.

## Decisions still open

These are places where the handoff and the NIDS code disagree, or where a
choice had to be made. Three were answered on 2026-11-12 and the internal-host
ladder and the ML cut-off on 2026-11-16. None are open.

1. **Handshake flags the NIDS code does not back up. DECIDED.** The handoff
   marks `BRUTEFORCE_*`, `LATERAL_*` and `BEHAVIOR_*` as handshake-confirmed.
   In the NIDS, brute force fires on bare SYNs, and the lateral/C2 checks fire
   on SYN -> SYN-ACK; neither proves the source address. The recommendation
   was approved: `BRUTEFORCE_*` is now `handshake: false` in `config.yaml`.
   Network brute force alone stops at throttle until the host sensor confirms
   it. `LATERAL_*` and `BEHAVIOR_*` keep the handoff's value (true).
2. **ML counts as an independent family. DECIDED (2026-11-16): only when
   confident.** Before, any ML alert above the 0.5 floor counted, so a p=0.51
   alert (0.08 points) turned a reset into a block. Now ML counts as a family
   only if some destination's best p is >= 0.8
   (`scoring.ml.family_min_probability`, the NIDS `HIGH_CONFIDENCE` line);
   below that it adds points only. Reasons: the live model flags 4.4% of benign
   hold-out flows (`models/cicids_live_meta.json`, worse on the lossy live
   schema), and it reads the same packets as the signature rules.
   `ANOMALY_TRAFFIC_BASELINE` is a rate check, not ML, but stays in
   `anomaly_ml`; with no probability it never counts as a family.
3. **Per-source ML cap of 4 points. DECIDED: keep.** An addition, not in the
   handoff, whose cap is per (source, destination).
4. **Internal hosts. DECIDED (2026-11-16): keep the ladder.** Any internal source with technique-bearing
   evidence goes on the graduated quarantine ladder (alert, reset,
   quarantine), plus a block on the external destination of its C2 /
   exfiltration / lateral / collection evidence from rung 2 upward
   (`policy.block_dst_min_rung`). The alternative was immediate quarantine on
   the first such alert; the user chose the ladder.
5. **Family-table additions. DECIDED: keep.** `ACTIVE_INTRUSION`
   (correlation), `MITM_ARP_SPOOF` and `ASSET_ROGUE_HOST` (both alert-only)
   stay in the family table.

Smaller points, already documented in the README under "Behaviours worth
knowing": actions run their full duration, manual unblock discards that IP's
evidence, IPv6 is observe-only. ATT&CK v20 renamed Defense Evasion to Stealth
and Defense Impairment, so tactic names in explanations follow that.

## Still owed

Nothing. The module walk-through was given in conversation on 2026-11-21.

## Where things are

- Project: `C:\Users\seifc\Downloads\Active Repsonse Engine`
- GitHub (private): https://github.com/Mafiosohack/active-response-engine
- NIDS source the adapter was written against:
  `C:\Users\seifc\Downloads\Compressed\nids` (read-only; not the older
  `Downloads\nids`)
