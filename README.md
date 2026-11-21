# Active Response Engine

Reads alerts from an existing network IDS and turns them into graduated,
explainable firewall responses on a Linux router.

**What it is.** A decision-and-response layer that sits on top of an IDS, in the
same category as fail2ban, CrowdSec and Wazuh active response.

**What it is not.** It is not an inline packet-inspecting IPS. It reacts to
alerts *after* they fire, so it blocks what comes next, not the packet that
triggered the alert.

## Quick start

```bash
python3 -m venv venv && . venv/bin/activate
pip install -r requirements.txt
pip install -e .                      # gives you the `are` command (or use `python -m are`)

are fetch-data                        # once: downloads the pinned ATT&CK and D3FEND files, checks sha256
# edit config.yaml: network.*, adapters.nids.db_path
are check                             # validates config + pinned data, prints the nftables ruleset
python -m pytest                      # 165 tests, no firewall or network needed
```

Run it in dry-run first (the default driver). It logs the exact nftables
operations it would perform and changes nothing:

```bash
cp .env.example .env                  # put a long random ARE_API_TOKEN in it
are run
are decisions                         # recent decisions with their explanations
are status
are unblock 203.0.113.9
```

See what the policy would have done with alerts you already recorded:

```bash
are replay --source evidence --from 1786470000 --to 1786480000        # from ips.db, exact
are replay --source nids-db /path/to/copy/of/nids_users.db            # from a NIDS database copy, approximate
are replay --source evidence --labels labels.yaml                     # adds false positives / time-to-action
```

`labels.yaml` is a list you write for a lab run:

```yaml
- {ip: 203.0.113.9,  label: attacker, from: 1786470000, to: 1786480000}
- {ip: 10.10.20.15,  label: benign,   from: 1786470000, to: 1786480000}
```

When replay looks right, enforce (on the router, as root):

```bash
are check --nft                       # asks nft to validate the ruleset; loads nothing
# config.yaml: engine.driver: nftables
sudo -E are run
sudo nft list table inet are          # the only table this engine owns
```

If the engine stops, existing entries expire on their own and new traffic flows
(fail-open). `sudo nft delete table inet are` removes everything it ever did.

## Run it as a service

On the router VM, from the project folder:

```bash
sudo sh deploy/install.sh             # safe to run again after a code update
sudoedit /opt/are/config.yaml         # network.*, adapters.nids.db_path
sudo are check
sudo systemctl enable --now are       # starts now and on every boot
sudo journalctl -u are -f
```

| Where | What |
|---|---|
| `/opt/are` | code, virtualenv, `config.yaml`, `data/` |
| `/etc/are/are.env` | `ARE_API_TOKEN`, generated on first install, root-only |
| `/var/lib/are/ips.db` | the decision log, the only place the service can write |
| `/usr/local/bin/are` | the `are` command, already pointed at the installed config and token |

The unit (`deploy/are.service`) runs as root with every capability dropped
except changing nftables and reading files, on a read-only filesystem. It
restarts on a crash, but not on a config error (exit status 2), and restarts
together with `nftables.service`, because reloading the system firewall wipes
the engine's table. After a restart every action still in force is re-applied
with its remaining time.

## How the pieces fit

```
NIDS database --(read-only)--> adapter --Evidence--> engine --Action--> driver --> nftables
                                                       |  ^
                                    scoring + policy <-+  +-- triage events, manual unblock
                                                       |
                                                    ips.db (evidence, decisions)
```

The core never imports NIDS code or a concrete firewall driver. A test
(`test_core_never_imports_...`) enforces that.

## The modules, in plain English

| Module | What it does |
|---|---|
| `are/models.py` | The shared vocabulary. `Evidence` is the one shape every alert takes when it enters the core. `Decision` is one row of the decision log. `Action` is what the core asks a driver to do. |
| `are/config.py` | Reads `config.yaml` into typed, validated settings. Every tunable number lives there. An unknown key is an error, so a typo cannot silently fall back to a default. |
| `are/enrichment.py` | Loads the pinned ATT&CK and D3FEND files once at startup (version and sha256 checked) and answers three questions: which tactic a technique belongs to, what things are called, and which D3FEND countermeasure matches an action. No network access, ever. Startup fails if config names something the pinned files do not contain. |
| `are/scoring.py` | Turns one source IP's evidence into a number. Severity becomes points; repeats of one rule add slowly (logarithm, capped at 3x); ML evidence is rescaled so "just over the alert threshold" scores zero, and is capped at 4 points; it counts as a family only at p >= 0.8. Pure maths, no clock, no database. |
| `are/policy.py` | The four checks: allowlist, response target, rung, action. Given the current evidence for an IP it says what *should* be true (for example "rung 2, reset, 10 min") and why the next rung was not reached. It never applies anything. |
| `are/explain.py` | Writes the plain-English explanation from the decision record alone: what was done, the score and families, the tactic and countermeasure, and why not one rung higher. No free text, so the same record always gives the same words. |
| `are/store.py` | `ips.db`, the engine's own SQLite database: every evidence record as received, every triage event, the decision log, and the adapter's bookmarks. |
| `are/engine.py` | The part with memory. Keeps each IP's evidence inside the 10-minute window and whatever action is in force, asks the policy on every new evidence record and every 30 s, and acts only when the answer is a *higher* rung than what is active. Also handles expiry, triage reversals, manual unblock, restart recovery and driver failures. |
| `are/adapters/base.py` | The adapter contract: `poll()` returns new evidence and triage events. |
| `are/adapters/nids.py` | The only code that knows the NIDS schema. Opens `nids_users.db` read-only, works out how many *new* occurrences each alert row has since last time, maps each rule to a family / handshake flag / ATT&CK technique from config, and reports analyst verdicts. |
| `are/enforcers/base.py` | The driver contract: `apply`, `remove`, `list_active`, `health`. Drivers never decide anything. |
| `are/enforcers/nft_script.py` | Generates the nftables ruleset text. Every address is parsed with Python's `ipaddress` module first, so nothing from an alert can change the shape of a rule. |
| `are/enforcers/dry_run.py` | Logs the exact nftables operations and changes nothing. The default driver, and the one replay always uses. |
| `are/enforcers/nftables.py` | Feeds that same text to `nft -f -`. Owns one table, `inet are`. Blocks are timed set elements, so the kernel does the expiry. |
| `are/replay.py` | Builds a throwaway engine on a simulated clock with the dry-run driver, feeds it recorded alerts in time order, and writes a JSON and a text report. |
| `are/api.py` | Small local HTTP API (bearer token, 127.0.0.1): decisions, active actions, one IP's current assessment, manual unblock. |
| `are/app.py` | Wiring. Builds everything from config and runs the 2-second polling loop, including the hourly clean-up of old `ips.db` rows. |
| `are/__main__.py` | The `are` command. |

## The rules the engine follows

**Score.** Evidence is grouped per source IP inside a 600 s sliding window.

* A rule group scores `base x (1 + log2(count))`, capped at `3 x base`
  (critical 10, high 6, medium 3, low 1, info 0).
* ML evidence, per (source, destination): `min(4, 4 x s x (1 + 0.25 x log2(count)))`
  where `s = (p - 0.5) / 0.5`. One source's ML total is also capped at 4.
  ML is an independent family only if some destination's best p is >= 0.8.
* Correlated incidents score 0. A forward stage progression raises the rung by one,
  once, whether a correlated incident shows it or the source's own alerts do: a
  later alert reaching a later NIDS stage (`adapters.nids.stages`) than an earlier
  one. That advancing alert must be handshake-confirmed. Turn the second kind off
  with `policy.progression_from_alerts: false`.

**Rung.** The highest rung whose conditions are all met.

| Rung | Conditions | External source | Internal source | Duration |
|---|---|---|---|---|
| 0 | any evidence | log only | log only | - |
| 1 | score >= 4 | throttle (20 packets/s) | high-priority alert | 10 min |
| 2 | score >= 8, handshake-confirmed | TCP reset | TCP reset (+ block external C2/exfil destination) | 10 min |
| 3 | score >= 12, 2+ independent families, handshake-confirmed | drop all | quarantine (drop except management host) | 15 min |
| 4 | reached rung 3 twice in 24 h | drop all | quarantine | 2 h, hard cap |

* **Spoof guard:** with no handshake-confirmed evidence the maximum is rung 1.
* **Allowlist:** logged, never acted on.
* **Alert-only:** ARP spoofing (T1557.002), rogue host (T1200) and Impossible
  Travel raise an alert and are never scored: an IP block cannot fix them.
* **While blocked:** evidence that arrives during a block or quarantine is
  stored and shown, but never scored, so it cannot extend or renew the block.
* **Triage:** when the NIDS marks an alert false positive, its evidence is
  withdrawn and each active action that used it is re-judged on the evidence
  it was made from. If that no longer supports the rung, the action is lifted
  and the reversal is logged.

## Behaviours worth knowing

* **Actions run their full time.** An action is applied when the rung goes up
  and then holds for its duration. It is not lifted early because evidence aged
  out (only triage or a manual unblock does that), and it is not extended by
  more evidence. When it expires the IP is re-evaluated, so a rung can step
  down (block -> nothing, reset -> throttle) or the same action can be
  re-applied if fresh evidence still supports it.
* **Manual unblock also discards that IP's current evidence.** Otherwise the
  next 30 s tick would see the same score and put the block straight back.
* **A superseded action is recorded as reversed** with the reason
  `superseded by decision #N`. Reports count these separately from real reversals.
* **A family only counts as independent if it scored above zero.** An
  info-severity alert or an ML alert at exactly p = 0.5 is not corroboration.
* **ML counts as a family only when the model is confident** (p >= 0.8,
  `scoring.ml.family_min_probability`, the NIDS's own "high" line). Fainter ML
  still adds its points but cannot be the second family a block needs, and the
  explanation lists it under "Also scored". `ANOMALY_TRAFFIC_BASELINE` has no
  probability (fallback 0.65), so it never counts as a family on its own.
* **IPv6 sources are observed, never acted on** (version 1 gap).
* **Driver failure:** the decision is logged with `driver_result: error: ...`,
  its explanation starts with `NOT ENFORCED`, and the engine retries on the
  next tick rather than on every new alert.
* **Restart:** live state is rebuilt from `ips.db`, and active actions are
  re-applied to the driver with their *remaining* time.
* **Retention:** evidence, triage events and expired decisions older than
  `engine.retention_days` (30) are deleted from `ips.db` at startup and then
  hourly. A decision still in force is never deleted, and the adapter's
  bookmarks are never touched. Replay from `ips.db` can only reach back that
  far. The file does not shrink; SQLite reuses the freed space.

## NIDS specifics the adapter handles

These come from reading the NIDS source (`main.py`, `detection/*.py`):

* Table `alerts` in `nids_users.db`; address columns are `src` and `dst`.
* A repeat raises `count` and moves `created_at` on the existing row. The
  adapter tracks the last count per row and emits only the difference.
* Repeat counts are written in batches, stamped with an older time. Each poll
  therefore re-reads a 600 s look-back window; the count difference removes
  duplicates.
* "Clear Alerts" restarts alert ids at 1. A reused id is detected from the
  row's creation marker; evidence ids then become `nids:g1-<id>:<count>`.
* Suppressed alerts are stored already marked `false_positive`; they never
  become evidence.
* Exploit alerts carry `details.source_verified` from the NIDS handshake
  verifier; when present it overrides the per-rule handshake default.
* `CORRELATED_INCIDENT` and `ACTIVE_INTRUSION` become correlation evidence.
  The NIDS raises `CORRELATED_INCIDENT` once, when the incident opens, so its
  stage list is never updated; this is why each alert also carries its own
  stage (copied from `detection/rules.py` into `adapters.nids.stages`).
* Repeat counts are only current in `nids_users.db` with the NIDS change of
  2026-11-21 (a background thread writes deferred counts every second,
  `NIDS_REPEAT_FLUSH_SEC`). Without it the end of a burst stays in NIDS memory
  until someone opens History, and the engine scores a stale count.
* `timestamp` is local time without a timezone and is never used for time logic.

## Known gaps (version 1)

* IPv4 only.
* Two drivers only: nftables and dry_run. iptables/ipset, Windows Firewall and
  web-app middleware are later work.
* No honeypot adapter yet; the `honeypot` family and its "contact alone reaches
  rung 3" rule exist in the policy and are tested.
* The nftables driver is tested here against a stand-in for the `nft` binary.
  Run `are check --nft` on the router before enforcing.
* The ML probability is uncalibrated and comes from a model trained on
  CIC-IDS2017, which has documented labelling errors. It is used as a ranking
  signal only.
