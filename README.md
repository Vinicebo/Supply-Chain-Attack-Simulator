# Supply Chain Attack Simulator

An **educational, local-only** demonstration of the **dependency-confusion**
attack vector — the same class of bug Alex Birsan used in 2021 to earn
$130,000+ in bounties from Apple, Microsoft, PayPal, and others — together with
working, testable implementations of every major defense.

> ### 🛡️ Safety model — read this first
> Nothing in this repository is published to any real package registry, and no
> code here reaches the public internet.
> - The "malicious" package beacons **only to `127.0.0.1`** and collects **only
>   non-sensitive metadata** (hostname, username, Python version, cwd, a list of
>   installed package *names*). It never reads secrets, files, or env vars.
> - The private registry, the monitor, and the victim install all run on
>   **loopback**.
> - This exists to help **defenders** see, measure, and block the attack. See
>   the ethics section in the generated report.

---

## What is dependency confusion?

Many companies install packages from **two** sources: a **private** index (their
internal packages) and **public PyPI** (everything else). If the same resolver
searches both for the **same name** and simply picks the **highest version**, an
attacker who learns an internal name (e.g. `internal-auth-utils`) can publish a
package with that name and a **huge version number** (`99.0.0`) to public PyPI.
The resolver picks the attacker's package, and **installing it runs the
attacker's code**.

This repo reproduces that end to end, locally, and then breaks it with five
defenses.

## Architecture

```
packages/internal-auth-utils/        the "malicious" package (v99.0.0, build hook -> beacon)
packages/internal-auth-utils-legit/  the real benign package (v1.4.2), for defense contrast
target-app/                          victim FastAPI app that depends on the name
monitor/                             loopback collection server + dashboard + timeline (SQLite)
detection/                           hash_check · network_monitor (scapy/psutil) · fs_monitor (watchdog)
defense/                             policy_scan · lockfile_pinning · scoped_registry · namespace_reservation · signing_verify
runner/demo.py                       orchestrates the whole thing (--narrated)
docs/report.py                       generates the attack-vs-defense analysis report
registry/packages/                   what the local pypiserver serves
```

Ports (loopback): registry `:8080`, monitor `:8090`. Override with
`SCAS_REGISTRY_PORT` / `SCAS_MONITOR_PORT`.

## Quick start

```bash
# 1. Install the base tooling into a project venv
uv venv
uv pip install -e ".[detect,sign,registry]"

# 2. Run the whole demonstration (starts servers itself), narrated
uv run python runner/demo.py run --narrated --keep-up
```

Installing also puts a `scas` command on your PATH, so `scas run --narrated`
works too.

> **On OneDrive / a cloud-synced folder?** uv's default hardlinking can fail
> (`os error 396`). Add `--link-mode=copy`, e.g.
> `uv pip install --link-mode=copy -e ".[detect,sign,registry]"`, or
> `export UV_LINK_MODE=copy` once for the session.

Then open the dashboard at <http://127.0.0.1:8090> and the attack timeline at
<http://127.0.0.1:8090/timeline>. A captured beacon with version `99.0.0` is
proof the attack executed.

### Run it piece by piece

```bash
# terminal 1 — the monitor (attacker collection server, loopback)
uv run python runner/demo.py monitor

# terminal 2 — the private registry
uv run python runner/demo.py build       # build + publish the malicious sdist
uv run python runner/demo.py registry

# terminal 3 — fire the attack, then investigate
uv run python runner/demo.py attack      # installs the dep -> beacon fires
uv run python runner/demo.py detect      # run all three detectors
uv run python runner/demo.py defend      # run all five defenses
uv run python runner/demo.py report      # regenerate docs/analysis_report.md
```

## The eight steps, mapped to the code

| Step | What it teaches | Where |
|------|-----------------|-------|
| 1 | Local private registry + project layout | `runner/demo.py registry`, `scas_config.py` |
| 2 | Malicious package with build/post-install hook | `packages/internal-auth-utils/setup.py` |
| 3 | Victim app + how resolution picks the attacker | `target-app/` |
| 4 | Monitoring dashboard, timeline, SQLite store | `monitor/server.py` |
| 5 | Detection: hash / network / filesystem | `detection/` |
| 6 | Defenses: pinning, namespace, scoping, signing, policy | `defense/` |
| 7 | Interactive narrated runner | `runner/demo.py run --narrated` |
| 8 | Attack-vs-defense matrix + incidents + ethics | `docs/report.py` → `docs/analysis_report.md` |

## Why the payload lives in an sdist build

Modern installers (uv, pip via PEP 517) install **prebuilt wheels**, which run
no code. Real dependency-confusion payloads therefore rely on the resolver
**building an sdist**, which executes `setup.py`. This repo publishes the
malicious package **sdist-only**, so the victim's `uv pip install` builds it and
the beacon fires — the realistic modern attack path. See the comments in
`packages/internal-auth-utils/setup.py`.

## Defenses (all runnable)

```bash
python -m defense.policy_scan --all                       # flag confusable deps
python -m defense.scoped_registry apply target-app/pyproject.toml --dry-run
python -m defense.lockfile_pinning explain
python -m defense.namespace_reservation status
python -m defense.signing_verify keygen
```

## Requirements

- Python 3.11+ and [`uv`](https://docs.astral.sh/uv/).
- Optional: `psutil` (network monitor, no privileges), `watchdog` (fs monitor),
  `scapy` + Npcap/root (full packet capture), `cryptography` (Ed25519 signing),
  `pypiserver` (private index). All are optional extras; the tools degrade
  gracefully and tell you what to install.

## License

MIT (educational). Do not use the techniques here against systems you do not own
or are not authorized to test.
