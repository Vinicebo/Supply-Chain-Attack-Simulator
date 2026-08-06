"""
Generate the analysis report: attack vs. defense matrix, real-world incidents,
and responsible-disclosure guidance.

Usage:
    python -m docs.report                 # writes docs/analysis_report.md
    python -m docs.report --stdout        # print instead of writing
"""
from __future__ import annotations

import argparse
import sys
from datetime import date
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

OUT_PATH = REPO_ROOT / "docs" / "analysis_report.md"

# The kill-chain stages of a dependency-confusion attack.
STAGES = [
    ("S1", "Reconnaissance", "Attacker learns the internal package name."),
    ("S2", "Publication", "Attacker uploads a same-named, higher-versioned package to a public index."),
    ("S3", "Resolution", "Victim's resolver selects the attacker's version."),
    ("S4", "Build/Install", "Installer builds the sdist / runs the install hook -> code execution."),
    ("S5", "Collection/Exfil", "Payload gathers host data and beacons it out."),
]

# Defense -> which stages it blocks, and how strongly.
#   B = blocks (attack cannot proceed), D = detects (attack proceeds but is
#   surfaced), - = no effect.
DEFENSES = [
    ("Namespace reservation",     {"S1": "-", "S2": "B", "S3": "-", "S4": "-", "S5": "-"},
     "You own the public name, so the attacker can't publish S2 at all."),
    ("Scoped registry routing",   {"S1": "-", "S2": "-", "S3": "B", "S4": "-", "S5": "-"},
     "Internal names resolve only from the private index; the public package is never a candidate."),
    ("Lockfile + hash pinning",   {"S1": "-", "S2": "-", "S3": "B", "S4": "B", "S5": "-"},
     "Resolver must install the pinned artifact/version; 99.0.0 is never chosen, and swaps fail the hash."),
    ("Package signing / attestations", {"S1": "-", "S2": "-", "S3": "D", "S4": "B", "S5": "-"},
     "Unsigned/wrong-key artifact fails verification before it is trusted/installed."),
    ("Policy-as-code scan",       {"S1": "D", "S2": "-", "S3": "D", "S4": "-", "S5": "-"},
     "Flags confusable internal-named deps in pyproject before they ever ship."),
    ("Network monitor",           {"S1": "-", "S2": "-", "S3": "-", "S4": "-", "S5": "D"},
     "Catches the outbound beacon during install."),
    ("Filesystem monitor",        {"S1": "-", "S2": "-", "S3": "-", "S4": "D", "S5": "D"},
     "Catches install scripts touching sensitive paths."),
    ("Pre-install hash check",    {"S1": "-", "S2": "-", "S3": "D", "S4": "B", "S5": "-"},
     "Refuses artifacts not matching a known-good lockfile before install."),
]


def _matrix_md() -> str:
    header = "| Defense | " + " | ".join(s[0] for s in STAGES) + " | Notes |"
    sep = "|" + "---|" * (len(STAGES) + 2)
    rows = [header, sep]
    for name, mapping, note in DEFENSES:
        cells = " | ".join(mapping[s[0]] for s in STAGES)
        rows.append(f"| {name} | {cells} | {note} |")
    legend = ("\n**Legend:** `B` = blocks the attack at this stage · "
              "`D` = detects/surfaces it · `-` = no effect.\n\n"
              "**Stages:** " + " · ".join(f"**{c}** {n} — {d}" for c, n, d in STAGES))
    return "\n".join(rows) + "\n" + legend


def build_report() -> str:
    return f"""# Supply Chain Attack Simulator — Analysis Report

_Generated {date.today().isoformat()}. All demonstrations in this repository are
local-only and loopback-scoped; nothing is published to a real registry._

## 1. The attack in one sentence

If a resolver can search both a private and a public index for the **same
package name**, an attacker who learns that name can publish a **higher-version**
public package and have it installed in place of the real internal one —
executing their code the moment it builds/installs. This is **dependency
confusion** (Alex Birsan, 2021; $130,000+ in bounties across Apple, Microsoft,
PayPal, and others).

## 2. Kill chain

{chr(10).join(f"- **{c} — {n}:** {d}" for c, n, d in STAGES)}

The pivotal, non-obvious fact demonstrated here: **stage S4 runs attacker code
during a routine `uv sync` / `pip install`.** With modern installers this happens
while *building an sdist* (setup.py executes), not only via legacy install hooks.

## 3. Attack vs. defense matrix

{_matrix_md()}

### Reading the matrix
- **Prevention beats detection.** Namespace reservation, scoped routing, and
  lockfile pinning each *block* the attack outright at an early stage. The
  monitors only *detect* it after code is already running.
- **Defense in depth.** No single control covers every stage. Scoped routing
  (S3) + lockfile/hash pinning (S3–S4) + signing (S4) together leave no gap,
  while the monitors provide detection if a control is misconfigured.
- **The cheapest durable fix** is scoped routing: never let two indexes compete
  to answer the same name.

## 4. Real-world incidents

### event-stream (2018)
A popular npm package was handed to a new "maintainer" who added a malicious
dependency (`flatmap-stream`) targeting a specific Bitcoin wallet app. Root
cause: **maintainer trust / account takeover of a transitive dependency**, not
name confusion — but it shows how install-time/runtime code from deep in the
tree reaches production. Relates to this repo's S4/S5: code you never wrote runs
in your environment.

### ua-parser-js (2021)
The maintainer's npm account was compromised and three malicious versions were
published that ran a post-install script downloading a crypto-miner and a
password stealer on Windows. Root cause: **account takeover + npm post-install
scripts**. Directly parallels our post-install/build hook (S4) and host
collection (S5); the defense is the same — pinned, hash-verified, signed
installs and disabling arbitrary install scripts.

### colors.js / faker.js (2022)
The author intentionally sabotaged their own widely-used packages with an
infinite loop ("protestware"). Root cause: **single-maintainer risk and blind
trust of `^`/`latest` version ranges**. Relates to S3: floating versions let a
new, hostile release flow into builds automatically. Lockfile pinning (this
repo's Defense #2) is the mitigation.

### Common thread
Every case reduces to *"an artifact you did not vet ran in your build or
runtime."* Whether the entry point is a squatted name (dependency confusion), a
stolen account, or a rogue maintainer, the defenses converge: **pin, verify,
sign, scope, and monitor.**

## 5. Frameworks

- **SLSA** (Supply-chain Levels for Software Artifacts): provenance and build
  integrity. Higher levels require hermetic, verifiable builds — which defeat
  S4 tampering.
- **NIST SSDF (SP 800-218)**: secure development practices including verifying
  third-party components (PW.4) and pinning/reviewing dependencies.
- **PEP 740 / Sigstore**: signed provenance attestations on PyPI (Defense #5).

## 6. Responsible disclosure & ethics

This project reproduces attack mechanics **only** to build and validate
defenses. Ethical boundaries observed here — and expected of anyone using it:

1. **Never publish confusable packages to a real public index.** Even a
   "harmless" placeholder uploaded to squat someone else's name can break their
   builds and may violate registry policy and law. Reserve only names your own
   organization owns.
2. **No real secret collection.** The demo payload gathers only non-sensitive
   metadata and sends it to loopback. Do not extend it to read credentials,
   environment secrets, or files.
3. **Test only systems you own or are authorized to test.** Dependency-confusion
   research against third parties requires explicit authorization (a bug-bounty
   scope or written permission).
4. **Coordinated disclosure.** If you find a real confusable name in the wild,
   report it privately to the affected vendor and the registry security team;
   give reasonable time to remediate before any public write-up.
5. **Minimize impact.** Prefer proof-of-concept that demonstrates resolution
   (e.g., a version-check callback) over payloads that alter or exfiltrate data.

## 7. What to do Monday morning

- [ ] Inventory internal package names; **reserve** them on public PyPI/npm.
- [ ] Configure **scoped routing** so internal names resolve only from the
      private index.
- [ ] Commit **lockfiles with hashes** and enable `--require-hashes` / `uv sync
      --locked` in CI.
- [ ] Turn on **signed publishing / attestations** and verify on install.
- [ ] Add the **policy scanner** to CI to catch confusable deps in review.
- [ ] Keep **install-time network/filesystem monitoring** as a detection
      backstop.
"""


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Generate the analysis report.")
    p.add_argument("--stdout", action="store_true")
    args = p.parse_args(argv)
    content = build_report()
    if args.stdout:
        print(content)
        return 0
    OUT_PATH.write_text(content, encoding="utf-8")
    print(f"Wrote {OUT_PATH.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
