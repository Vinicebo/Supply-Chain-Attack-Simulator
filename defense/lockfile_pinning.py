"""
Defense #2 -- Lockfile pinning with hash verification.

A lockfile freezes the exact (name, version, sha256) of every artifact. On the
next install the resolver is NOT free to pick a higher public version -- it must
install the pinned artifact and verify its hash. This neutralises dependency
confusion: the attacker's 99.0.0 is simply never selected, and even a swapped
artifact at the pinned version fails the hash check.

This module:
  * generates a lockfile for a set of built artifacts (generate_lock), and
  * verifies a proposed install against it (verify_install), reusing the same
    logic the hash_check detector uses.

It also explains the real-tool equivalents (`uv lock`, `pip-compile
--generate-hashes`, `pip install --require-hashes`).

Usage:
    python -m defense.lockfile_pinning generate <dist_dir> -o uv-approved.lock.json
    python -m defense.lockfile_pinning verify uv-approved.lock.json <artifact>
    python -m defense.lockfile_pinning explain
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from detection.hash_check import sha256_file, check_artifact  # noqa: E402

_ARTIFACT_RE = re.compile(r"^(?P<name>.+?)-(?P<version>\d[^-]*)")


def _parse_name_version(artifact: Path) -> tuple[str, str]:
    stem = artifact.name
    for suffix in (".tar.gz", ".whl", ".zip"):
        if stem.endswith(suffix):
            stem = stem[: -len(suffix)]
            break
    m = _ARTIFACT_RE.match(stem)
    if not m:
        return stem, "0"
    name = m.group("name").replace("_", "-").lower()
    return name, m.group("version")


def generate_lock(dist_dir: Path) -> dict:
    lock: dict = {}
    artifacts = sorted(dist_dir.glob("*.whl")) + sorted(dist_dir.glob("*.tar.gz"))
    for art in artifacts:
        name, version = _parse_name_version(art)
        lock[name] = {"version": version, "sha256": sha256_file(art),
                      "artifact": art.name}
    return lock


def verify_install(lockfile: dict, artifact: Path) -> int:
    name, version = _parse_name_version(artifact)
    alert = check_artifact(lockfile, name, version, artifact)
    if alert:
        print(alert.render())
        print("\n❌ lockfile_pinning: install BLOCKED -- artifact violates the lock.")
        return 1
    print(f"✅ lockfile_pinning: {name}=={version} matches the lockfile. Install allowed.")
    return 0


_EXPLAIN = """
Lockfile pinning -- how the real tools do it
============================================

uv:
    uv lock                       # writes uv.lock with pinned versions + hashes
    uv sync --locked              # refuse to install anything not in uv.lock
    # uv verifies artifact hashes against uv.lock automatically.

pip / pip-tools:
    pip-compile --generate-hashes -o requirements.txt requirements.in
    pip install --require-hashes -r requirements.txt
    # --require-hashes makes pip reject any artifact whose sha256 isn't listed.

Why this stops dependency confusion:
  * The resolver can no longer 'pick the highest version'. It must install the
    pinned version. The attacker's 99.0.0 is never a candidate.
  * If an attacker swaps bytes at the pinned version, the sha256 won't match and
    the install aborts.
  * Lockfiles must be committed and reviewed. A malicious version bump becomes a
    visible diff a human can catch.
"""


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Lockfile pinning + hash verification.")
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("generate")
    g.add_argument("dist_dir")
    g.add_argument("-o", "--out", default="approved.lock.json")

    v = sub.add_parser("verify")
    v.add_argument("lockfile")
    v.add_argument("artifact")

    sub.add_parser("explain")

    args = p.parse_args(argv)

    if args.cmd == "generate":
        lock = generate_lock(Path(args.dist_dir))
        Path(args.out).write_text(json.dumps(lock, indent=2), encoding="utf-8")
        print(f"Wrote lockfile with {len(lock)} package(s) to {args.out}")
        return 0

    if args.cmd == "verify":
        lock = json.loads(Path(args.lockfile).read_text(encoding="utf-8"))
        return verify_install(lock, Path(args.artifact))

    if args.cmd == "explain":
        print(_EXPLAIN)
        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
