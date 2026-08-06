"""
Detection #1 -- Pre-install hash verification.

A lockfile records the EXACT artifact (name, version, sha256) that a build is
allowed to install. Before installing, we recompute the hash of the artifact
the resolver picked and compare it to the lockfile. Any mismatch -- including
"the resolver chose a version/artifact the lockfile never approved" -- is an
alert.

This is the mechanism behind `pip install --require-hashes` and uv's
`--locked` / hash-verified installs. Here we implement a tiny, transparent
version so you can see exactly what it checks.

Usage:
    python -m detection.hash_check --lockfile <path> --artifact <wheel-or-sdist>
    python -m detection.hash_check --demo      # runs against the built package
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from detection.alerts import Alert  # noqa: E402


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def load_lockfile(path: Path) -> dict:
    """Lockfile schema: {"package": {"version": "...", "sha256": "..."} , ...}."""
    return json.loads(Path(path).read_text(encoding="utf-8"))


def check_artifact(lockfile: dict, package: str, version: str,
                   artifact_path: Path) -> Alert | None:
    """Return an Alert if the artifact violates the lockfile, else None."""
    pinned = lockfile.get(package)
    actual_hash = sha256_file(artifact_path)

    if pinned is None:
        return Alert(
            detector="hash_check", severity="critical",
            title=f"Unpinned package '{package}' about to install",
            what=f"{package}=={version} is not present in the lockfile at all.",
            why=("A build should only install artifacts the lockfile approved. "
                 "An unlisted package means the resolver pulled something the "
                 "team never reviewed -- the classic dependency-confusion path."),
            evidence={"package": package, "version": version,
                      "artifact": artifact_path.name, "actual_sha256": actual_hash},
        )

    if pinned.get("version") != version:
        return Alert(
            detector="hash_check", severity="critical",
            title=f"Version mismatch for '{package}'",
            what=f"Resolver picked {version}; lockfile pins {pinned.get('version')}.",
            why=("Dependency confusion wins by advertising a HIGHER version than "
                 "the internal one. A version that jumps past the pinned value is "
                 "exactly that signature."),
            evidence={"expected_version": pinned.get("version"),
                      "got_version": version, "artifact": artifact_path.name},
        )

    if pinned.get("sha256") != actual_hash:
        return Alert(
            detector="hash_check", severity="critical",
            title=f"Hash mismatch for '{package}=={version}'",
            what="The artifact's sha256 does not match the approved hash.",
            why=("Same name and version but different bytes means the artifact "
                 "was swapped -- a tampered or substituted package."),
            evidence={"expected_sha256": pinned.get("sha256"),
                      "actual_sha256": actual_hash, "artifact": artifact_path.name},
        )

    return None


def _find_built_artifact() -> Path | None:
    dist = REPO_ROOT / "packages" / "internal-auth-utils" / "dist"
    if not dist.exists():
        return None
    candidates = sorted(dist.glob("*.whl")) + sorted(dist.glob("*.tar.gz"))
    return candidates[0] if candidates else None


def _demo() -> int:
    """Run against the built malicious package using a 'known-good' lockfile
    that pins the LEGITIMATE 1.4.2 -- so the 99.0.0 artifact must fail."""
    import scas_config as cfg  # noqa

    artifact = _find_built_artifact()
    if artifact is None:
        print("No built artifact found. Build the demo package first "
              "(python runner/demo.py build).")
        return 2

    # A lockfile that approved the REAL internal version only.
    lockfile = {
        "internal-auth-utils": {
            "version": "1.4.2",
            "sha256": "0" * 64,  # placeholder for the approved (benign) build
        }
    }
    alert = check_artifact(lockfile, "internal-auth-utils", "99.0.0", artifact)
    if alert:
        print(alert.render())
        return 1
    print("✅ hash_check: artifact matches the lockfile (no attack detected).")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Pre-install hash verification.")
    p.add_argument("--lockfile")
    p.add_argument("--package")
    p.add_argument("--version")
    p.add_argument("--artifact")
    p.add_argument("--demo", action="store_true")
    args = p.parse_args(argv)

    if args.demo:
        return _demo()

    if not (args.lockfile and args.package and args.version and args.artifact):
        p.error("provide --lockfile --package --version --artifact, or --demo")

    lockfile = load_lockfile(Path(args.lockfile))
    alert = check_artifact(lockfile, args.package, args.version, Path(args.artifact))
    if alert:
        print(alert.render())
        return 1
    print(f"✅ hash_check: {args.package}=={args.version} matches lockfile.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
