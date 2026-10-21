"""Shared fixtures for the SCAS test suite.

Everything here is loopback-only and hermetic: the "attack" runs the real
`packages/internal-auth-utils/setup.py` against a real instance of the monitor
(`monitor.server`) bound to a free port, with its SQLite file in a tmp dir.
No registry, no `uv install`, no public network.
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

MALICIOUS_PKG_DIR = REPO_ROOT / "packages" / "internal-auth-utils"
TARGET_PYPROJECT = REPO_ROOT / "target-app" / "pyproject.toml"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@dataclass
class LiveMonitor:
    port: int

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    @property
    def beacon_url(self) -> str:
        import scas_config as cfg
        return self.url + cfg.MONITOR_BEACON_PATH

    def get(self, path: str) -> str:
        with urllib.request.urlopen(self.url + path, timeout=5) as r:
            return r.read().decode("utf-8")

    def captures(self) -> list[dict]:
        return json.loads(self.get("/api/captures"))


@pytest.fixture
def live_monitor(tmp_path, monkeypatch):
    """The real monitor app served by uvicorn on a free loopback port."""
    pytest.importorskip("fastapi")
    uvicorn = pytest.importorskip("uvicorn")
    import monitor.server as srv

    monkeypatch.setattr(srv, "DB_PATH", tmp_path / "captures.db")
    srv.init_db()

    port = free_port()
    server = uvicorn.Server(uvicorn.Config(
        srv.app, host="127.0.0.1", port=port, log_level="error"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 10
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    assert server.started, "monitor did not start"
    try:
        yield LiveMonitor(port)
    finally:
        server.should_exit = True
        thread.join(timeout=5)


@pytest.fixture
def run_attack(tmp_path):
    """Return a callable that 'installs' the malicious package.

    Building the sdist is what runs setup.py, so `setup.py egg_info` is the
    same code path `uv pip install` triggers. We copy the package first so the
    build leaves no egg-info in the repo.
    """
    pytest.importorskip("setuptools")
    counter = {"n": 0}

    def _run(beacon_url: str, **extra_env: str) -> subprocess.CompletedProcess:
        counter["n"] += 1
        work = tmp_path / f"victim_build_{counter['n']}"
        shutil.copytree(MALICIOUS_PKG_DIR, work,
                        ignore=shutil.ignore_patterns("dist", "build", "*.egg-info"))
        env = {k: v for k, v in os.environ.items() if not k.startswith("_SCAS_")}
        env["SCAS_BEACON_URL"] = beacon_url
        env.update(extra_env)
        return subprocess.run(
            [sys.executable, "setup.py", "egg_info"],
            cwd=work, env=env, capture_output=True, text=True, timeout=120)

    return _run
