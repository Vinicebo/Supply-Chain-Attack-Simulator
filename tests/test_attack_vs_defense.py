"""End to end: the same attack, with and without each defense switched on.

This is what turns the attack-vs-defense matrix from a claim into a measurement.
Every scenario ends by asking the real monitor whether a beacon arrived:
  * control (no defense)    -> beacon captured  (the attack works)
  * each defense            -> no beacon        (the attack is stopped)

The resolver is a small stand-in for uv's `unsafe-best-match` strategy, driven
by the *actual* target-app/pyproject.toml, so the scoped-registry defense is
exercised through the config file it really edits.
"""
from __future__ import annotations

import tomllib

import pytest

import defense.lockfile_pinning as lp
import defense.namespace_reservation as ns
import defense.policy_scan as ps
import defense.scoped_registry as sr
import defense.signing_verify as sv
import scas_config as cfg
from conftest import TARGET_PYPROJECT

NAME = cfg.DEMO_PACKAGE_NAME
INDEXES = {  # what each configured index would offer for NAME
    "local-private": cfg.LEGIT_INTERNAL_VERSION,   # 1.4.2
    "public-pypi": cfg.DEMO_PACKAGE_VERSION,       # 99.0.0 (squatted)
}


def _ver(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in v.split("."))


def resolve(pyproject_text: str, name: str = NAME) -> str:
    """Pick the version uv would pick for `name` under this config."""
    uv = tomllib.loads(pyproject_text)["tool"]["uv"]
    pin = (uv.get("sources") or {}).get(name)
    if pin:                                   # explicit source -> that index only
        return INDEXES[pin["index"]]
    if uv.get("index-strategy") == "unsafe-best-match":
        return max(INDEXES.values(), key=_ver)  # highest across ALL indexes
    return INDEXES["local-private"]


@pytest.fixture
def victim(tmp_path, live_monitor, run_attack):
    """`install(version)` runs the payload iff the resolver chose 99.0.0."""
    class Victim:
        monitor = live_monitor
        pyproject = tmp_path / "pyproject.toml"

        def __init__(self):
            self.pyproject.write_text(TARGET_PYPROJECT.read_text(encoding="utf-8"),
                                      encoding="utf-8")

        def install(self, version: str) -> None:
            if version == cfg.DEMO_PACKAGE_VERSION:
                run_attack(live_monitor.beacon_url)

        def compromised(self) -> bool:
            return bool(live_monitor.captures())

    return Victim()


def _artifact(tmp_path, version: str, data: bytes):
    p = tmp_path / f"internal_auth_utils-{version}.tar.gz"
    p.write_bytes(data)
    return p


def test_control_vulnerable_config_is_compromised(victim):
    chosen = resolve(victim.pyproject.read_text(encoding="utf-8"))
    assert chosen == "99.0.0", "unsafe-best-match must pick the squatted version"
    victim.install(chosen)
    assert victim.compromised()
    assert victim.monitor.captures()[0]["package_version"] == "99.0.0"


def test_scoped_registry_stops_the_attack(victim):
    sr.apply(victim.pyproject)
    chosen = resolve(victim.pyproject.read_text(encoding="utf-8"))
    assert chosen == "1.4.2"
    victim.install(chosen)
    assert not victim.compromised()


def test_policy_scan_gate_stops_the_attack(victim):
    """CI refuses to ship while the scan has findings; nothing gets installed."""
    findings = ps.scan_pyproject(victim.pyproject)
    assert findings, "gate must close on the vulnerable config -> no install"
    assert not victim.compromised()

    # After fixing the config the gate opens and the (now safe) install proceeds.
    sr.apply(victim.pyproject)
    assert ps.scan_pyproject(victim.pyproject) == []
    victim.install(resolve(victim.pyproject.read_text(encoding="utf-8")))
    assert not victim.compromised()


def test_lockfile_hash_gate_stops_the_attack(victim, tmp_path):
    lock_dir = tmp_path / "approved"
    lock_dir.mkdir()
    _artifact(lock_dir, "1.4.2", b"legit")
    lock = lp.generate_lock(lock_dir)

    picked = resolve(victim.pyproject.read_text(encoding="utf-8"))   # 99.0.0
    evil = _artifact(tmp_path, picked, b"evil")
    assert lp.verify_install(lock, evil) == 1, "gate must reject -> no install"
    assert not victim.compromised()


@pytest.fixture(params=["ed25519", "hmac"])
def _signing_keys(request, tmp_path, monkeypatch):
    if request.param == "ed25519":
        pytest.importorskip("cryptography")
    else:
        monkeypatch.setattr(sv, "_have_crypto", lambda: False)
    keydir = tmp_path / "keys"
    monkeypatch.setattr(sv, "KEYDIR", keydir)
    monkeypatch.setattr(sv, "PRIV_PATH", keydir / "signing_key")
    monkeypatch.setattr(sv, "PUB_PATH", keydir / "trusted_key.pub")
    sv.keygen()


def test_signature_gate_stops_the_attack(victim, tmp_path, _signing_keys):
    picked = resolve(victim.pyproject.read_text(encoding="utf-8"))   # 99.0.0
    evil = _artifact(tmp_path, picked, b"evil")                      # never signed
    assert sv.verify(evil) == 1, "gate must reject -> no install"
    assert not victim.compromised()


def test_namespace_reservation_blocks_publication(fake_index_with_name):
    """If we already own the public name, the attacker's upload (S2) can't happen."""
    public_index = fake_index_with_name
    attacker_can_publish = ns.name_reserved_on(public_index, NAME) is not True
    assert not attacker_can_publish


@pytest.fixture
def fake_index_with_name():
    import http.server
    import threading
    from conftest import free_port

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()

        def log_message(self, *a):
            pass

    port = free_port()
    srv = http.server.HTTPServer(("127.0.0.1", port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{port}/simple/"
    finally:
        srv.shutdown()
        srv.server_close()
