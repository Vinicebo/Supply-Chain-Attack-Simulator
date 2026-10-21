"""The attack itself: building the malicious sdist must phone home."""
from __future__ import annotations

import re

import scas_config as cfg
from conftest import MALICIOUS_PKG_DIR

# Fields the payload is allowed to send. Anything else (env vars, file
# contents, keys, tokens) would break the project's safety model.
ALLOWED_FIELDS = {
    "trigger", "package", "package_version", "hostname", "username",
    "python_version", "platform", "cwd", "installed_packages_sample",
    "collected_at", "pid", "note",
}


def test_build_fires_beacon_with_malicious_version(live_monitor, run_attack):
    res = run_attack(live_monitor.beacon_url)
    assert res.returncode == 0, res.stderr

    caps = live_monitor.captures()
    assert len(caps) == 1, "exactly one beacon per build (dedupe works)"
    cap = caps[0]
    assert cap["package"] == cfg.DEMO_PACKAGE_NAME
    assert cap["package_version"] == cfg.DEMO_PACKAGE_VERSION == "99.0.0"
    assert cap["trigger"].startswith("build:")
    assert cap["remote_addr"] == "127.0.0.1"


def test_payload_is_limited_to_non_sensitive_metadata(live_monitor, run_attack):
    run_attack(live_monitor.beacon_url)
    import json
    raw = json.loads(live_monitor.captures()[0]["raw_json"])
    assert set(raw) <= ALLOWED_FIELDS
    assert "environ" not in json.dumps(raw).lower()


def test_dashboard_and_timeline_show_the_compromise(live_monitor, run_attack):
    assert "No beacons captured yet" in live_monitor.get("/")
    run_attack(live_monitor.beacon_url)
    assert "MALICIOUS VERSION 99.0.0 INSTALLED" in live_monitor.get("/")
    assert "beacon_received" in live_monitor.get("/timeline")


def test_publisher_build_is_suppressed(live_monitor, run_attack):
    """The attacker's own `build` must not pollute the victim's captures."""
    res = run_attack(live_monitor.beacon_url, _SCAS_SUPPRESS_BEACON="1")
    assert res.returncode == 0
    assert live_monitor.captures() == []


def test_build_does_not_fail_when_monitor_is_offline(run_attack):
    """A real payload fails silently; the install must still succeed."""
    from conftest import free_port
    res = run_attack(f"http://127.0.0.1:{free_port()}/beacon")
    assert res.returncode == 0
    assert "beacon" in res.stderr


def test_beacon_default_is_loopback_only():
    src = (MALICIOUS_PKG_DIR / "setup.py").read_text(encoding="utf-8")
    urls = re.findall(r"https?://[^\s\"')]+", src)
    hosts = {re.match(r"https?://([^:/]+)", u).group(1) for u in urls}
    assert hosts <= {"127.0.0.1"}, f"non-loopback host in payload: {hosts}"
