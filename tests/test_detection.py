"""Detectors: they must surface the attack, and stay quiet when there is none."""
from __future__ import annotations

import os
import socket
import threading
import time

import pytest

import detection.fs_monitor as fm
import detection.network_monitor as nm
from detection.alerts import Alert


class TestAlert:
    def test_render_and_dict(self):
        a = Alert("d", "critical", "t", "what", "why", {"k": 1})
        assert "CRITICAL" in a.render() and "WHAT: what" in a.render()
        assert a.to_dict()["evidence"] == {"k": 1}


class TestNetworkClassification:
    def test_beacon_port_is_always_suspicious(self):
        assert nm._is_suspicious("127.0.0.1", nm.BEACON_PORT)

    def test_registry_and_https_are_allowed(self):
        assert not nm._is_suspicious("127.0.0.1", nm.cfg.REGISTRY_PORT)
        assert not nm._is_suspicious("151.101.0.223", 443)

    def test_unknown_port_is_suspicious(self):
        assert nm._is_suspicious("203.0.113.9", 4444)
        assert nm._is_suspicious("127.0.0.1", 4444)


def _watch(seconds: int) -> tuple[threading.Thread, list]:
    alerts: list = []
    t = threading.Thread(target=lambda: alerts.extend(nm.monitor_psutil(seconds)),
                         daemon=True)
    t.start()
    time.sleep(0.5)
    return t, alerts


def test_network_monitor_flags_connection_to_beacon_endpoint(live_monitor, monkeypatch):
    """Detector logic: an install-process connection to the exfil port is flagged."""
    pytest.importorskip("psutil")
    monkeypatch.setattr(nm, "BEACON_PORT", live_monitor.port)

    t, alerts = _watch(4)
    with socket.create_connection(("127.0.0.1", live_monitor.port), timeout=5):
        time.sleep(1.5)  # long enough for the 0.25s poller to observe it
    t.join(timeout=20)

    assert any(a.evidence["dst_port"] == live_monitor.port for a in alerts)
    assert all(a.severity == "critical" for a in alerts)


def test_network_monitor_is_quiet_without_beacon(live_monitor, monkeypatch):
    pytest.importorskip("psutil")
    monkeypatch.setattr(nm, "BEACON_PORT", live_monitor.port)
    t, alerts = _watch(2)
    t.join(timeout=20)
    assert not any(a.evidence["dst_port"] == live_monitor.port for a in alerts)


@pytest.mark.xfail(
    strict=False,
    reason="Known gap: monitor_psutil polls every 0.25s and the real beacon is a "
           "single short-lived HTTP request, so it can be missed (the monitor "
           "tends to see only the server-side sockets). Packet capture (scapy) "
           "does not have this race.")
def test_network_monitor_catches_the_real_short_lived_beacon(
        live_monitor, run_attack, monkeypatch):
    pytest.importorskip("psutil")
    monkeypatch.setattr(nm, "BEACON_PORT", live_monitor.port)
    t, alerts = _watch(8)
    run_attack(live_monitor.beacon_url)
    t.join(timeout=20)
    assert any(a.evidence["dst_port"] == live_monitor.port
               and a.evidence["process"] == "python.exe"
               and a.evidence["pid"] != os.getpid() for a in alerts)


class TestFsMonitor:
    def test_alert_describes_event(self):
        a = fm._alert_for("modified", "/home/u/.ssh/id_rsa")
        assert a.detector == "fs_monitor"
        assert a.evidence == {"event": "modified", "path": "/home/u/.ssh/id_rsa"}

    def test_touching_a_watched_path_alerts(self, tmp_path):
        pytest.importorskip("watchdog")
        watched = tmp_path / "ssh"
        watched.mkdir()

        def _touch():
            time.sleep(1.0)
            (watched / "id_rsa").write_text("canary")

        threading.Thread(target=_touch, daemon=True).start()
        alerts = fm.monitor_watchdog(3, [watched])
        assert any(a.evidence["path"].endswith("id_rsa") for a in alerts)

    def test_quiet_path_does_not_alert(self, tmp_path):
        pytest.importorskip("watchdog")
        quiet = tmp_path / "quiet"
        quiet.mkdir()
        assert fm.monitor_watchdog(1, [quiet]) == []
