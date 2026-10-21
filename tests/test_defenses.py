"""Each defense, tested in isolation against the attacker's artifact."""
from __future__ import annotations

import http.server
import threading
import tomllib

import pytest

import defense.lockfile_pinning as lp
import defense.namespace_reservation as ns
import defense.policy_scan as ps
import defense.scoped_registry as sr
import defense.signing_verify as sv
import detection.hash_check as hc
import scas_config as cfg
from conftest import TARGET_PYPROJECT, free_port

LEGIT = b"legit 1.4.2 sdist bytes"
EVIL = b"malicious 99.0.0 sdist bytes"


# --------------------------------------------------------------------------- #
# Defense: policy-as-code scan
# --------------------------------------------------------------------------- #
class TestPolicyScan:
    def test_vulnerable_target_app_is_flagged_critical(self):
        findings = ps.scan_pyproject(TARGET_PYPROJECT)
        assert [f["package"] for f in findings] == ["internal-auth-utils"]
        assert findings[0]["severity"] == "critical"

    def test_public_dependencies_are_never_flagged(self, tmp_path):
        p = tmp_path / "pyproject.toml"
        p.write_text('[project]\nname="x"\ndependencies=["fastapi>=0.110","requests"]\n')
        assert ps.scan_pyproject(p) == []

    def test_private_pin_by_index_name_is_clean(self, tmp_path):
        p = tmp_path / "pyproject.toml"
        p.write_text(
            '[project]\nname="x"\ndependencies=["internal-auth-utils"]\n'
            '[tool.uv.sources]\ninternal-auth-utils = { index = "priv" }\n'
            '[[tool.uv.index]]\nname="priv"\nurl="http://127.0.0.1:8080/simple/"\n'
            '[[tool.uv.index]]\nname="pub"\nurl="https://pypi.org/simple/"\n')
        assert ps.scan_pyproject(p) == []

    def test_pin_to_public_index_is_still_flagged(self, tmp_path):
        p = tmp_path / "pyproject.toml"
        p.write_text(
            '[project]\nname="x"\ndependencies=["internal-auth-utils"]\n'
            '[tool.uv.sources]\ninternal-auth-utils = { index = "pub" }\n'
            '[[tool.uv.index]]\nname="pub"\nurl="https://pypi.org/simple/"\n')
        assert ps.scan_pyproject(p)[0]["severity"] == "critical"

    def test_unpinned_without_public_index_is_a_warning(self, tmp_path):
        p = tmp_path / "pyproject.toml"
        p.write_text('[project]\nname="x"\ndependencies=["internal-auth-utils"]\n')
        assert ps.scan_pyproject(p)[0]["severity"] == "warning"

    @pytest.mark.parametrize("name", ["internal-x", "internal_x", "corp-x", "acme-x"])
    def test_every_internal_prefix_is_recognised(self, name):
        assert ps.looks_internal(name)

    def test_cli_exit_codes(self, tmp_path):
        assert ps.main([str(TARGET_PYPROJECT)]) == 1
        clean = tmp_path / "pyproject.toml"
        clean.write_text('[project]\nname="x"\ndependencies=["fastapi"]\n')
        assert ps.main([str(clean)]) == 0


# --------------------------------------------------------------------------- #
# Defense: scoped registry
# --------------------------------------------------------------------------- #
class TestScopedRegistry:
    @pytest.fixture
    def target(self, tmp_path):
        p = tmp_path / "pyproject.toml"
        p.write_text(TARGET_PYPROJECT.read_text(encoding="utf-8"), encoding="utf-8")
        return p

    def test_dry_run_changes_nothing(self, target):
        before = target.read_text(encoding="utf-8")
        assert sr.apply(target, dry_run=True) == 0
        assert target.read_text(encoding="utf-8") == before

    def test_apply_pins_internal_dep_and_fixes_the_scan(self, target):
        assert ps.scan_pyproject(target)  # vulnerable first
        assert sr.apply(target) == 0
        data = tomllib.loads(target.read_text(encoding="utf-8"))
        assert data["tool"]["uv"]["sources"]["internal-auth-utils"] == {
            "index": sr.PRIVATE_INDEX_NAME}
        assert ps.scan_pyproject(target) == []

    def test_apply_is_idempotent(self, target):
        sr.apply(target)
        once = target.read_text(encoding="utf-8")
        sr.apply(target)
        assert target.read_text(encoding="utf-8") == once

    def test_public_deps_are_not_pinned(self, target):
        sr.apply(target)
        sources = tomllib.loads(target.read_text(encoding="utf-8"))["tool"]["uv"]["sources"]
        assert set(sources) == {"internal-auth-utils"}

    def test_no_internal_deps_means_nothing_to_do(self, tmp_path):
        p = tmp_path / "pyproject.toml"
        text = '[project]\nname="x"\ndependencies=["fastapi"]\n'
        p.write_text(text)
        assert sr.apply(p) == 0
        assert p.read_text() == text


# --------------------------------------------------------------------------- #
# Defense: lockfile pinning + pre-install hash check
# --------------------------------------------------------------------------- #
class TestLockfileAndHash:
    @pytest.fixture
    def dist(self, tmp_path):
        d = tmp_path / "dist"
        d.mkdir()
        (d / "internal_auth_utils-1.4.2.tar.gz").write_bytes(LEGIT)
        return d

    @pytest.fixture
    def lock(self, dist):
        return lp.generate_lock(dist)

    def test_generate_lock_records_name_version_and_hash(self, lock, dist):
        entry = lock["internal-auth-utils"]
        assert entry["version"] == "1.4.2"
        assert entry["sha256"] == hc.sha256_file(dist / "internal_auth_utils-1.4.2.tar.gz")

    def test_pinned_artifact_is_allowed(self, lock, dist):
        assert lp.verify_install(lock, dist / "internal_auth_utils-1.4.2.tar.gz") == 0

    def test_higher_version_from_attacker_is_blocked(self, lock, tmp_path):
        evil = tmp_path / "internal_auth_utils-99.0.0.tar.gz"
        evil.write_bytes(EVIL)
        assert lp.verify_install(lock, evil) == 1
        alert = hc.check_artifact(lock, "internal-auth-utils", "99.0.0", evil)
        assert alert.severity == "critical" and "Version mismatch" in alert.title

    def test_swapped_bytes_at_pinned_version_fail_the_hash(self, lock, tmp_path):
        swapped = tmp_path / "internal_auth_utils-1.4.2.tar.gz"
        swapped.write_bytes(EVIL)
        assert lp.verify_install(lock, swapped) == 1
        alert = hc.check_artifact(lock, "internal-auth-utils", "1.4.2", swapped)
        assert "Hash mismatch" in alert.title

    def test_unlisted_package_is_blocked(self, lock, tmp_path):
        other = tmp_path / "other_pkg-1.0.0.tar.gz"
        other.write_bytes(EVIL)
        assert lp.verify_install(lock, other) == 1
        alert = hc.check_artifact(lock, "other-pkg", "1.0.0", other)
        assert "Unpinned" in alert.title

    def test_clean_artifact_produces_no_alert(self, lock, dist):
        art = dist / "internal_auth_utils-1.4.2.tar.gz"
        assert hc.check_artifact(lock, "internal-auth-utils", "1.4.2", art) is None

    def test_hash_check_demo_flags_the_built_malicious_artifact(self, tmp_path, monkeypatch):
        art = tmp_path / "internal_auth_utils-99.0.0.tar.gz"
        art.write_bytes(EVIL)
        monkeypatch.setattr(hc, "_find_built_artifact", lambda: art)
        assert hc._demo() == 1

    def test_hash_check_demo_without_artifact_reports_missing(self, monkeypatch):
        monkeypatch.setattr(hc, "_find_built_artifact", lambda: None)
        assert hc._demo() == 2


# --------------------------------------------------------------------------- #
# Defense: package signing (both backends)
# --------------------------------------------------------------------------- #
@pytest.fixture(params=["ed25519", "hmac"])
def signer(request, tmp_path, monkeypatch):
    if request.param == "ed25519":
        pytest.importorskip("cryptography")
    else:
        monkeypatch.setattr(sv, "_have_crypto", lambda: False)
    keydir = tmp_path / "keys"
    monkeypatch.setattr(sv, "KEYDIR", keydir)
    monkeypatch.setattr(sv, "PRIV_PATH", keydir / "signing_key")
    monkeypatch.setattr(sv, "PUB_PATH", keydir / "trusted_key.pub")
    assert sv.keygen() == 0
    return request.param


class TestSigning:
    def test_signed_legit_artifact_verifies(self, signer, tmp_path):
        art = tmp_path / "internal_auth_utils-1.4.2.tar.gz"
        art.write_bytes(LEGIT)
        assert sv.sign(art) == 0
        assert sv.verify(art) == 0

    def test_unsigned_attacker_artifact_is_rejected(self, signer, tmp_path):
        evil = tmp_path / "internal_auth_utils-99.0.0.tar.gz"
        evil.write_bytes(EVIL)
        assert sv.verify(evil) == 1

    def test_artifact_modified_after_signing_is_rejected(self, signer, tmp_path):
        art = tmp_path / "internal_auth_utils-1.4.2.tar.gz"
        art.write_bytes(LEGIT)
        sv.sign(art)
        art.write_bytes(EVIL)
        assert sv.verify(art) == 1

    def test_signature_from_a_different_key_is_rejected(self, signer, tmp_path):
        art = tmp_path / "internal_auth_utils-99.0.0.tar.gz"
        art.write_bytes(EVIL)
        sv.sign(art)          # "attacker" signs with their own key...
        sv.keygen()           # ...but the trusted key is a different one
        assert sv.verify(art) == 1

    def test_sign_without_key_fails_cleanly(self, signer, tmp_path):
        sv.PRIV_PATH.unlink()
        art = tmp_path / "a-1.0.0.tar.gz"
        art.write_bytes(LEGIT)
        assert sv.sign(art) == 2


# --------------------------------------------------------------------------- #
# Defense: namespace reservation
# --------------------------------------------------------------------------- #
@pytest.fixture
def fake_index():
    """A loopback 'simple index' that serves only names in `served`."""
    served: set[str] = set()

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            name = self.path.strip("/").split("/")[-1]
            self.send_response(200 if name in served else 404)
            self.end_headers()

        def log_message(self, *a):
            pass

    port = free_port()
    srv = http.server.HTTPServer(("127.0.0.1", port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{port}/simple/", served
    finally:
        srv.shutdown()
        srv.server_close()


class TestNamespaceReservation:
    def test_reserved_name_is_detected(self, fake_index):
        url, served = fake_index
        served.add(cfg.DEMO_PACKAGE_NAME)
        assert ns.name_reserved_on(url, cfg.DEMO_PACKAGE_NAME) is True

    def test_unreserved_name_is_detected(self, fake_index):
        url, _ = fake_index
        assert ns.name_reserved_on(url, cfg.DEMO_PACKAGE_NAME) is False

    def test_unreachable_index_returns_none(self):
        assert ns.name_reserved_on(f"http://127.0.0.1:{free_port()}/simple/", "x", 1) is None

    def test_status_exit_code_reflects_reservation(self, fake_index, monkeypatch):
        url, served = fake_index
        monkeypatch.setattr(cfg, "REGISTRY_SIMPLE_URL", url)
        assert ns.status() == 1                # name free -> attacker could claim it
        served.add(cfg.DEMO_PACKAGE_NAME)
        assert ns.status() == 0                # name owned -> safe

    def test_plan_never_executes_anything(self, capsys):
        assert ns.plan("internal-auth-utils") == 0
        out = capsys.readouterr().out
        assert "NOT executed" in out and "internal-auth-utils" in out
