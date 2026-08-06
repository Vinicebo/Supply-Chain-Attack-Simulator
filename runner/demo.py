"""
Interactive demonstration runner for the Supply Chain Attack Simulator.

Orchestrates the whole scenario end to end and can narrate each step. Every
network endpoint it touches is loopback; nothing is uploaded anywhere.

Subcommands:
    registry            Start the local private PyPI server (foreground).
    monitor             Start the monitoring dashboard (foreground).
    build               Build + "publish" the demo package (sdist) to the
                        local registry directory.
    build-legit         Build the benign v1.4.2 package too.
    attack              Install internal-auth-utils from the local index into a
                        throwaway venv -> triggers the beacon.
    detect              Run all three detection mechanisms.
    defend              Run all five defenses against the scenario.
    report              Generate the analysis report (docs/).
    run                 Full end-to-end demo (starts servers itself).
        --narrated      Pause + explain between steps.
        --keep-up       Leave registry + monitor running at the end.

Examples:
    python runner/demo.py run --narrated
    python runner/demo.py registry        # in one terminal
    python runner/demo.py monitor         # in another
    python runner/demo.py build && python runner/demo.py attack
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import scas_config as cfg  # noqa: E402

DEMO_PKG_DIR = REPO_ROOT / "packages" / "internal-auth-utils"
LEGIT_PKG_DIR = REPO_ROOT / "packages" / "internal-auth-utils-legit"

C = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
    "red": "\033[31m", "green": "\033[32m", "yellow": "\033[33m",
    "blue": "\033[34m", "cyan": "\033[36m",
}
if os.name == "nt":
    os.system("")  # enable ANSI on Windows terminals


# --------------------------------------------------------------------------- #
# Narration helpers
# --------------------------------------------------------------------------- #
class Narrator:
    def __init__(self, narrated: bool):
        self.narrated = narrated
        self.step = 0

    def stage(self, title: str, explanation: str = "") -> None:
        self.step += 1
        print(f"\n{C['bold']}{C['cyan']}━━ Step {self.step}: {title} ━━{C['reset']}")
        if explanation and self.narrated:
            print(f"{C['dim']}{explanation}{C['reset']}")
        if self.narrated:
            try:
                input(f"{C['dim']}   [press Enter to continue]{C['reset']}")
            except EOFError:
                pass

    @staticmethod
    def note(msg: str) -> None:
        print(f"{C['blue']}› {msg}{C['reset']}")

    @staticmethod
    def ok(msg: str) -> None:
        print(f"{C['green']}✓ {msg}{C['reset']}")

    @staticmethod
    def warn(msg: str) -> None:
        print(f"{C['yellow']}⚠ {msg}{C['reset']}")

    @staticmethod
    def bad(msg: str) -> None:
        print(f"{C['red']}✗ {msg}{C['reset']}")


def _run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    print(f"{C['dim']}$ {' '.join(cmd)}{C['reset']}")
    return subprocess.run(cmd, **kw)


def _terminate_tree(proc: subprocess.Popen) -> None:
    """Kill a process AND its children.

    `uv run` / `uvx` spawn the real server as a grandchild; a plain terminate()
    leaves that grandchild listening. On Windows we use taskkill /T; on POSIX we
    signal the process group.
    """
    if proc.poll() is not None:
        return
    try:
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        else:
            import signal
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            except Exception:
                proc.terminate()
    except Exception:
        proc.terminate()
    try:
        proc.wait(timeout=5)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def _http_get(url: str, timeout: float = 2.0) -> str | None:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:  # noqa: S310
            return r.read().decode("utf-8", "replace")
    except Exception:
        return None


def _wait_for(url: str, name: str, tries: int = 30) -> bool:
    for _ in range(tries):
        if _http_get(url) is not None:
            return True
        time.sleep(0.4)
    Narrator.bad(f"{name} did not come up at {url}")
    return False


# --------------------------------------------------------------------------- #
# Building / publishing
# --------------------------------------------------------------------------- #
def _rmtree_robust(path: Path, tries: int = 5) -> None:
    """rmtree that survives Windows read-only files and transient OneDrive locks."""
    import stat

    def _onerror(func, p, _exc):
        try:
            os.chmod(p, stat.S_IWRITE)
            func(p)
        except Exception:
            pass

    for attempt in range(tries):
        if not path.exists():
            return
        shutil.rmtree(path, onerror=_onerror)
        if not path.exists():
            return
        time.sleep(0.4)
    # Last resort: leave whatever remains; the build writes fresh files anyway.


def build_package(pkg_dir: Path, sdist_only: bool = True) -> list[Path]:
    """Build a package and copy artifacts into the local registry dir."""
    cfg.ensure_dirs()
    out = pkg_dir / "dist"
    if out.exists():
        _rmtree_robust(out)
    cmd = ["uv", "build", "--sdist" if sdist_only else "--wheel", str(pkg_dir),
           "-o", str(out)]
    # The attacker BUILDING their package should not beacon; only the victim's
    # install should. Suppress the hook for our own publish step.
    build_env = dict(os.environ, _SCAS_SUPPRESS_BEACON="1")
    res = _run(cmd, env=build_env)
    if res.returncode != 0:
        raise SystemExit(f"build failed for {pkg_dir}")
    # Only real distribution artifacts (uv drops a .gitignore into dist/).
    artifacts = sorted(out.glob("*.whl")) + sorted(out.glob("*.tar.gz"))
    for art in artifacts:
        shutil.copy2(art, cfg.REGISTRY_DIR / art.name)
    return artifacts


def cmd_build(_args) -> int:
    n = Narrator(False)
    n.stage("Build & publish the DEMO package")
    arts = build_package(DEMO_PKG_DIR, sdist_only=True)
    for a in arts:
        n.ok(f"published {a.name} -> {cfg.REGISTRY_DIR}")
    n.note("Published SDIST-only on purpose: the victim must BUILD it, which "
           "runs setup.py (the payload). A prebuilt wheel would run no code.")
    return 0


def cmd_build_legit(_args) -> int:
    n = Narrator(False)
    n.stage("Build & publish the LEGIT package (v1.4.2)")
    arts = build_package(LEGIT_PKG_DIR, sdist_only=False)
    for a in arts:
        n.ok(f"published {a.name}")
    return 0


# --------------------------------------------------------------------------- #
# Servers
# --------------------------------------------------------------------------- #
def start_registry_bg() -> subprocess.Popen:
    cfg.ensure_dirs()
    cmd = ["uvx", "--from", "pypiserver", "pypi-server", "run",
           "-p", str(cfg.REGISTRY_PORT), "-i", cfg.REGISTRY_HOST,
           "-P", ".", "-a", ".",  # no auth for the local demo
           str(cfg.REGISTRY_DIR)]
    print(f"{C['dim']}$ {' '.join(cmd)}{C['reset']}")
    return subprocess.Popen(cmd, cwd=str(REPO_ROOT),
                            start_new_session=(os.name != "nt"))


def start_monitor_bg() -> subprocess.Popen:
    cfg.ensure_dirs()
    cmd = ["uv", "run", "--with", "fastapi", "--with", "uvicorn",
           "uvicorn", "monitor.server:app",
           "--host", cfg.MONITOR_HOST, "--port", str(cfg.MONITOR_PORT)]
    print(f"{C['dim']}$ {' '.join(cmd)}{C['reset']}")
    return subprocess.Popen(cmd, cwd=str(REPO_ROOT),
                            start_new_session=(os.name != "nt"))


def cmd_registry(_args) -> int:
    p = start_registry_bg()
    Narrator.note(f"Registry serving {cfg.REGISTRY_DIR} at {cfg.REGISTRY_SIMPLE_URL}")
    Narrator.note("Ctrl+C to stop.")
    try:
        p.wait()
    except KeyboardInterrupt:
        _terminate_tree(p)
    return 0


def cmd_monitor(_args) -> int:
    p = start_monitor_bg()
    Narrator.note(f"Monitor dashboard at {cfg.MONITOR_URL}")
    Narrator.note("Ctrl+C to stop.")
    try:
        p.wait()
    except KeyboardInterrupt:
        _terminate_tree(p)
    return 0


# --------------------------------------------------------------------------- #
# Attack
# --------------------------------------------------------------------------- #
def run_attack_install(net_watch: bool = False) -> tuple[int, list]:
    """Install internal-auth-utils from the local index into a temp venv.

    Building the sdist runs setup.py -> beacon fires. Optionally run the psutil
    network monitor concurrently to catch the outbound beacon.
    """
    import tempfile

    venv = Path(tempfile.mkdtemp(prefix="scas_victim_"))
    net_alerts: list = []
    net_thread = None

    if net_watch:
        import threading
        from detection import network_monitor as nm

        def _watch():
            try:
                net_alerts.extend(nm.monitor_psutil(12))
            except Exception as e:  # pragma: no cover
                print(f"[net monitor] {e}")

        net_thread = threading.Thread(target=_watch, daemon=True)
        net_thread.start()
        time.sleep(0.5)

    env = dict(os.environ, SCAS_BEACON_URL=cfg.MONITOR_BEACON_URL)
    cmd = [
        "uv", "pip", "install",
        "--python", str(venv),
        "--index-url", cfg.REGISTRY_SIMPLE_URL,
        "--no-cache",
        cfg.DEMO_PACKAGE_NAME,
    ]
    # Create the venv first.
    _run(["uv", "venv", str(venv)])
    res = _run(cmd, env=env)

    if net_thread:
        net_thread.join(timeout=15)

    shutil.rmtree(venv, ignore_errors=True)
    return res.returncode, net_alerts


def cmd_attack(_args) -> int:
    n = Narrator(False)
    n.stage("Run the attack: install the internal package")
    rc, _ = run_attack_install()
    if rc == 0:
        n.ok("install completed; check the monitor for the captured beacon.")
    else:
        n.warn("install returned non-zero (the beacon may still have fired).")
    return 0


# --------------------------------------------------------------------------- #
# Detect / Defend
# --------------------------------------------------------------------------- #
def _module(mod: str, *args: str) -> int:
    return _run([sys.executable, "-m", mod, *args], cwd=str(REPO_ROOT)).returncode


def cmd_detect(_args) -> int:
    n = Narrator(False)
    n.stage("Detection #1: hash verification")
    _module("detection.hash_check", "--demo")
    n.stage("Detection #2: network monitor (live during a fresh install)")
    n.note("Installing again while watching outbound connections...")
    rc, alerts = run_attack_install(net_watch=True)
    if alerts:
        n.ok(f"network monitor flagged {len(alerts)} suspicious connection(s).")
    else:
        n.warn("network monitor saw nothing (install may have been cached; "
               "try: pip install psutil).")
    n.stage("Detection #3: filesystem monitor")
    n.note("Watching sensitive paths for ~6s; a real payload probing ~/.ssh "
           "or .env would trip this.")
    _module("detection.fs_monitor", "--seconds", "6")
    return 0


def cmd_defend(_args) -> int:
    n = Narrator(False)
    n.stage("Defense #1: policy-as-code scan")
    _module("defense.policy_scan", "target-app/pyproject.toml")
    n.stage("Defense #2: lockfile pinning + hash verification")
    _module("defense.lockfile_pinning", "explain")
    _module("detection.hash_check", "--demo")
    n.stage("Defense #3: scoped registry (dry run)")
    _module("defense.scoped_registry", "apply", "target-app/pyproject.toml", "--dry-run")
    n.stage("Defense #4: namespace reservation")
    _module("defense.namespace_reservation", "status")
    n.stage("Defense #5: package signing verification")
    n.note("Signing the demo artifact and verifying it, then showing an "
           "unsigned artifact being rejected.")
    _module("defense.signing_verify", "keygen")
    return 0


def cmd_report(_args) -> int:
    return _module("docs.report")


# --------------------------------------------------------------------------- #
# Full run
# --------------------------------------------------------------------------- #
def cmd_run(args) -> int:
    n = Narrator(args.narrated)
    cfg.ensure_dirs()
    print(f"{C['bold']}Supply Chain Attack Simulator — full demonstration{C['reset']}")
    print(f"{C['dim']}Everything below is loopback-only. Nothing is uploaded.{C['reset']}")

    procs: list[subprocess.Popen] = []
    try:
        n.stage("Start the monitor (attacker collection server, loopback)",
                "This dashboard receives the beacon the malicious package sends "
                "during installation and stores it in SQLite.")
        procs.append(start_monitor_bg())
        _wait_for(cfg.MONITOR_URL, "monitor")
        n.ok(f"monitor up at {cfg.MONITOR_URL}")

        n.stage("Build & publish the malicious package to the private registry",
                "We publish an sdist so the victim's resolver BUILDS it, which "
                "executes setup.py. Version 99.0.0 guarantees it wins resolution.")
        build_package(DEMO_PKG_DIR, sdist_only=True)
        n.ok("internal-auth-utils==99.0.0 published (sdist) to the local registry")

        n.stage("Start the private PyPI registry",
                "pypiserver serves our published package over the PEP 503 simple "
                "API, exactly like a company's internal index.")
        procs.append(start_registry_bg())
        _wait_for(cfg.REGISTRY_SIMPLE_URL, "registry")
        n.ok(f"registry up at {cfg.REGISTRY_SIMPLE_URL}")

        n.stage("Victim installs the dependency (the attack fires)",
                "The victim runs the equivalent of `uv sync`. The resolver picks "
                "99.0.0, builds the sdist, and setup.py beacons host metadata to "
                "the monitor. Watch the network monitor catch it live.")
        rc, net_alerts = run_attack_install(net_watch=True)
        time.sleep(1.0)
        caps = _http_get(cfg.MONITOR_URL + "/api/captures")
        if caps and caps.strip() not in ("[]", ""):
            n.bad("COMPROMISED: the monitor captured exfiltrated host metadata.")
            n.note(f"View it at {cfg.MONITOR_URL} and {cfg.MONITOR_URL}/timeline")
        else:
            n.warn("No capture recorded. Check that the monitor is running and "
                   "that the build was not fully cached.")
        if net_alerts:
            n.ok(f"network monitor independently flagged {len(net_alerts)} "
                 "suspicious connection(s) during the install.")

        n.stage("Now run the DEFENSES against this exact scenario",
                "Each defense is testable. We show which ones would have stopped "
                "the attack and where.")
        _module("defense.policy_scan", "target-app/pyproject.toml")
        _module("detection.hash_check", "--demo")
        _module("defense.scoped_registry", "apply", "target-app/pyproject.toml", "--dry-run")

        n.stage("Generate the analysis report",
                "A defense matrix mapping each defense to the attack stage it "
                "blocks, plus real-world incidents and disclosure ethics.")
        _module("docs.report")
        n.ok("report written to docs/analysis_report.md")

        if args.keep_up:
            n.note("Leaving monitor + registry running (--keep-up). Ctrl+C to stop.")
            n.note(f"Dashboard: {cfg.MONITOR_URL}   Timeline: {cfg.MONITOR_URL}/timeline")
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        for p in procs:
            _terminate_tree(p)
    print(f"\n{C['bold']}Demo complete.{C['reset']}")
    return 0


# --------------------------------------------------------------------------- #
def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="demo.py",
        description="Supply Chain Attack Simulator — demonstration runner.")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("registry").set_defaults(func=cmd_registry)
    sub.add_parser("monitor").set_defaults(func=cmd_monitor)
    sub.add_parser("build").set_defaults(func=cmd_build)
    sub.add_parser("build-legit").set_defaults(func=cmd_build_legit)
    sub.add_parser("attack").set_defaults(func=cmd_attack)
    sub.add_parser("detect").set_defaults(func=cmd_detect)
    sub.add_parser("defend").set_defaults(func=cmd_defend)
    sub.add_parser("report").set_defaults(func=cmd_report)

    r = sub.add_parser("run")
    r.add_argument("--narrated", action="store_true")
    r.add_argument("--keep-up", action="store_true")
    r.set_defaults(func=cmd_run)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
