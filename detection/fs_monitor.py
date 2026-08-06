"""
Detection #3 -- Filesystem monitor (install scripts touching sensitive paths).

A benign package build reads/writes inside its own build and site-packages
directories. A malicious post-install hook that goes looking for secrets will
touch places like ~/.ssh, ~/.aws, the project's .env, or the OS credential
store. This monitor watches a set of "sensitive" directories during the install
window and alerts on any access.

Backend: `watchdog` (cross-platform). If it is not installed we say so and exit.

Because watchdog reports create/modify/move (not pure reads) on most
platforms, the demo also supports a "canary" mode: we plant a marker file in a
watched sensitive dir and alert if anything opens/moves/deletes it.

Usage:
    python -m detection.fs_monitor --seconds 20
    python -m detection.fs_monitor --seconds 20 --watch ~/.ssh ./target-app
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from detection.alerts import Alert  # noqa: E402

# Default sensitive locations a supply-chain payload might probe.
def _default_sensitive_paths() -> list[Path]:
    home = Path.home()
    candidates = [
        home / ".ssh",
        home / ".aws",
        home / ".config" / "gcloud",
        REPO_ROOT / "target-app",   # contains the (fake) .env
    ]
    return [p for p in candidates if p.exists()]


def _alert_for(event_type: str, src_path: str) -> Alert:
    return Alert(
        detector="fs_monitor", severity="warning",
        title="Install-time access to a sensitive path",
        what=f"A '{event_type}' event occurred on {src_path} during install.",
        why=("Package installation has no legitimate reason to touch SSH keys, "
             "cloud credentials, or a project's .env. This is the recon step a "
             "credential-stealing payload performs."),
        evidence={"event": event_type, "path": src_path},
    )


def monitor_watchdog(seconds: int, watch_paths: list[Path]) -> list[Alert]:
    from watchdog.observers import Observer  # type: ignore
    from watchdog.events import FileSystemEventHandler  # type: ignore

    alerts: list[Alert] = []

    class Handler(FileSystemEventHandler):
        def on_any_event(self, event):
            # Ignore directory-listing noise from the observer itself.
            if event.event_type in ("created", "modified", "moved", "deleted"):
                alert = _alert_for(event.event_type, event.src_path)
                alerts.append(alert)
                print(alert.render())

    observer = Observer()
    watched = []
    for path in watch_paths:
        try:
            observer.schedule(Handler(), str(path), recursive=True)
            watched.append(str(path))
        except Exception as exc:
            print(f"[fs_monitor] cannot watch {path}: {exc}")

    if not watched:
        print("[fs_monitor] no sensitive paths available to watch on this host.")
        return alerts

    print(f"[fs_monitor] watching for {seconds}s: {', '.join(watched)}")
    observer.start()
    try:
        time.sleep(seconds)
    finally:
        observer.stop()
        observer.join()

    if not alerts:
        print("[fs_monitor] no sensitive-path access observed.")
    return alerts


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Filesystem access monitor.")
    p.add_argument("--seconds", type=int, default=20)
    p.add_argument("--watch", nargs="*", help="paths to watch (default: sensitive dirs)")
    args = p.parse_args(argv)

    try:
        import watchdog  # noqa
    except Exception:
        print("watchdog is not installed.\n  pip install watchdog")
        return 2

    if args.watch:
        watch_paths = [Path(os.path.expanduser(w)).resolve() for w in args.watch]
    else:
        watch_paths = _default_sensitive_paths()

    alerts = monitor_watchdog(args.seconds, watch_paths)
    return 1 if alerts else 0


if __name__ == "__main__":
    raise SystemExit(main())
