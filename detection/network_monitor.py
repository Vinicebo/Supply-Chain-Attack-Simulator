"""
Detection #2 -- Network monitor (unexpected outbound connections during install).

A package install should talk to your package indexes and nothing else. A
post-install hook that beacons to some other host is a bright red flag. This
monitor watches for outbound HTTP-ish connections during an install window and
alerts on any destination that is not an allow-listed index.

Two backends:
  * scapy  -- sniffs real packets (needs Npcap on Windows / root on Linux, and
              the `scapy` package). Best fidelity.
  * psutil -- polls per-connection socket tables (no special privileges). Good
              enough to catch the demo's beacon to 127.0.0.1:8090.

If neither is installed, we explain what to install and exit cleanly.

Usage:
    python -m detection.network_monitor --seconds 20
    python -m detection.network_monitor --seconds 20 --backend scapy
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import scas_config as cfg  # noqa: E402
from detection.alerts import Alert  # noqa: E402

# Destinations a package install is *allowed* to reach.
ALLOWED_HOSTS = {"127.0.0.1", "::1", "localhost"}
ALLOWED_INDEX_PORTS = {cfg.REGISTRY_PORT, 443, 80}
# The monitor/beacon port is where a "malicious" hook phones home. Reaching it
# is precisely the thing we want to flag, even though it's loopback.
BEACON_PORT = cfg.MONITOR_PORT

# Process names that belong to a package install. We only scrutinise
# connections owned by these -- otherwise the whole machine's network noise
# (browsers, chat apps, background services) floods the output and buries the
# one connection that matters. The beacon port is always flagged regardless of
# which process opened it.
INSTALL_PROCESS_NAMES = {
    "python", "python3", "python.exe", "python3.exe",
    "uv", "uv.exe", "pip", "pip.exe", "pip3", "pip3.exe",
    "setup.py",
}


def _flag(dst_ip: str, dst_port: int, backend: str, pid=None) -> Alert:
    return Alert(
        detector="network_monitor", severity="critical",
        title="Unexpected outbound connection during install",
        what=f"A process connected to {dst_ip}:{dst_port} while a package "
             f"was installing.",
        why=("Installs should only reach your package indexes. A connection to "
             "a collection endpoint (here the simulated exfil monitor on "
             f"port {BEACON_PORT}) is a post-install hook phoning home."),
        evidence={"dst_ip": dst_ip, "dst_port": dst_port,
                  "pid": pid, "backend": backend},
    )


def _is_suspicious(dst_ip: str, dst_port: int) -> bool:
    if dst_port == BEACON_PORT:
        return True  # the beacon endpoint is always suspicious
    if dst_ip in ALLOWED_HOSTS and dst_port in ALLOWED_INDEX_PORTS:
        return False
    if dst_ip in ALLOWED_HOSTS:
        return True  # loopback but not an index/known port
    return dst_port not in ALLOWED_INDEX_PORTS


def monitor_psutil(seconds: int, all_processes: bool = False) -> list[Alert]:
    import psutil  # type: ignore

    scope = "ALL processes" if all_processes else "install-related processes only"
    print(f"[network_monitor/psutil] watching outbound connections for "
          f"{seconds}s ({scope})...")
    alerts: list[Alert] = []
    seen: set[tuple] = set()
    name_cache: dict[int, str] = {}

    def _proc_name(pid) -> str:
        if pid in (None, 0):
            return ""
        if pid not in name_cache:
            try:
                name_cache[pid] = psutil.Process(pid).name().lower()
            except Exception:
                name_cache[pid] = ""
        return name_cache[pid]

    deadline = time.time() + seconds
    while time.time() < deadline:
        for c in psutil.net_connections(kind="inet"):
            if not c.raddr:
                continue
            dst_ip, dst_port = c.raddr.ip, c.raddr.port
            key = (dst_ip, dst_port, c.pid)
            if key in seen:
                continue
            seen.add(key)

            # The beacon endpoint is always interesting. Everything else is only
            # considered if it belongs to the install process tree.
            if dst_port != BEACON_PORT and not all_processes:
                if _proc_name(c.pid) not in INSTALL_PROCESS_NAMES:
                    continue

            if _is_suspicious(dst_ip, dst_port):
                alert = _flag(dst_ip, dst_port, "psutil", c.pid)
                alert.evidence["process"] = _proc_name(c.pid) or "unknown"
                alerts.append(alert)
                print(alert.render())
        time.sleep(0.25)
    if not alerts:
        print("[network_monitor/psutil] no suspicious connections observed.")
    return alerts


def monitor_scapy(seconds: int) -> list[Alert]:
    from scapy.all import sniff, IP, TCP  # type: ignore

    print(f"[network_monitor/scapy] sniffing TCP SYN packets for {seconds}s "
          "(requires Npcap/root)...")
    alerts: list[Alert] = []
    seen: set[tuple] = set()

    def handle(pkt):
        if IP in pkt and TCP in pkt and pkt[TCP].flags == "S":
            dst_ip, dst_port = pkt[IP].dst, int(pkt[TCP].dport)
            key = (dst_ip, dst_port)
            if key in seen:
                return
            seen.add(key)
            if _is_suspicious(dst_ip, dst_port):
                alert = _flag(dst_ip, dst_port, "scapy")
                alerts.append(alert)
                print(alert.render())

    sniff(prn=handle, store=False, timeout=seconds, filter="tcp")
    if not alerts:
        print("[network_monitor/scapy] no suspicious SYNs observed.")
    return alerts


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Outbound connection monitor.")
    p.add_argument("--seconds", type=int, default=20)
    p.add_argument("--backend", choices=["auto", "scapy", "psutil"], default="auto")
    p.add_argument("--all-processes", action="store_true",
                   help="scrutinise every process, not just the install tree "
                        "(noisy: surfaces all system network traffic).")
    args = p.parse_args(argv)

    backend = args.backend
    if backend == "auto":
        try:
            import scapy.all  # noqa
            backend = "scapy"
        except Exception:
            try:
                import psutil  # noqa
                backend = "psutil"
            except Exception:
                print("Neither scapy nor psutil is installed.\n"
                      "  pip install psutil        # simple, no privileges\n"
                      "  pip install scapy         # full packet capture (needs Npcap/root)")
                return 2

    try:
        if backend == "scapy":
            alerts = monitor_scapy(args.seconds)
        else:
            alerts = monitor_psutil(args.seconds, all_processes=args.all_processes)
    except PermissionError:
        print("Packet capture needs elevated privileges. Try --backend psutil.")
        return 2
    except Exception as exc:
        print(f"[network_monitor] backend '{backend}' failed: {exc}\n"
              "Try --backend psutil.")
        return 2

    return 1 if alerts else 0


if __name__ == "__main__":
    raise SystemExit(main())
