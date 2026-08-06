"""
Shared configuration for the Supply Chain Attack Simulator.

Every component imports these constants so ports, URLs, and paths stay
consistent across the demo package, the target app, the monitor, and the
detection/defense tooling.

SAFETY: Every network endpoint here is a loopback (127.0.0.1) address.
Nothing in this project is designed to reach a real registry or the
public internet. See README.md for the full safety model.
"""
from __future__ import annotations

import os
import sys as _sys
from pathlib import Path

# Windows terminals default to cp1252 and crash on emoji/box-drawing output.
# Every CLI in this project imports scas_config, so reconfigure once here.
for _stream in (_sys.stdout, _sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except Exception:
        pass

# --- Repository layout -------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parent
REGISTRY_DIR = REPO_ROOT / "registry" / "packages"       # pypiserver storage
MONITOR_DB = REPO_ROOT / "monitor" / "captures.db"        # SQLite capture store
ARTIFACTS_DIR = REPO_ROOT / "artifacts"                   # generated evidence

# --- Network endpoints (loopback only) --------------------------------------
REGISTRY_HOST = "127.0.0.1"
REGISTRY_PORT = int(os.environ.get("SCAS_REGISTRY_PORT", "8080"))
REGISTRY_URL = f"http://{REGISTRY_HOST}:{REGISTRY_PORT}"
REGISTRY_SIMPLE_URL = f"{REGISTRY_URL}/simple/"

MONITOR_HOST = "127.0.0.1"
MONITOR_PORT = int(os.environ.get("SCAS_MONITOR_PORT", "8090"))
MONITOR_URL = f"http://{MONITOR_HOST}:{MONITOR_PORT}"
# The endpoint the "malicious" post-install hook beacons to.
MONITOR_BEACON_PATH = "/beacon"
MONITOR_BEACON_URL = f"{MONITOR_URL}{MONITOR_BEACON_PATH}"

# --- The package at the heart of the demo -----------------------------------
DEMO_PACKAGE_NAME = "internal-auth-utils"
DEMO_PACKAGE_IMPORT = "internal_auth_utils"
# A deliberately high version so it wins resolution against any realistic
# internal version (dependency confusion's core trick).
DEMO_PACKAGE_VERSION = "99.0.0"
# A plausible "real" internal version, used by defenses to show the contrast.
LEGIT_INTERNAL_VERSION = "1.4.2"

# Naming conventions a company might use for private packages. The policy
# scanner (defense/policy_scan.py) flags dependencies matching these that
# would resolve against a public index.
INTERNAL_NAMESPACE_PREFIXES = (
    "internal-",
    "internal_",
    "corp-",
    "acme-",
    "acme-internal-",
)


def ensure_dirs() -> None:
    """Create runtime directories if they do not yet exist."""
    for path in (REGISTRY_DIR, MONITOR_DB.parent, ARTIFACTS_DIR):
        path.mkdir(parents=True, exist_ok=True)
