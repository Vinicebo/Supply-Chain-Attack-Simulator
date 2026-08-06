"""
Defense #4 -- Namespace reservation (defensive registration).

The simplest structural defense: register your internal package NAMES on the
public index yourself, as harmless placeholders, so no attacker can claim them.
If `internal-auth-utils` already exists on PyPI and you own it, an attacker
cannot upload a malicious `internal-auth-utils`.

We can't (and must not) actually register anything on real PyPI here. Instead
this module:
  * checks whether your internal names are ALREADY taken on the local registry
    (a safe stand-in for "is the name reserved?"), and
  * emits the exact placeholder package + upload steps you WOULD run to reserve
    a name on real PyPI, without executing them.

Usage:
    python -m defense.namespace_reservation status
    python -m defense.namespace_reservation plan internal-auth-utils
"""
from __future__ import annotations

import argparse
import sys
import urllib.error
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import scas_config as cfg  # noqa: E402


def name_reserved_on(index_simple_url: str, name: str, timeout: float = 3.0) -> bool | None:
    """True if the name resolves on the given simple index, False if 404,
    None if the index is unreachable."""
    url = index_simple_url.rstrip("/") + "/" + name + "/"
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (loopback)
            return 200 <= resp.status < 300
    except urllib.error.HTTPError as e:
        return False if e.code == 404 else None
    except Exception:
        return None


def status() -> int:
    print("Namespace reservation status (against the LOCAL private index):\n")
    any_unreserved = False
    # We only probe our known demo name; the prefixes below are guidance for
    # which name families an org should reserve on public PyPI.
    for name in (cfg.DEMO_PACKAGE_NAME,):
        reserved = name_reserved_on(cfg.REGISTRY_SIMPLE_URL, name)
        if reserved is None:
            state = "❓ index unreachable (is the registry running?)"
        elif reserved:
            state = "✅ present on private index"
        else:
            state = "⚠️ NOT present -- an attacker could claim this name publicly"
            any_unreserved = True
        print(f"  {name:<28} {state}")
    print("\nConventions to reserve on PUBLIC PyPI (placeholders you own):")
    for p in cfg.INTERNAL_NAMESPACE_PREFIXES:
        print(f"  - every '{p}*' name your org uses internally")
    return 1 if any_unreserved else 0


_PLACEHOLDER_SETUP = '''\
from setuptools import setup
setup(
    name="{name}",
    version="0.0.0",
    description="Reserved namespace placeholder owned by ACME Security. Do not use.",
    long_description="This name is reserved to prevent dependency confusion. "
                     "The real package lives on ACME's private index.",
    author="ACME Security",
    license="Proprietary",
    py_modules=[],
)'''


def plan(name: str) -> int:
    print(f"Reservation plan for '{name}' (NOT executed):\n")
    print("1. Create a minimal placeholder package:")
    print("   # setup.py")
    for line in _PLACEHOLDER_SETUP.format(name=name).splitlines():
        print("   " + line)
    print("\n2. Build it:")
    print("   python -m build")
    print("\n3. Upload to REAL PyPI to claim the name (requires YOUR account):")
    print(f"   twine upload dist/*      # registers '{name}' to your account")
    print("\n4. (Optional) Enable PyPI 'Trusted Publishing' / 2FA and add the name")
    print("   to an organization so only your CI can ever publish updates.")
    print("\nEffect: the public name is now yours; attackers cannot squat it.")
    print("NOTE: This simulator never uploads to real PyPI. Run these yourself,")
    print("      deliberately, for names your organization actually owns.")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Namespace reservation helper.")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status")
    pl = sub.add_parser("plan")
    pl.add_argument("name")
    args = p.parse_args(argv)

    if args.cmd == "status":
        return status()
    if args.cmd == "plan":
        return plan(args.name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
