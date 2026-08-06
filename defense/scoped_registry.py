"""
Defense #3 -- Scoped registry configuration.

The root cause of dependency confusion is that ONE resolver searches BOTH a
private and a public index for the same name, and picks the highest version.
The fix is to route names by convention: anything matching `internal-*` may ONLY
come from the private index; everything else may use public PyPI. The public
index is never even asked about internal names, so the attacker's public
99.0.0 is invisible to the resolver.

This module rewrites a target `pyproject.toml` to add explicit `[tool.uv.sources]`
pins for every internal-looking dependency, and shows the equivalent config for
pip (`--index-url` + per-package sources) and npm scoped registries.

Usage:
    python -m defense.scoped_registry apply target-app/pyproject.toml
    python -m defense.scoped_registry apply target-app/pyproject.toml --dry-run
    python -m defense.scoped_registry explain
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import scas_config as cfg  # noqa: E402
from defense.policy_scan import _dep_name, looks_internal  # noqa: E402

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore

PRIVATE_INDEX_NAME = "local-private"


def _internal_deps(data: dict) -> list[str]:
    deps = data.get("project", {}).get("dependencies", []) or []
    return sorted({_dep_name(d) for d in deps if looks_internal(_dep_name(d))})


def _existing_index_names(data: dict) -> set[str]:
    entries = data.get("tool", {}).get("uv", {}).get("index", []) or []
    if isinstance(entries, dict):
        entries = [entries]
    return {e.get("name") for e in entries if isinstance(e, dict) and e.get("name")}


def build_sources_block(names: list[str], declare_index: bool = True) -> str:
    """Return the TOML text pinning each internal name to the private index.

    If the private index is already declared in the target file, pass
    declare_index=False so we don't emit a duplicate `[[tool.uv.index]]`.
    """
    lines = [
        "",
        "# --- Added by defense/scoped_registry.py -----------------------------",
        "# Route internal-namespace packages to the PRIVATE index ONLY.",
        "# Public PyPI is never queried for these names, so a squatted public",
        "# package (even at version 99.0.0) can never be resolved.",
        "[tool.uv.sources]",
    ]
    for name in names:
        lines.append(f'"{name}" = {{ index = "{PRIVATE_INDEX_NAME}" }}')
    if declare_index:
        lines.append("")
        lines.append("[[tool.uv.index]]")
        lines.append(f'name = "{PRIVATE_INDEX_NAME}"')
        lines.append(f'url = "{cfg.REGISTRY_SIMPLE_URL}"')
        lines.append("explicit = true  # only used for names that name it explicitly")
    else:
        lines.append(f'# (index "{PRIVATE_INDEX_NAME}" is already declared above)')
    lines.append("# ---------------------------------------------------------------------")
    return "\n".join(lines)


def apply(path: Path, dry_run: bool = False) -> int:
    text = path.read_text(encoding="utf-8")
    data = tomllib.loads(text)
    names = _internal_deps(data)
    declare_index = PRIVATE_INDEX_NAME not in _existing_index_names(data)

    if not names:
        print(f"scoped_registry: no internal-namespace deps in {path}; nothing to pin.")
        return 0

    if "# --- Added by defense/scoped_registry.py" in text:
        print(f"scoped_registry: {path} already contains scoped-source pins.")
        return 0

    block = build_sources_block(names, declare_index=declare_index)
    new_text = text.rstrip() + "\n" + block + "\n"

    if dry_run:
        print(f"--- scoped_registry would append to {path} ---")
        print(block)
        return 0

    path.write_text(new_text, encoding="utf-8")
    print(f"✅ scoped_registry: pinned {len(names)} internal package(s) to "
          f"'{PRIVATE_INDEX_NAME}' in {path}:")
    for n in names:
        print(f"     - {n} -> {PRIVATE_INDEX_NAME} (private only)")
    print("Public PyPI will no longer be consulted for these names.")
    return 0


_EXPLAIN = f"""
Scoped registry configuration -- routing by namespace
=====================================================

uv (this project):
    [tool.uv.sources]
    "internal-auth-utils" = {{ index = "local-private" }}

    [[tool.uv.index]]
    name = "local-private"
    url  = "{cfg.REGISTRY_SIMPLE_URL}"
    explicit = true
  -> uv resolves internal-auth-utils ONLY from local-private. Public PyPI is
     never asked, so a public 99.0.0 is unreachable.

pip:
    # Put internal packages behind their own index and DON'T mix indexes for
    # the same name. Prefer a private index that PROXIES public packages
    # (Artifactory / Nexus / devpi / GitLab) so there is a single source of
    # truth and confusion is impossible.

npm (the canonical example):
    # .npmrc
    @acme:registry=https://npm.internal.acme.com/
  -> every @acme/* package comes from the private registry; the public one is
     never consulted for that scope. Python has no first-class scopes, so we
     emulate them with per-name source pins.

Key idea: never let two indexes compete to answer the same name.
"""


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Scoped registry configuration.")
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("apply")
    a.add_argument("pyproject")
    a.add_argument("--dry-run", action="store_true")
    sub.add_parser("explain")
    args = p.parse_args(argv)

    if args.cmd == "apply":
        return apply(Path(args.pyproject), dry_run=args.dry_run)
    if args.cmd == "explain":
        print(_EXPLAIN)
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
