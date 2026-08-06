"""
Defense #1 -- Policy-as-code: scan pyproject.toml for confusable dependencies.

This scanner flags dependencies whose names match your INTERNAL naming
conventions (e.g. `internal-*`, `acme-*`) but that could resolve from a PUBLIC
index. Those are exactly the names an attacker squats on public PyPI.

It parses the `[project].dependencies`, `[tool.uv]` index configuration, and
any `[tool.uv.sources]` to decide whether each internal-looking dependency is
safely pinned to a private index.

Usage:
    python -m defense.policy_scan target-app/pyproject.toml
    python -m defense.policy_scan --all      # scan every pyproject in the repo
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import scas_config as cfg  # noqa: E402

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore

PUBLIC_INDEX_MARKERS = ("pypi.org", "pythonhosted.org")

_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*")


def _dep_name(spec: str) -> str:
    m = _NAME_RE.match(spec.strip())
    return (m.group(0) if m else spec).lower()


def looks_internal(name: str) -> bool:
    return any(name.startswith(p) for p in cfg.INTERNAL_NAMESPACE_PREFIXES)


def scan_pyproject(path: Path) -> list[dict]:
    """Return a list of findings (dicts). Empty list == clean."""
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    findings: list[dict] = []

    deps = data.get("project", {}).get("dependencies", []) or []
    uv = data.get("tool", {}).get("uv", {}) or {}
    sources = uv.get("sources", {}) or {}

    # Index URLs can come from the deprecated `index-url`/`extra-index-url`
    # keys OR the modern `[[tool.uv.index]]` array of tables. Collect both, and
    # build a name -> url map so per-name source pins can be resolved.
    extra_indexes = uv.get("extra-index-url", []) or []
    if isinstance(extra_indexes, str):
        extra_indexes = [extra_indexes]
    default_index = uv.get("index-url", "")

    index_entries = uv.get("index", []) or []
    if isinstance(index_entries, dict):  # tolerate a single (malformed) table
        index_entries = [index_entries]
    index_url_by_name = {e.get("name"): e.get("url", "")
                         for e in index_entries if isinstance(e, dict)}
    all_index_urls = ([default_index] + list(extra_indexes)
                      + [e.get("url", "") for e in index_entries if isinstance(e, dict)])

    def _is_public_url(url: str) -> bool:
        return bool(url) and any(m in url for m in PUBLIC_INDEX_MARKERS)

    public_reachable = any(_is_public_url(idx) for idx in all_index_urls)

    for spec in deps:
        name = _dep_name(spec)
        if not looks_internal(name):
            continue

        # Is this name pinned to a private source explicitly? A pin may name a
        # url directly, or reference an index by name (resolve it to a url).
        src = sources.get(name) or sources.get(name.replace("-", "_"))
        pinned_private = False
        if isinstance(src, dict):
            pin_url = src.get("url", "")
            if not pin_url and src.get("index"):
                pin_url = index_url_by_name.get(src.get("index"), src.get("index"))
            if pin_url and not _is_public_url(pin_url):
                pinned_private = True

        if pinned_private:
            continue

        if public_reachable:
            findings.append({
                "package": name,
                "severity": "critical",
                "issue": "internal-named dependency can resolve from a public index",
                "detail": (f"'{name}' matches an internal naming convention but the "
                           "project's index config reaches public PyPI and does not "
                           "pin this name to a private source. An attacker can "
                           "publish a higher version publicly (dependency confusion)."),
                "fix": (f"Add [tool.uv.sources] {name} = {{ index = 'local-private' }} "
                        "or restrict the resolver so internal-* names only resolve "
                        "from the private index (see defense/scoped_registry.py)."),
            })
        else:
            findings.append({
                "package": name,
                "severity": "warning",
                "issue": "internal-named dependency not explicitly pinned to a source",
                "detail": (f"'{name}' is internal-looking but relies on index ordering "
                           "rather than an explicit private-source pin."),
                "fix": "Pin the name to the private index via [tool.uv.sources].",
            })

    return findings


def scan_and_report(path: Path) -> int:
    findings = scan_pyproject(path)
    rel = path
    try:
        rel = path.relative_to(REPO_ROOT)
    except ValueError:
        pass
    if not findings:
        print(f"✅ policy_scan: {rel} -- no confusable internal dependencies.")
        return 0
    print(f"🚨 policy_scan: {rel} -- {len(findings)} finding(s):")
    for f in findings:
        icon = "🚨" if f["severity"] == "critical" else "⚠️"
        print(f"  {icon} [{f['severity'].upper()}] {f['package']}: {f['issue']}")
        print(f"       {f['detail']}")
        print(f"       FIX: {f['fix']}")
    return 1


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Scan pyproject.toml for confusable deps.")
    p.add_argument("paths", nargs="*", help="pyproject.toml files")
    p.add_argument("--all", action="store_true", help="scan every pyproject in the repo")
    args = p.parse_args(argv)

    if args.all:
        targets = sorted(REPO_ROOT.glob("**/pyproject.toml"))
        targets = [t for t in targets if ".venv" not in t.parts and "site-packages" not in t.parts]
    else:
        targets = [Path(p) for p in args.paths]

    if not targets:
        p.error("provide one or more pyproject.toml paths, or --all")

    rc = 0
    for t in targets:
        rc |= scan_and_report(t)
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
