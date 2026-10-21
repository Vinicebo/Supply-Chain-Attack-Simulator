"""The attack-vs-defense matrix must be well-formed and tell a coherent story.

Behavioural proof for each `B` (blocks) claim lives in test_attack_vs_defense.py;
these tests keep the declared matrix honest and complete.
"""
from __future__ import annotations

import docs.report as report

STAGE_IDS = [s[0] for s in report.STAGES]


def test_every_defense_rates_every_stage_with_a_valid_symbol():
    for name, mapping, note in report.DEFENSES:
        assert list(mapping) == STAGE_IDS, name
        assert set(mapping.values()) <= {"B", "D", "-"}, name
        assert note.strip(), name


def test_every_stage_is_covered_by_some_defense():
    for stage in STAGE_IDS:
        assert any(m[stage] in "BD" for _, m, _ in report.DEFENSES), stage


def test_attack_is_blocked_before_code_execution():
    """Prevention must exist at S2/S3 (before S4 runs attacker code)."""
    def blockers(stage):
        return {n for n, m, _ in report.DEFENSES if m[stage] == "B"}
    assert "Namespace reservation" in blockers("S2")
    assert {"Scoped registry routing", "Lockfile + hash pinning"} <= blockers("S3")


def test_monitors_only_detect_never_block():
    monitors = {"Network monitor", "Filesystem monitor"}
    for name, mapping, _ in report.DEFENSES:
        if name in monitors:
            assert "B" not in mapping.values(), name


def test_report_renders_matrix_and_sections():
    md = report.build_report()
    for name, _, _ in report.DEFENSES:
        assert name in md
    for heading in ("Kill chain", "Attack vs. defense matrix", "Real-world incidents"):
        assert heading in md
