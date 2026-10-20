"""Tests for parse_seed(require_goal=False) — goalless seed reads (#6604).

A bernstein.yaml without a ``goal`` key is valid when the goal is supplied by
``--from-plan``.  ``parse_seed(path, require_goal=False)`` must return a full
SeedConfig with ``goal=""`` rather than raising SeedError, so that operator
settings like ``evolution_enabled: false`` are honoured on plan runs.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from bernstein.core.seed import SeedError, parse_seed


def _write(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "bernstein.yaml"
    p.write_text(content, encoding="utf-8")
    return p


class TestRequireGoalFalse:
    def test_missing_goal_returns_empty_goal_string(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "evolution_enabled: false\n")
        seed = parse_seed(path, require_goal=False)
        assert seed.goal == ""

    def test_missing_goal_still_raises_by_default(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "evolution_enabled: false\n")
        with pytest.raises(SeedError, match="non-empty 'goal'"):
            parse_seed(path)

    def test_evolution_enabled_false_is_preserved(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "evolution_enabled: false\n")
        seed = parse_seed(path, require_goal=False)
        assert seed.evolution_enabled is False

    def test_gate_repair_enabled_false_is_preserved(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "gate_repair_enabled: false\n")
        seed = parse_seed(path, require_goal=False)
        assert seed.gate_repair_enabled is False

    def test_goal_present_works_with_require_goal_false(self, tmp_path: Path) -> None:
        path = _write(tmp_path, 'goal: "Refactor auth"\nevolution_enabled: false\n')
        seed = parse_seed(path, require_goal=False)
        assert seed.goal == "Refactor auth"
        assert seed.evolution_enabled is False

    def test_empty_goal_string_raises_by_default(self, tmp_path: Path) -> None:
        path = _write(tmp_path, 'goal: ""\n')
        with pytest.raises(SeedError, match="non-empty 'goal'"):
            parse_seed(path)

    def test_empty_goal_string_accepted_with_require_goal_false(self, tmp_path: Path) -> None:
        path = _write(tmp_path, 'goal: ""\nevolution_enabled: false\n')
        seed = parse_seed(path, require_goal=False)
        assert seed.goal == ""
        assert seed.evolution_enabled is False
